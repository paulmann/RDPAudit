// File:    tests/RdpAudit.Service.Tests/MikroTikClientTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: HttpMessageHandler-driven tests for the Stage 9 MikroTikClient. Verifies that the
//          requests are dispatched to /rest endpoints, carry HTTP Basic authentication, that
//          AddBlockAsync is idempotent when a matching rule already exists, and that
//          RemoveBlockAsync only deletes rules whose comment matches the configured prefix.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.Security;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public class MikroTikClientTests
{
	private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitor(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class StubFactory : IHttpClientFactory
	{
		private readonly HttpMessageHandler _handler;
		public StubFactory(HttpMessageHandler handler) => _handler = handler;
		public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
	}

	private sealed class ScriptedHandler : HttpMessageHandler
	{
		public List<HttpRequestMessage> Requests { get; } = new();
		public Queue<HttpResponseMessage> Responses { get; } = new();

		protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			Requests.Add(request);
			if (Responses.Count == 0)
			{
				return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
				{
					Content = new StringContent("[]", Encoding.UTF8, "application/json"),
				});
			}
			return Task.FromResult(Responses.Dequeue());
		}
	}

	private static (MikroTikClient Client, ScriptedHandler Handler, InMemorySecretProtector Protector, MikroTikOptions Opts)
		Build(MikroTikOptions? overrideOpts = null)
	{
		MikroTikOptions opts = overrideOpts ?? new MikroTikOptions
		{
			Enabled = true,
			AddAttackerRules = true,
			Host = "10.0.0.1",
			UseHttps = true,
			UserName = "rdpaudit",
			TimeoutSeconds = 5,
			FilterChain = "input",
			FilterAction = "drop",
			CommentPrefix = "RdpAudit",
			ValidateServerCertificate = true,
		};

		InMemorySecretProtector protector = new();
		if (string.IsNullOrEmpty(opts.Password))
		{
			opts.Password = protector.Protect("router-password");
		}

		RdpAuditOptions rd = new() { MikroTik = opts };
		ScriptedHandler handler = new();
		MikroTikClient client = new(
			new StubFactory(handler),
			new StaticOptionsMonitor<RdpAuditOptions>(rd),
			protector,
			NullLogger<MikroTikClient>.Instance);
		return (client, handler, protector, opts);
	}

	private static HttpResponseMessage Json(HttpStatusCode code, string body) => new(code)
	{
		Content = new StringContent(body, Encoding.UTF8, "application/json"),
	};

	[Fact]
	public async Task PingAsync_ReturnsNotConfigured_WhenHostMissing()
	{
		MikroTikOptions opts = new() { Enabled = true, AddAttackerRules = true, UserName = "x" };
		(MikroTikClient client, _, _, _) = Build(opts);

		MikroTikOperationResult result = await client.PingAsync(CancellationToken.None);

		Assert.Equal(MikroTikOutcome.NotConfigured, result.Outcome);
	}

	[Fact]
	public async Task PingAsync_HitsSystemResource_OnSuccess()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();
		handler.Responses.Enqueue(Json(HttpStatusCode.OK, "{\"uptime\":\"1d2h\"}"));

		MikroTikOperationResult result = await client.PingAsync(CancellationToken.None);

		Assert.Equal(MikroTikOutcome.Accepted, result.Outcome);
		Assert.Single(handler.Requests);
		HttpRequestMessage req = handler.Requests[0];
		Assert.Equal(HttpMethod.Get, req.Method);
		Assert.Contains("/rest/system/resource", req.RequestUri!.AbsolutePath, StringComparison.Ordinal);
		Assert.NotNull(req.Headers.Authorization);
		Assert.Equal("Basic", req.Headers.Authorization!.Scheme);
	}

	[Fact]
	public async Task PingAsync_Maps401_ToRejected()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();
		handler.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.Unauthorized));

		MikroTikOperationResult result = await client.PingAsync(CancellationToken.None);

		Assert.Equal(MikroTikOutcome.Rejected, result.Outcome);
		Assert.Equal(401, result.ResponseCode);
	}

	[Fact]
	public async Task PingAsync_Maps503_ToServerError()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();
		handler.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

		MikroTikOperationResult result = await client.PingAsync(CancellationToken.None);

		Assert.Equal(MikroTikOutcome.ServerError, result.Outcome);
		Assert.Equal(503, result.ResponseCode);
	}

	[Fact]
	public async Task AddBlockAsync_ReusesExistingRule_WhenAlreadyPresent()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();

		// First call: list owned rules — returns one matching row.
		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"[{\".id\":\"*1\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.10\",\"comment\":\"RdpAudit autoblock\"}]"));

		MikroTikOperationResult result = await client.AddBlockAsync(new MikroTikBlockRequest
		{
			Ip = "203.0.113.10",
			Chain = "input",
			Action = "drop",
			Comment = "RdpAudit auto-block",
		}, CancellationToken.None);

		Assert.Equal(MikroTikOutcome.AlreadyExists, result.Outcome);
		Assert.Equal("*1", result.RuleId);
		Assert.Single(handler.Requests);
	}

	[Fact]
	public async Task AddBlockAsync_PutsNewRule_AndReturnsRuleId()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();

		// 1) list owned rules — empty.
		handler.Responses.Enqueue(Json(HttpStatusCode.OK, "[]"));
		// 2) PUT new rule — RouterOS returns the row.
		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"{\".id\":\"*7\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.10\",\"comment\":\"RdpAudit\"}"));

		MikroTikOperationResult result = await client.AddBlockAsync(new MikroTikBlockRequest
		{
			Ip = "203.0.113.10",
			Chain = "input",
			Action = "drop",
			Comment = "RdpAudit auto-block",
		}, CancellationToken.None);

		Assert.Equal(MikroTikOutcome.Accepted, result.Outcome);
		Assert.Equal("*7", result.RuleId);
		Assert.Equal(2, handler.Requests.Count);
		Assert.Equal(HttpMethod.Put, handler.Requests[1].Method);
	}

	[Fact]
	public async Task RemoveBlockAsync_RefusesWhenCommentPrefixDoesNotMatch()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();

		// Verify GET — returns row owned by someone else.
		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"{\".id\":\"*42\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.10\",\"comment\":\"manual block\"}"));

		MikroTikOperationResult result = await client.RemoveBlockAsync("*42", "203.0.113.10", CancellationToken.None);

		Assert.Equal(MikroTikOutcome.Rejected, result.Outcome);
		// Only the verify GET was sent — DELETE must not happen.
		Assert.Single(handler.Requests);
		Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
	}

	[Fact]
	public async Task RemoveBlockAsync_DeletesWhenRuleOwned()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();

		// Verify GET — returns RdpAudit-owned row.
		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"{\".id\":\"*7\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.10\",\"comment\":\"RdpAudit auto-block\"}"));
		// DELETE response.
		handler.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.NoContent));

		MikroTikOperationResult result = await client.RemoveBlockAsync("*7", "203.0.113.10", CancellationToken.None);

		Assert.Equal(MikroTikOutcome.Accepted, result.Outcome);
		Assert.Equal("*7", result.RuleId);
		Assert.Equal(2, handler.Requests.Count);
		Assert.Equal(HttpMethod.Delete, handler.Requests[1].Method);
	}

	[Fact]
	public async Task RemoveBlockAsync_ResolvesById_WhenIpProvided()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();

		// 1) ListOwnedRulesAsync GET — find IP -> id mapping.
		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"[{\".id\":\"*9\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.42\",\"comment\":\"RdpAudit auto-block\"}]"));
		// 2) verify GET.
		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"{\".id\":\"*9\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.42\",\"comment\":\"RdpAudit auto-block\"}"));
		// 3) DELETE.
		handler.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.NoContent));

		MikroTikOperationResult result = await client.RemoveBlockAsync(null, "203.0.113.42", CancellationToken.None);

		Assert.Equal(MikroTikOutcome.Accepted, result.Outcome);
		Assert.Equal("*9", result.RuleId);
		Assert.Equal(3, handler.Requests.Count);
	}

	[Fact]
	public async Task ListOwnedRulesAsync_OnlyReturnsRowsWithMatchingPrefix()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();
		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"[{\".id\":\"*1\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.1\",\"comment\":\"RdpAudit\"}," +
			"{\".id\":\"*2\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.2\",\"comment\":\"manual block\"}]"));

		(MikroTikOperationResult result, IReadOnlyList<MikroTikRule> rules) =
			await client.ListOwnedRulesAsync(CancellationToken.None);

		Assert.Equal(MikroTikOutcome.Accepted, result.Outcome);
		Assert.Single(rules);
		Assert.Equal("*1", rules[0].Id);
	}

	[Fact]
	public void IsOwnedRule_DetectsPrefix()
	{
		string body = "{\".id\":\"*1\",\"comment\":\"RdpAudit auto-block\"}";
		Assert.True(MikroTikClient.IsOwnedRule(body, "RdpAudit"));
		Assert.False(MikroTikClient.IsOwnedRule(body, "Other"));
	}

	[Fact]
	public void TryExtractRuleId_ParsesIdField()
	{
		string body = "{\".id\":\"*5\",\"comment\":\"x\"}";
		Assert.Equal("*5", MikroTikClient.TryExtractRuleId(body));
		Assert.Null(MikroTikClient.TryExtractRuleId(null));
		Assert.Null(MikroTikClient.TryExtractRuleId("not-json"));
	}
}
