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

		/// <summary>Request bodies captured inside <see cref="SendAsync"/>; aligned by index with
		/// <see cref="Requests"/>.</summary>
		public List<string?> RequestBodies { get; } = new();

		public Queue<HttpResponseMessage> Responses { get; } = new();

		/// <remarks>
		/// The body is read HERE, while the request is alive. <c>MikroTikClient</c> owns the
		/// <see cref="HttpRequestMessage"/> and disposes it when the operation returns, and disposing a
		/// request disposes its <see cref="StringContent"/> too - so reading <c>Content</c> from the test
		/// after the call returns yields <see cref="ObjectDisposedException"/>. Measured, not assumed.
		/// </remarks>
		protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
		{
			Requests.Add(request);
			RequestBodies.Add(request.Content is null
				? null
				: await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));

			if (Responses.Count == 0)
			{
				return new HttpResponseMessage(HttpStatusCode.OK)
				{
					Content = new StringContent("[]", Encoding.UTF8, "application/json"),
				};
			}
			return Responses.Dequeue();
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
		// The reuse path now also pulls the existing rule to the front of the chain, because a rule
		// created by an older build may sit behind a terminal drop and never fire.
		Assert.Equal(2, handler.Requests.Count);
		Assert.Equal(HttpMethod.Post, handler.Requests[1].Method);
		Assert.Contains("/rest/ip/firewall/filter/move", handler.Requests[1].RequestUri!.AbsolutePath, StringComparison.Ordinal);
		string moveBody = handler.RequestBodies[1] ?? string.Empty;
		Assert.Contains("\".id\":\"*1\"", moveBody, StringComparison.Ordinal);
	}

	[Fact]
	public async Task AddBlockAsync_StillReuses_WhenMoveIsRefused()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();

		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"[{\".id\":\"*1\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.10\",\"comment\":\"RdpAudit autoblock\"}]"));
		// RouterOS answers 400 "cannot move builtin" when the rule already sits ahead of the builtin
		// row — the rule is already in the best position, so this must stay a success.
		handler.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.BadRequest));

		MikroTikOperationResult result = await client.AddBlockAsync(new MikroTikBlockRequest
		{
			Ip = "203.0.113.10",
			Chain = "input",
			Action = "drop",
			Comment = "RdpAudit auto-block",
		}, CancellationToken.None);

		// A refused repositioning must not turn a successful reuse into a failure.
		Assert.Equal(MikroTikOutcome.AlreadyExists, result.Outcome);
		Assert.Equal("*1", result.RuleId);
		Assert.Equal(2, handler.Requests.Count);
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

		// Placement is part of the contract: a rule appended to the end of the table is never
		// evaluated for WAN traffic on a default configuration, so every created rule must ask
		// RouterOS to insert it above the first row.
		string body = handler.RequestBodies[1] ?? string.Empty;
		Assert.Contains("\"place-before\":\"0\"", body, StringComparison.Ordinal);
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
	public async Task RemoveBlockAsync_UsesRuleIdVerbatimInRequestPath()
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();

		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"{\".id\":\"*7\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.10\",\"comment\":\"RdpAudit auto-block\"}"));
		handler.Responses.Enqueue(new HttpResponseMessage(HttpStatusCode.NoContent));

		MikroTikOperationResult result = await client.RemoveBlockAsync("*7", "203.0.113.10", CancellationToken.None);

		Assert.Equal(MikroTikOutcome.Accepted, result.Outcome);
		foreach (HttpRequestMessage request in handler.Requests)
		{
			// RouterOS does not percent-decode the id segment: "%2A7" answers HTTP 400
			// "no such command prefix" and the block is never removed.
			Assert.DoesNotContain("%2A", request.RequestUri!.OriginalString, StringComparison.OrdinalIgnoreCase);
			Assert.Contains("*7", request.RequestUri.OriginalString, StringComparison.Ordinal);
		}
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

	[Theory]
	[InlineData("*7/../../system/script")]
	[InlineData("*7?x=1")]
	[InlineData("*")]
	[InlineData("*ZZ")]
	[InlineData("7")]
	public async Task RemoveBlockAsync_RefusesRuleIdThatIsNotAHandle(string ruleId)
	{
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build();

		MikroTikOperationResult result = await client.RemoveBlockAsync(ruleId, "203.0.113.10", CancellationToken.None);

		Assert.Equal(MikroTikOutcome.Rejected, result.Outcome);
		// Nothing may be sent: Uri normalises '..' segments, so a crafted id would address another
		// REST menu ("DELETE /rest/system/script") instead of the firewall filter row.
		Assert.Empty(handler.Requests);
	}

	[Theory]
	[InlineData("*7", true)]
	[InlineData("*A1", true)]
	[InlineData("*deadbeef", true)]
	[InlineData("*", false)]
	[InlineData("*7 ", false)]
	[InlineData("*7/1", false)]
	[InlineData("", false)]
	public void IsRouterOsRuleHandle_AcceptsOnlyHandles(string ruleId, bool expected)
	{
		Assert.Equal(expected, MikroTikClient.IsRouterOsRuleHandle(ruleId));
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

	[Fact]
	public async Task AddBlockAsync_EmptyConfiguredChain_StillReusesExistingInputRule()
	{
		// A blank FilterChain resolves to "input" when the rule is created; the idempotency match
		// must compare against that resolved chain, or every re-block creates a duplicate rule.
		MikroTikOptions opts = new()
		{
			Enabled = true,
			AddAttackerRules = true,
			Host = "10.0.0.1",
			UseHttps = true,
			UserName = "rdpaudit",
			TimeoutSeconds = 5,
			FilterChain = string.Empty,
			FilterAction = "drop",
			CommentPrefix = "RdpAudit",
			ValidateServerCertificate = true,
		};
		(MikroTikClient client, ScriptedHandler handler, _, _) = Build(opts);

		handler.Responses.Enqueue(Json(HttpStatusCode.OK,
			"[{\".id\":\"*1\",\"chain\":\"input\",\"action\":\"drop\",\"src-address\":\"203.0.113.10\",\"comment\":\"RdpAudit autoblock\"}]"));

		MikroTikOperationResult result = await client.AddBlockAsync(new MikroTikBlockRequest
		{
			Ip = "203.0.113.10",
			Chain = string.Empty,
			Action = "drop",
			Comment = "RdpAudit auto-block",
		}, CancellationToken.None);

		Assert.Equal(MikroTikOutcome.AlreadyExists, result.Outcome);
		Assert.Equal("*1", result.RuleId);
		Assert.DoesNotContain(handler.Requests, r => r.Method == HttpMethod.Put);
		Assert.Contains(handler.Requests, r =>
			r.RequestUri!.AbsolutePath.Contains("/filter/move", StringComparison.Ordinal));
	}
}
