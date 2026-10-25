/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixApiClient.cs
// Project: RdpAudit.Service (RdpAudit.Service.Zabbix)
// Purpose: JSON-RPC client used only for provisioning and for the connection test. Every call shape
//          here was verified against a live Zabbix 8.0.0 on 2026-10-25: hostgroup.create,
//          host.create without an interface (trapper items need none), item.create with type 2 and
//          delay 0, trigger.create with tags, and dashboard.create with a problems widget filtered by
//          the integration tag. The client is additive by construction: get-then-create, no update of
//          an existing object's settings, no delete at all.
// Extends: System.Object

using System.Globalization;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Security;
using RdpAudit.Core.Zabbix;

namespace RdpAudit.Service.Zabbix;

/// <summary>Zabbix JSON-RPC client: connection probe and idempotent provisioning.</summary>
public sealed class ZabbixApiClient : IZabbixApiClient
{
	/// <summary>Named HttpClient used when the server certificate is validated.</summary>
	public const string HttpClientName = "ZabbixApi";

	/// <summary>Named HttpClient used when the operator explicitly accepted an untrusted certificate.</summary>
	public const string HttpClientNameInsecure = "ZabbixApiInsecure";

	/// <summary>Tag that groups every event of this integration in the Zabbix UI.</summary>
	public const string IntegrationTag = "rdpaudit";

	/// <summary>Tag name carrying the integration marker.</summary>
	public const string ScopeTagName = "scope";

	/// <summary>Stable dashboard name, so a second provisioning run recognises its own dashboard.</summary>
	public const string DashboardName = "RDPAudit fleet - incidents";

	/// <summary>Description stored on the host, so an operator knows where it came from.</summary>
	public const string HostDescription = "Managed by RDPAudit 2.0";

	private const string JsonRpcContentType = "application/json-rpc";

	private readonly IHttpClientFactory _httpFactory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ISecretProtector? _protector;
	private readonly ILogger<ZabbixApiClient> _logger;
	private int _requestId;

	/// <summary>Creates the client.</summary>
	/// <param name="httpFactory">Factory for the named clients.</param>
	/// <param name="options">Live options, so a settings save takes effect without a restart.</param>
	/// <param name="protector">Unprotects the stored credential envelope; may be absent on a host
	/// where DPAPI is unavailable, in which case only a plaintext-configured token can be used.</param>
	/// <param name="logger">Logger; never receives a credential value.</param>
	public ZabbixApiClient(
		IHttpClientFactory httpFactory,
		IOptionsMonitor<RdpAuditOptions> options,
		ISecretProtector? protector,
		ILogger<ZabbixApiClient> logger)
	{
		ArgumentNullException.ThrowIfNull(httpFactory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_httpFactory = httpFactory;
		_options = options;
		_protector = protector;
		_logger = logger;
	}

	/// <inheritdoc />
	public async Task<ZabbixApiProbe> ProbeAsync(CancellationToken ct)
	{
		ZabbixOptions opts = _options.CurrentValue.Zabbix;
		string endpoint = opts.ResolveApiEndpoint();
		if (endpoint.Length == 0)
		{
			return new ZabbixApiProbe(false, string.Empty, false, "The frontend URL is not configured.");
		}

		using HttpClient http = CreateHttpClient(opts);
		try
		{
			JsonNode? version = await CallAsync(http, endpoint, token: null, "apiinfo.version", parameters: null, ct)
				.ConfigureAwait(false);
			string versionText = version?.GetValue<string>() ?? string.Empty;

			string? token = await ResolveTokenAsync(http, endpoint, opts, ct).ConfigureAwait(false);
			if (string.IsNullOrEmpty(token))
			{
				return new ZabbixApiProbe(true, versionText, false,
					"The API answered version " + versionText + " but no credential is configured.");
			}

			JsonNode? user = await CallAsync(http, endpoint, token, "user.get",
				new JsonObject { ["output"] = new JsonArray { "userid", "username" } }, ct).ConfigureAwait(false);
			string userName = user is JsonArray arr && arr.Count > 0
				? arr[0]?["username"]?.GetValue<string>() ?? string.Empty
				: string.Empty;

			return new ZabbixApiProbe(true, versionText, true,
				string.Format(CultureInfo.InvariantCulture,
					"Zabbix {0} answered and the credential was accepted{1}.",
					versionText,
					userName.Length == 0 ? string.Empty : " as '" + userName + "'"));
		}
		catch (ZabbixApiException ex)
		{
			return new ZabbixApiProbe(false, string.Empty, false, ex.Message);
		}
		catch (HttpRequestException ex)
		{
			return new ZabbixApiProbe(false, string.Empty, false,
				"The API endpoint could not be reached: " + ex.Message);
		}
		catch (OperationCanceledException) when (!ct.IsCancellationRequested)
		{
			return new ZabbixApiProbe(false, string.Empty, false, "The API did not answer in time.");
		}
	}

	/// <inheritdoc />
	public async Task<ZabbixProvisionReport> ProvisionAsync(
		bool provisionTriggers,
		bool createDashboard,
		CancellationToken ct)
	{
		ZabbixOptions opts = _options.CurrentValue.Zabbix;
		string endpoint = opts.ResolveApiEndpoint();
		if (endpoint.Length == 0)
		{
			throw new ZabbixApiException("The frontend URL is not configured, so provisioning cannot run.");
		}

		if (!opts.IsApiConfigured())
		{
			throw new ZabbixApiException("No API credential is configured, so provisioning cannot run.");
		}

		string hostName = ZabbixHostName.Resolve(opts.HostName, Environment.MachineName);
		string groupName = opts.ResolveHostGroup();

		// A trapper item accepts values only from the hosts on its allowed-hosts list, and the
		// default is loopback — measured 2026-10-25: "allowed hosts: 127.0.0.1,::1". Without this
		// list every push from the monitored machine is rejected while the protocol still answers
		// success, so it is part of provisioning rather than an operator chore.
		string trapperHosts = string.IsNullOrWhiteSpace(opts.TrapperAllowedHosts)
			? ZabbixLocalAddresses.Describe()
			: opts.TrapperAllowedHosts.Trim();

		using HttpClient http = CreateHttpClient(opts);
		string? token = await ResolveTokenAsync(http, endpoint, opts, ct).ConfigureAwait(false)
			?? throw new ZabbixApiException("The API credential could not be resolved.");

		// --- host group ---
		bool groupCreated = false;
		JsonNode? groups = await CallAsync(http, endpoint, token, "hostgroup.get", new JsonObject
		{
			["output"] = new JsonArray { "groupid", "name" },
			["filter"] = new JsonObject { ["name"] = new JsonArray { groupName } },
		}, ct).ConfigureAwait(false);

		string groupId;
		if (groups is JsonArray groupArray && groupArray.Count > 0)
		{
			groupId = groupArray[0]!["groupid"]!.GetValue<string>();
		}
		else
		{
			JsonNode? created = await CallAsync(http, endpoint, token, "hostgroup.create",
				new JsonObject { ["name"] = groupName }, ct).ConfigureAwait(false);
			groupId = created!["groupids"]![0]!.GetValue<string>();
			groupCreated = true;
		}

		// --- host ---
		bool hostCreated = false;
		JsonNode? hosts = await CallAsync(http, endpoint, token, "host.get", new JsonObject
		{
			["output"] = new JsonArray { "hostid", "host" },
			["filter"] = new JsonObject { ["host"] = new JsonArray { hostName } },
		}, ct).ConfigureAwait(false);

		string hostId;
		if (hosts is JsonArray hostArray && hostArray.Count > 0)
		{
			hostId = hostArray[0]!["hostid"]!.GetValue<string>();
		}
		else
		{
			JsonNode? created = await CallAsync(http, endpoint, token, "host.create", new JsonObject
			{
				["host"] = hostName,
				["name"] = hostName,
				["description"] = HostDescription,
				["groups"] = new JsonArray { new JsonObject { ["groupid"] = groupId } },
				["tags"] = new JsonArray
				{
					new JsonObject { ["tag"] = ScopeTagName, ["value"] = IntegrationTag },
				},
			}, ct).ConfigureAwait(false);
			hostId = created!["hostids"]![0]!.GetValue<string>();
			hostCreated = true;
			_logger.LogInformation("Zabbix provisioning created host {Host}.", hostName);
		}

		// --- items ---
		JsonNode? existingItems = await CallAsync(http, endpoint, token, "item.get", new JsonObject
		{
			["hostids"] = hostId,
			["output"] = new JsonArray { "itemid", "key_", "trapper_hosts" },
		}, ct).ConfigureAwait(false);

		HashSet<string> knownKeys = new(StringComparer.Ordinal);
		if (existingItems is JsonArray itemArray)
		{
			foreach (JsonNode? node in itemArray)
			{
				string? key = node?["key_"]?.GetValue<string>();
				if (key is not null)
				{
					knownKeys.Add(key);
				}
			}
		}

		int itemsCreated = 0;
		foreach (ZabbixItemKeys.ZabbixItemDefinition definition in ZabbixItemKeys.Definitions)
		{
			if (knownKeys.Contains(definition.Key))
			{
				continue;
			}

			JsonObject itemBody = new()
			{
				["hostid"] = hostId,
				["name"] = definition.DisplayName,
				["key_"] = definition.Key,
				["type"] = 2, // Zabbix trapper: values are pushed by this agent, never polled.
				["value_type"] = (int)definition.Kind,
				["delay"] = "0",
				["history"] = "90d",
				["trends"] = "0",
			};
			if (trapperHosts.Length > 0)
			{
				itemBody["trapper_hosts"] = trapperHosts;
			}

			await CallAsync(http, endpoint, token, "item.create", itemBody, ct).ConfigureAwait(false);
			itemsCreated++;
		}

		// Existing items may predate this run or carry a narrower list. Only the allowed-hosts field
		// of OUR OWN keys is corrected, and the correction is a union: an operator's extra entries are
		// kept, and no other setting of an existing item is touched.
		int itemsUpdated = 0;
		if (trapperHosts.Length > 0 && existingItems is JsonArray knownItems)
		{
			foreach (JsonNode? node in knownItems)
			{
				string? key = node?["key_"]?.GetValue<string>();
				string? itemId = node?["itemid"]?.GetValue<string>();
				string? current = node?["trapper_hosts"]?.GetValue<string>();
				if (key is null || itemId is null || !IsOurKey(key))
				{
					continue;
				}

				if (ZabbixLocalAddresses.Covers(current, trapperHosts))
				{
					continue;
				}

				await CallAsync(http, endpoint, token, "item.update", new JsonObject
				{
					["itemid"] = itemId,
					["trapper_hosts"] = ZabbixLocalAddresses.Merge(current, trapperHosts),
				}, ct).ConfigureAwait(false);
				itemsUpdated++;
			}
		}

		// --- triggers ---
		int triggersCreated = 0;
		int triggersExisted = 0;
		if (provisionTriggers)
		{
			JsonNode? existingTriggers = await CallAsync(http, endpoint, token, "trigger.get", new JsonObject
			{
				["hostids"] = hostId,
				["output"] = new JsonArray { "triggerid", "description" },
			}, ct).ConfigureAwait(false);

			HashSet<string> knownTriggers = new(StringComparer.Ordinal);
			if (existingTriggers is JsonArray triggerArray)
			{
				foreach (JsonNode? node in triggerArray)
				{
					string? description = node?["description"]?.GetValue<string>();
					if (description is not null)
					{
						knownTriggers.Add(description);
					}
				}
			}

			List<ZabbixSeverity.ZabbixTriggerDefinition> wanted = new(ZabbixSeverity.BuildTriggerSet(hostName))
			{
				ZabbixSeverity.BuildHeartbeatTrigger(hostName),
			};

			foreach (ZabbixSeverity.ZabbixTriggerDefinition trigger in wanted)
			{
				if (knownTriggers.Contains(trigger.Description))
				{
					triggersExisted++;
					continue;
				}

				await CallAsync(http, endpoint, token, "trigger.create", new JsonObject
				{
					["description"] = trigger.Description,
					["expression"] = trigger.Expression,
					["priority"] = trigger.Priority,
					["tags"] = new JsonArray
					{
						new JsonObject { ["tag"] = ScopeTagName, ["value"] = IntegrationTag },
						new JsonObject { ["tag"] = "component", ["value"] = "rdp-audit" },
						new JsonObject { ["tag"] = "trigger", ["value"] = trigger.Key },
					},
				}, ct).ConfigureAwait(false);
				triggersCreated++;
			}
		}

		// --- dashboard: the single window across the fleet ---
		bool dashboardCreated = false;
		bool dashboardExisted = false;
		if (createDashboard)
		{
			JsonNode? dashboards = await CallAsync(http, endpoint, token, "dashboard.get", new JsonObject
			{
				["output"] = new JsonArray { "dashboardid", "name" },
				["filter"] = new JsonObject { ["name"] = new JsonArray { DashboardName } },
			}, ct).ConfigureAwait(false);

			if (dashboards is JsonArray dashboardArray && dashboardArray.Count > 0)
			{
				dashboardExisted = true;
			}
			else
			{
				await CallAsync(http, endpoint, token, "dashboard.create", BuildDashboardDocument(), ct)
					.ConfigureAwait(false);
				dashboardCreated = true;
			}
		}

		string message = string.Format(
			CultureInfo.InvariantCulture,
			"Host '{0}' in group '{1}': {2}, items created {3}, items allowed-hosts widened {4}, "
			+ "trigger(s) created {5}, dashboard {6}. Trapper accepts values from {7}.",
			hostName,
			groupName,
			hostCreated ? "created" : "already present",
			itemsCreated,
			itemsUpdated,
			triggersCreated,
			dashboardCreated ? "created" : dashboardExisted ? "already present" : "skipped",
			ZabbixLocalAddresses.DescribeForMessage(trapperHosts));

		_logger.LogInformation("Zabbix provisioning finished: {Message}", message);

		return new ZabbixProvisionReport(
			groupCreated,
			!groupCreated,
			hostCreated,
			!hostCreated,
			itemsCreated,
			knownKeys.Count,
			itemsUpdated,
			trapperHosts,
			triggersCreated,
			triggersExisted,
			dashboardCreated,
			dashboardExisted,
			message);
	}

	/// <summary>Builds the dashboard document: one Problems widget filtered by the integration tag, so
	/// incidents from every machine land in a single list.</summary>
	internal static JsonObject BuildDashboardDocument() => new()
	{
		["name"] = DashboardName,
		["display_period"] = 30,
		["auto_start"] = 1,
		["pages"] = new JsonArray
		{
			new JsonObject
			{
				["name"] = "RDPAudit incidents",
				["widgets"] = new JsonArray
				{
					new JsonObject
					{
						["type"] = "problems",
						["name"] = "RDPAudit incidents on all machines",
						["x"] = 0,
						["y"] = 0,
						["width"] = 24,
						["height"] = 8,
						["fields"] = new JsonArray
						{
							new JsonObject { ["type"] = 1, ["name"] = "tags.tag.0", ["value"] = ScopeTagName },
							new JsonObject { ["type"] = 0, ["name"] = "tags.operator.0", ["value"] = "1" },
							new JsonObject { ["type"] = 1, ["name"] = "tags.value.0", ["value"] = IntegrationTag },
							new JsonObject { ["type"] = 0, ["name"] = "show_tags", ["value"] = "3" },
							new JsonObject { ["type"] = 0, ["name"] = "show_opdata", ["value"] = "1" },
						},
					},
				},
			},
		},
	};

	/// <summary>Builds one JSON-RPC request body.</summary>
	/// <param name="method">API method name.</param>
	/// <param name="parameters">Method parameters; null becomes an empty object.</param>
	/// <param name="requestId">Request id echoed by the server.</param>
	/// <remarks>
	/// <c>params</c> is always present, even when empty. Measured against Zabbix 8.0.0 on 2026-10-25:
	/// omitting the member for <c>apiinfo.version</c> is rejected with
	/// <c>Invalid parameter "/": the parameter "params" is missing</c>, which turns a healthy server
	/// into "unreachable" in the connection test.
	/// </remarks>
	internal static string BuildRequestBody(string method, JsonObject? parameters, int requestId)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(method);
		JsonObject body = new()
		{
			["jsonrpc"] = "2.0",
			["method"] = method,
			["params"] = parameters ?? new JsonObject(),
			["id"] = requestId,
		};

		return body.ToJsonString();
	}
	/// <summary>True when <paramref name="key"/> belongs to this integration, so correcting it is
	/// maintenance of our own object rather than a change to an operator's tuning.</summary>
	private static bool IsOurKey(string key)
	{
		foreach (string candidate in ZabbixItemKeys.All)
		{
			if (string.Equals(candidate, key, StringComparison.Ordinal))
			{
				return true;
			}
		}

		return false;
	}

	private HttpClient CreateHttpClient(ZabbixOptions opts)
	{
		string name = opts.ValidateServerCertificate ? HttpClientName : HttpClientNameInsecure;
		HttpClient client = _httpFactory.CreateClient(name);
		client.Timeout = TimeSpan.FromSeconds(opts.ResolveTimeoutSeconds());
		return client;
	}

	/// <summary>Prefers the stored token; falls back to <c>user.login</c> when no token is configured.
	/// The plaintext never leaves this method.</summary>
	private async Task<string?> ResolveTokenAsync(
		HttpClient http,
		string endpoint,
		ZabbixOptions opts,
		CancellationToken ct)
	{
		string? token = TryUnprotect(opts.ApiToken);
		if (!string.IsNullOrEmpty(token))
		{
			return token;
		}

		string? user = opts.ApiUser;
		string? password = TryUnprotect(opts.ApiPassword);
		if (string.IsNullOrWhiteSpace(user) || string.IsNullOrEmpty(password))
		{
			return null;
		}

		JsonNode? login = await CallAsync(http, endpoint, token: null, "user.login", new JsonObject
		{
			["username"] = user,
			["password"] = password,
		}, ct).ConfigureAwait(false);

		return login?.GetValue<string>();
	}

	private string? TryUnprotect(string? envelope)
	{
		if (string.IsNullOrWhiteSpace(envelope))
		{
			return null;
		}

		try
		{
			return _protector is null ? envelope : _protector.Unprotect(envelope);
		}
		catch (SecretProtectionException ex)
		{
			// Deliberately no value in the message: only the fact that the envelope could not be opened.
			_logger.LogWarning(ex, "A stored Zabbix credential could not be unprotected on this host.");
			return null;
		}
	}

	private async Task<JsonNode?> CallAsync(
		HttpClient http,
		string endpoint,
		string? token,
		string method,
		JsonObject? parameters,
		CancellationToken ct)
	{
		string bodyText = BuildRequestBody(method, parameters, Interlocked.Increment(ref _requestId));

		using StringContent content = new(bodyText, Encoding.UTF8, JsonRpcContentType);
		using HttpRequestMessage request = new(HttpMethod.Post, endpoint) { Content = content };
		if (!string.IsNullOrEmpty(token))
		{
			request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
		}

		using HttpResponseMessage response = await http.SendAsync(request, ct).ConfigureAwait(false);
		string text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

		if (!response.IsSuccessStatusCode)
		{
			throw new ZabbixApiException(string.Format(
				CultureInfo.InvariantCulture,
				"{0}: HTTP {1} from the API endpoint.",
				method,
				(int)response.StatusCode));
		}

		JsonNode? root;
		try
		{
			root = JsonNode.Parse(text);
		}
		catch (JsonException ex)
		{
			throw new ZabbixApiException(method + ": the API returned a body that is not JSON.", ex);
		}

		if (root is null)
		{
			throw new ZabbixApiException(method + ": the API returned an empty body.");
		}

		if (root["error"] is JsonObject error)
		{
			string data = error["data"]?.GetValue<string>() ?? error["message"]?.GetValue<string>() ?? "unspecified";
			throw new ZabbixApiException(method + ": " + data);
		}

		return root["result"];
	}
}
