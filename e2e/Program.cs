// Throw-away end-to-end harness: drives the SHIPPED Zabbix code paths (provisioning client, payload
// builder, sender client) against the live instance, then prints what the server said.
// Deleted after the run; never part of the solution.

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Models;
using RdpAudit.Core.Security;
using RdpAudit.Core.Zabbix;
using RdpAudit.Service.Zabbix;

string token = Environment.GetEnvironmentVariable("ZBX_TOKEN") ?? throw new InvalidOperationException("ZBX_TOKEN is not set");
string hostName = "rdpaudit-e2e-" + DateTime.UtcNow.ToString("HHmmss");

ZabbixOptions zabbix = new()
{
	Enabled = true,
	ServerHost = "22877.ru",
	ServerPort = 10051,
	HostName = hostName,
	HostGroup = "RDPAudit",
	ApiUrl = "https://22877.ru",
	ApiToken = token,
	ValidateServerCertificate = true,
	TimeoutSeconds = 20,
	MinimumSeverity = AlertSeverity.Low,
};

RdpAuditOptions root = new() { Zabbix = zabbix };
StaticMonitor monitor = new(root);
SimpleHttpFactory httpFactory = new();
PassThroughProtector protector = new();

ZabbixApiClient api = new(httpFactory, monitor, protector, NullLogger<ZabbixApiClient>.Instance);

Console.WriteLine("== probe ==");
ZabbixApiProbe probe = await api.ProbeAsync(CancellationToken.None);
Console.WriteLine($"reachable={probe.Reachable} version={probe.Version} auth={probe.Authenticated} :: {probe.Message}");

Console.WriteLine("== provision ==");
ZabbixProvisionReport report = await api.ProvisionAsync(provisionTriggers: true, createDashboard: true, CancellationToken.None);
Console.WriteLine(
	$"group={report.GroupCreated}/{report.GroupExisted} host={report.HostCreated}/{report.HostExisted} "
	+ $"items+{report.ItemsCreated} triggers+{report.TriggersCreated} dashboard={report.DashboardCreated}/{report.DashboardExisted}");
Console.WriteLine(report.Message);

Console.WriteLine("== waiting 20 s for the Zabbix configuration cache ==");
await Task.Delay(TimeSpan.FromSeconds(20));

Console.WriteLine("== push an incident through the shipped sender ==");
ZabbixIncident incident = new(
	AlertId: 123456,
	TimeUtc: DateTime.UtcNow,
	RuleId: "BRUTE_FORCE",
	Severity: AlertSeverity.High,
	SourceIp: "203.0.113.9",
	SourceIpDerived: false,
	UserName: "md",
	Message: "Synthetic end-to-end check from the RDPAudit Zabbix client");

ZabbixMachineSummary summary = new(
	Environment.MachineName,
	"2.0.3-e2e",
	TimeSpan.FromMinutes(3),
	EventsCaptured: 111,
	EventsDropped: 0,
	AlertsRaised: 1,
	ActiveBlocks: 1,
	PendingBacklog: 0,
	SkippedIncidents: 0);

ZabbixPayload payload = ZabbixIncidentPayloadBuilder.Build(hostName, new[] { incident }, summary, sequence: 1, DateTime.UtcNow);
Console.WriteLine($"maxSeverity={payload.MaxSeverity} values={payload.Values.Count} json={payload.IncidentsJson.Length} bytes");

ZabbixSenderClient sender = new();
ZabbixSenderOutcome outcome = await sender.SendAsync("22877.ru", 10051, payload.Values, TimeSpan.FromSeconds(15), CancellationToken.None);
Console.WriteLine($"delivered={outcome.Delivered} processed={outcome.Processed} failed={outcome.Failed} total={outcome.Total}");
Console.WriteLine(outcome.Message);

Console.WriteLine("== recovery push (severity 0) ==");
ZabbixPayload quiet = ZabbixIncidentPayloadBuilder.Build(hostName, Array.Empty<ZabbixIncident>(), summary, sequence: 2, DateTime.UtcNow);
ZabbixSenderOutcome quietOutcome = await sender.SendAsync("22877.ru", 10051, quiet.Values, TimeSpan.FromSeconds(15), CancellationToken.None);
Console.WriteLine($"delivered={quietOutcome.Delivered} processed={quietOutcome.Processed} failed={quietOutcome.Failed}");

Console.WriteLine("HOSTNAME=" + hostName);

internal sealed class StaticMonitor : IOptionsMonitor<RdpAuditOptions>
{
	public StaticMonitor(RdpAuditOptions value) => CurrentValue = value;

	public RdpAuditOptions CurrentValue { get; }

	public RdpAuditOptions Get(string? name) => CurrentValue;

	public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
}

internal sealed class SimpleHttpFactory : IHttpClientFactory
{
	public HttpClient CreateClient(string name) => new() { Timeout = TimeSpan.FromSeconds(30) };
}

internal sealed class PassThroughProtector : ISecretProtector
{
	public bool IsAvailable => true;

	public string Protect(string plaintext, SecretScope scope = SecretScope.LocalMachine) => plaintext;

	public string Unprotect(string envelopeOrPlaintext) => envelopeOrPlaintext;

	public bool IsProtectedEnvelope(string? value) => false;
}
