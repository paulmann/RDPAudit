// File:    tests/RdpAudit.ScenarioTests/SiemExportScenarioTests.cs
// Module:  RdpAudit.ScenarioTests
// Purpose: Tier 3 scenario coverage for Backlog #4 SIEM export. Seeds an in-memory SQLite
//          audit database with raw events and correlated alerts for two IPs (one target, one
//          noise), drives the real IPC dispatcher directly for GetStatus (device version),
//          GetEventsForIp (39) and GetAlertsForIp (70), then composes the export through the
//          Configurator's pure SiemExportRunner.BuildText and asserts the golden CEF / LEEF 2.0 /
//          NDJSON shapes a Splunk / QRadar consumer expects: correct headers, the UTC event time
//          rendered without a local time-zone shift, strict ordering (events first, then alerts),
//          and strict per-IP filtering.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Siem;
using RdpAudit.Core.Util;
using RdpAudit.Service;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.ScenarioTests;

/// <summary>End-to-end user scenario for "Export SIEM Events + Alerts": service-side data for
/// one selected IP becomes a valid CEF / LEEF / NDJSON export, without named pipes or dialogs.</summary>
public sealed class SiemExportScenarioTests
{
	/// <summary>The attack source the operator selects for export.</summary>
	private const string TargetIp = "203.0.113.17";

	/// <summary>Another IP that must never leak into the export (strict per-IP filtering).</summary>
	private const string NoiseIp = "198.51.100.9";

	/// <summary>Fixed UTC instant with a distinctive time of day so a time-zone shift (UTC vs
	/// local interpretation) becomes immediately visible in the rendered timestamp.</summary>
	private static readonly DateTime LatestFailedAt = new(2026, 9, 10, 12, 34, 56, DateTimeKind.Utc);

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		private readonly RdpAuditOptions _value;

		public StaticOptionsMonitor(RdpAuditOptions value) => _value = value;

		public RdpAuditOptions CurrentValue => _value;

		public RdpAuditOptions Get(string? name) => _value;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private static async Task<(IDbContextFactory<AuditDbContext> Factory, SqliteConnection Connection)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;

		await using (AuditDbContext init = new(options))
		{
			await init.Database.EnsureCreatedAsync();
		}

		return (new TestDbContextFactory(options), conn);
	}

	private static IpcDispatcher CreateDispatcher(IDbContextFactory<AuditDbContext> factory)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitor monitor = new(new RdpAuditOptions());
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager firewall = new(NullLogger<FirewallManager>.Instance);
		return new IpcDispatcher(factory, metrics, monitor, settings, firewall,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance);
	}

	private static async Task SeedAsync(IDbContextFactory<AuditDbContext> factory)
	{
		await using AuditDbContext db = factory.CreateDbContext();

		// For the selected IP: two 4625 failed logons (older first) and one later 4624 success
		// so the export carries both severities and proves newest-first event ordering.
		db.RawEvents.Add(new RawEvent
		{
			EventId = 4625,
			Channel = "Security",
			TimeUtc = LatestFailedAt.AddMinutes(-10),
			SourceIp = TargetIp,
			UserName = "attacker",
			Domain = "tgt.example",
			LogonType = 3,
			AuthPackage = "NTLM",
			ProcessName = "winlogon.exe",
			Status = "0xC000006A",
		});
		db.RawEvents.Add(new RawEvent
		{
			EventId = 4625,
			Channel = "Security",
			TimeUtc = LatestFailedAt,
			SourceIp = TargetIp,
			UserName = "attacker",
			Domain = "tgt.example",
			LogonType = 3,
			AuthPackage = "NTLM",
			ProcessName = "winlogon.exe",
			Status = "0xC000006A",
		});
		db.RawEvents.Add(new RawEvent
		{
			EventId = 4624,
			Channel = "Security",
			TimeUtc = LatestFailedAt.AddMinutes(5),
			SourceIp = TargetIp,
			UserName = "attacker",
			Domain = "tgt.example",
			LogonType = 10,
			AuthPackage = "Negotiate",
			ProcessName = "winlogon.exe",
			Status = "0x0",
		});

		// Noise IP with the same event ids: must never appear in the target export.
		db.RawEvents.Add(new RawEvent
		{
			EventId = 4625,
			Channel = "Security",
			TimeUtc = LatestFailedAt,
			SourceIp = NoiseIp,
			UserName = "noise",
			Domain = "noise.example",
			LogonType = 3,
			AuthPackage = "NTLM",
			ProcessName = "winlogon.exe",
			Status = "0xC000006A",
		});

		// Correlated alerts for the selected IP: a High brute-force alert and an Info note.
		db.Alerts.Add(new Alert
		{
			RuleId = "BruteForce",
			Severity = AlertSeverity.High,
			TimeUtc = LatestFailedAt.AddMinutes(1),
			SourceIp = TargetIp,
			UserName = "attacker",
			Message = "Repeated failed RDP logons detected",
			Acknowledged = false,
			TriggerEventId = 2,
		});
		db.Alerts.Add(new Alert
		{
			RuleId = "BruteForceNote",
			Severity = AlertSeverity.Info,
			TimeUtc = LatestFailedAt.AddMinutes(2),
			SourceIp = TargetIp,
			UserName = "attacker",
			Message = "Attack pattern note",
			Acknowledged = true,
			TriggerEventId = 3,
		});

		// Noise alert from the other IP: must never leak into the export.
		db.Alerts.Add(new Alert
		{
			RuleId = "BruteForce",
			Severity = AlertSeverity.High,
			TimeUtc = LatestFailedAt,
			SourceIp = NoiseIp,
			UserName = "noise",
			Message = "noise alert",
			Acknowledged = false,
			TriggerEventId = 1,
		});

		await db.SaveChangesAsync();
	}

	private static async Task<T> CallAsync<T>(IpcDispatcher dispatcher, IpcCommand command, object? payload = null)
	{
		IpcRequest request = new()
		{
			Command = command,
			Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
		};

		IpcResponse response = await dispatcher.DispatchAsync(request, CancellationToken.None);
		Assert.True(response.Success, response.Error);
		Assert.NotNull(response.Payload);
		T? dto = JsonSerializer.Deserialize<T>(response.Payload!, JsonOptions.Default);
		Assert.NotNull(dto);
		return dto!;
	}

	private static async Task<(EventsForIpDto Events, AlertsForIpDto Alerts, string DeviceVersion)> FetchAsync(IpcDispatcher dispatcher)
	{
		ServiceStatus status = await CallAsync<ServiceStatus>(dispatcher, IpcCommand.GetStatus);
		EventsForIpDto events = await CallAsync<EventsForIpDto>(dispatcher, IpcCommand.GetEventsForIp,
			new EventsForIpRequest { Ip = TargetIp, Limit = 0 });
		AlertsForIpDto alerts = await CallAsync<AlertsForIpDto>(dispatcher, IpcCommand.GetAlertsForIp,
			new AlertsForIpRequest { Ip = TargetIp, Limit = 0 });
		return (events, alerts, status.Version);
	}

	/// <summary>Given one selected IP with two failed and one successful logon plus two correlated
	/// alerts, when the whole service-to-export path runs, then the CEF export starts with the
	/// golden header carrying the service-reported version, renders each record with the mapped
	/// severity and an unshifted UTC timestamp, keeps events before alerts and never leaks the
	/// noise IP.</summary>
	[Fact]
	public async Task CefExport_FullIpcPath_GoldenShapeAndStrictIpFiltering()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);
			(EventsForIpDto events, AlertsForIpDto alerts, string version) = await FetchAsync(dispatcher);

			Assert.Equal(IpcResultStatus.Success, events.Status);
			Assert.Equal(IpcResultStatus.Success, alerts.Status);
			Assert.Equal(3, events.Events.Count);
			Assert.Equal(2, alerts.Alerts.Count);
			Assert.False(string.IsNullOrWhiteSpace(version));

			string cef = SiemExportRunner.BuildText(events, alerts, SiemFormat.Cef, version);
			string[] lines = cef.Split('\n');

			Assert.Equal(5, lines.Length);
			Assert.DoesNotContain(NoiseIp, cef);
			Assert.DoesNotContain("noise", cef);

			string header = "CEF:0|RdpAudit|RdpAudit|" + version + "|";
			Assert.StartsWith(header, lines[0]);
			Assert.StartsWith("event:4624|", lines[0][header.Length..]);
			Assert.Contains("|", lines[0]);

			// Newest event first, then the two older 4625s, then both alerts.
			Assert.StartsWith(header + "event:4625|", lines[1]);
			Assert.StartsWith(header + "event:4625|", lines[2]);
			Assert.StartsWith(header + "BruteForceNote|", lines[3]);
			Assert.StartsWith(header + "BruteForce|", lines[4]);

			// Severities: 4624 is informational (1), 4625 failed-auth (5), High alert (8), Info alert (1).
			Assert.Matches(@"CEF:0\|[^|]*\|[^|]*\|[^|]*\|event:4624\|[^|]*\|1\s", lines[0]);
			Assert.Matches(@"CEF:0\|[^|]*\|[^|]*\|[^|]*\|event:4625\|[^|]*\|5\s", lines[1]);
			Assert.Matches(@"\|BruteForceNote\|[^|]*\|1\s", lines[3]);
			Assert.Matches(@"\|BruteForce\|[^|]*\|8\s", lines[4]);

			// The 4625 recorded at 12:34:56 UTC must stay 12:34:56 regardless of the host time zone.
			Assert.Contains("deviceCustomDate1Label=eventTime", cef);
			Assert.Contains("deviceCustomDate1=Sep 10 2026 12:34:56 +00:00", cef);
			Assert.Contains("src=" + TargetIp, cef);
			Assert.Contains("cs8Label=recordType", cef);
			Assert.Contains("cs8=event", cef);
			Assert.Contains("cs8=alert", cef);
			Assert.EndsWith("cs8=alert", cef);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	/// <summary>Given the same seeded scenario, when the LEEF 2.0 format is requested, then every
	/// record honours the golden TAB-separated attribute shape with an ISO-8601 UTC devTime,
	/// mapped severities and the recordType telling event/alert apart.</summary>
	[Fact]
	public async Task LeefExport_FullIpcPath_GoldenShapeAndUtcStability()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);
			(EventsForIpDto events, AlertsForIpDto alerts, string version) = await FetchAsync(dispatcher);

			string leef = SiemExportRunner.BuildText(events, alerts, SiemFormat.Leef, version);
			string[] lines = leef.Split('\n');

			Assert.Equal(5, lines.Length);
			Assert.DoesNotContain(NoiseIp, leef);
			Assert.DoesNotContain("noise", leef);

			string header = "LEEF:2.0|RdpAudit|RdpAudit|" + version + "|";
			Assert.StartsWith(header + "event:4624\tdevTime=", lines[0]);
			Assert.StartsWith(header + "event:4625\tdevTime=", lines[1]);
			Assert.StartsWith(header + "event:4625\tdevTime=", lines[2]);
			Assert.StartsWith(header + "BruteForceNote\tdevTime=", lines[3]);
			Assert.StartsWith(header + "BruteForce\tdevTime=", lines[4]);

			Assert.Contains("devTime=2026-09-10T12:34:56.000Z", leef);
			Assert.Contains("\tsev=1\t", leef);
			Assert.Contains("\tsev=5\t", leef);
			Assert.Contains("\tsev=8\t", leef);
			Assert.Contains("\tsrc=" + TargetIp + "\t", leef);
			Assert.Contains("\trecordType=event\n", leef);
			Assert.Contains("\trecordType=alert", leef);
			Assert.EndsWith("recordType=alert", leef);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	/// <summary>Given the same seeded scenario, when NDJSON is requested, then every line is a
	/// standalone camelCase JSON object with an explicit UTC timestamp, enum strings "event" /
	/// "alert", mapped severities, and the last record ends the stream without a trailing newline.</summary>
	[Fact]
	public async Task NdjsonExport_FullIpcPath_ValidObjectsAndOrdering()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);
			(EventsForIpDto events, AlertsForIpDto alerts, string version) = await FetchAsync(dispatcher);

			string ndjson = SiemExportRunner.BuildText(events, alerts, SiemFormat.JsonNdjson, version);
			string[] lines = ndjson.Split('\n');

			Assert.Equal(5, lines.Length);
			Assert.DoesNotContain(NoiseIp, ndjson);
			Assert.DoesNotContain("noise", ndjson);

			string[] expectedTypes = { "event", "event", "event", "alert", "alert" };
			int[] expectedSeverity = { 1, 5, 5, 1, 8 };
			string[] expectedSignature = { "event:4624", "event:4625", "event:4625", "BruteForceNote", "BruteForce" };

			for (int i = 0; i < lines.Length; i++)
			{
				using JsonDocument doc = JsonDocument.Parse(lines[i]);
				JsonElement root = doc.RootElement;

				Assert.Equal(expectedTypes[i], root.GetProperty("type").GetString());
				Assert.Equal(expectedSeverity[i], root.GetProperty("severity").GetInt32());
				Assert.Equal(expectedSignature[i], root.GetProperty("signatureId").GetString());
				Assert.Equal(TargetIp, root.GetProperty("sourceIp").GetString());
				Assert.Equal(version, root.GetProperty("deviceVersion").GetString());
				Assert.Equal("RdpAudit", root.GetProperty("deviceVendor").GetString());
				Assert.Equal("RdpAudit", root.GetProperty("deviceProduct").GetString());
			}

			using (JsonDocument first = JsonDocument.Parse(lines[0]))
			{
				Assert.Equal("2026-09-10T12:39:56Z", first.RootElement.GetProperty("timeUtc").GetString());
			}

			using (JsonDocument second = JsonDocument.Parse(lines[1]))
			{
				Assert.Equal("2026-09-10T12:34:56Z", second.RootElement.GetProperty("timeUtc").GetString());
			}

			Assert.False(ndjson.EndsWith("\n", StringComparison.Ordinal), "NDJSON stream must not end with a trailing newline.");
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
