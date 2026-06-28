// File:    src/RdpAudit.Service/Services/SecurityAuthProbeService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Runs a one-shot bounded Security-channel auth read inside the service process so
//          operators can disambiguate "Security Armed but zero events" symptoms. The probe
//          mirrors what PowerShell does during incident triage — a narrow XPath against the
//          canonical auth event IDs, ReverseDirection=true, MaxEvents=20, with a 24h lower
//          time bound — so a successful PowerShell read on the same host must imply a
//          successful probe here. Three failure modes are reported distinctly: AccessDenied
//          (the service account is missing the "Manage auditing and security log" right or is
//          not a member of "Event Log Readers"); Timeout (the channel is so large that the
//          per-record read budget exhausted); and NoEvents (channel reachable, no recent auth).
//          The probe is also used internally at startup as the "first-time bounded latest
//          backfill" data source so a stale bookmark cannot keep the service in a permanent
//          zero-events state on a host that has just been upgraded.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Service.Services;

/// <summary>One-shot bounded Security-channel auth read used by the diagnostic IPC and the
/// startup "latest backfill" recovery path.</summary>
public sealed class SecurityAuthProbeService
{
	/// <summary>The probe queries the canonical auth event IDs only — broad Security catalog
	/// scans are exactly what makes the live watcher path stall on busy hosts, so this read
	/// must be just as narrow as the watcher's filter.</summary>
	internal static readonly IReadOnlyList<int> ProbeEventIds = new[] { 4624, 4625 };

	/// <summary>Default lookback used by the probe — 24h is wide enough to catch overnight
	/// brute-force chatter but bounded enough that a real-host read finishes in seconds.</summary>
	public const int DefaultLookbackHours = 24;

	/// <summary>Max events the probe returns; matches the PowerShell <c>-MaxEvents 20</c> the
	/// task description references.</summary>
	public const int DefaultMaxEvents = 20;

	/// <summary>Per-EventRecord read timeout. Keeps the probe responsive on hosts whose Security
	/// channel back-pressures the reader between records.</summary>
	internal static readonly TimeSpan PerRecordReadTimeout = TimeSpan.FromMilliseconds(750);

	private readonly ILogger<SecurityAuthProbeService> _logger;

	public SecurityAuthProbeService(ILogger<SecurityAuthProbeService> logger)
	{
		_logger = logger;
	}

	/// <summary>Execute the probe and produce an outcome envelope. Never throws — the failure
	/// path is reported via <see cref="SecurityAuthProbeDto.Outcome"/>.</summary>
	public SecurityAuthProbeDto Run(int lookbackHours = DefaultLookbackHours, int maxEvents = DefaultMaxEvents)
	{
		DateTime startedUtc = DateTime.UtcNow;
		int boundedLookback = Math.Clamp(lookbackHours, 1, 24 * 7);
		int boundedMax = Math.Clamp(maxEvents, 1, 200);
		DateTime sinceUtc = startedUtc - TimeSpan.FromHours(boundedLookback);
		string xpath = SecurityAuthQuery.BuildXPath(ProbeEventIds, sinceUtc);
		string identity = ResolveIdentity();

		SecurityAuthProbeDto dto = new()
		{
			GeneratedUtc = startedUtc,
			Identity = identity,
			Query = xpath,
			LookbackHours = boundedLookback,
		};

		if (!OperatingSystem.IsWindows())
		{
			dto.Status = IpcResultStatus.Unavailable;
			dto.Outcome = "NotWindows";
			dto.Message = "Security auth probe requires Windows; cannot run on this host.";
			return dto;
		}

		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			RunWindows(dto, xpath, boundedMax);
		}
		catch (Exception ex)
		{
			dto.Status = IpcResultStatus.Unavailable;
			dto.Outcome = "Error";
			dto.ExceptionType = ex.GetType().Name;
			dto.ExceptionHResult = "0x" + ex.HResult.ToString("X8", System.Globalization.CultureInfo.InvariantCulture);
			dto.ExceptionMessage = ex.Message;
			dto.Message = "Probe failed: " + ex.GetType().Name + " - " + ex.Message;
			_logger.LogWarning(ex, "Security auth probe failed unexpectedly");
		}
		finally
		{
			sw.Stop();
			dto.ElapsedMilliseconds = sw.ElapsedMilliseconds;
		}

		return dto;
	}

	[SupportedOSPlatform("windows")]
	private void RunWindows(SecurityAuthProbeDto dto, string xpath, int maxEvents)
	{
		EventLogQuery query = new(EventCatalog.ChannelSecurity, PathType.LogName, xpath)
		{
			ReverseDirection = true,
		};

		using EventLogReader reader = new(query);
		int returned = 0;
		EventRecord? first = null;
		bool sawAny = false;
		Stopwatch perRecord = Stopwatch.StartNew();
		try
		{
			while (returned < maxEvents)
			{
				perRecord.Restart();
				EventRecord? record = reader.ReadEvent(PerRecordReadTimeout);
				if (record is null)
				{
					// Null means the timeout elapsed or the result set was exhausted. Distinguish
					// "timeout while reading the first record" (we never observed any record at
					// all) from "natural end of results" by inspecting whether we saw any event.
					if (!sawAny && perRecord.Elapsed >= PerRecordReadTimeout)
					{
						dto.Status = IpcResultStatus.Unavailable;
						dto.Outcome = "Timeout";
						dto.Message = string.Format(
							System.Globalization.CultureInfo.InvariantCulture,
							"Reader returned no record within {0}ms — Security log is too large or under read pressure.",
							PerRecordReadTimeout.TotalMilliseconds);
						return;
					}

					break;
				}

				sawAny = true;
				if (first is null)
				{
					first = record;
					dto.FirstEvent = ParseFirstEvent(first);
				}
				else
				{
					record.Dispose();
				}

				returned++;
			}
		}
		finally
		{
			first?.Dispose();
		}

		dto.Count = returned;
		if (returned == 0)
		{
			dto.Status = IpcResultStatus.Success;
			dto.Outcome = "NoEvents";
			dto.Message = string.Format(
				System.Globalization.CultureInfo.InvariantCulture,
				"No 4624/4625 events in the last {0}h. Audit policy may be disabled, or the host genuinely had no auth activity.",
				dto.LookbackHours);
			return;
		}

		dto.Status = IpcResultStatus.Success;
		dto.Outcome = "Ok";
		dto.Message = string.Format(
			System.Globalization.CultureInfo.InvariantCulture,
			"Read {0} event(s); first event id={1} time={2:O}.",
			returned,
			dto.FirstEvent?.EventId,
			dto.FirstEvent?.TimeUtc);
	}

	private static SecurityAuthProbeEvent? ParseFirstEvent(EventRecord record)
	{
		try
		{
			string xml = record.ToXml();
			System.Xml.XmlDocument? doc = EventXmlParser.ParseSafe(xml);
			int? logonType = EventXmlParser.GetInt(doc, "LogonType");
			string? ip = EventXmlParser.GetData(doc, "IpAddress");
			string? user = EventXmlParser.GetData(doc, "TargetUserName")
				?? EventXmlParser.GetData(doc, "SubjectUserName")
				?? EventXmlParser.GetDataAt(doc, 5);
			string? domain = EventXmlParser.GetData(doc, "TargetDomainName")
				?? EventXmlParser.GetData(doc, "SubjectDomainName");
			string? status = NtStatusFormatter.Canonicalize(EventXmlParser.GetData(doc, "Status"));
			string? subStatus = NtStatusFormatter.Canonicalize(EventXmlParser.GetData(doc, "SubStatus"));
			string? subStatusMeaning = SubStatusCatalog.Translate(subStatus);
			string? authPackage = EventXmlParser.GetData(doc, "AuthenticationPackageName")
				?? EventXmlParser.GetData(doc, "Package")
				?? EventXmlParser.GetData(doc, "PackageName");
			string? workstation = EventXmlParser.GetData(doc, "WorkstationName")
				?? EventXmlParser.GetData(doc, "Workstation");

			return new SecurityAuthProbeEvent
			{
				EventId = record.Id,
				TimeUtc = record.TimeCreated?.ToUniversalTime(),
				User = user,
				Domain = domain,
				Ip = ip,
				LogonType = logonType,
				Status = status,
				SubStatus = subStatus,
				SubStatusMeaning = subStatusMeaning,
				AuthPackage = authPackage,
				WorkstationName = workstation,
			};
		}
		catch (Exception)
		{
			return new SecurityAuthProbeEvent
			{
				EventId = record.Id,
				TimeUtc = record.TimeCreated?.ToUniversalTime(),
			};
		}
	}

	private static string ResolveIdentity()
	{
		try
		{
			if (OperatingSystem.IsWindows())
			{
				using WindowsIdentity current = WindowsIdentity.GetCurrent();
				return current.Name ?? "(unknown)";
			}
		}
		catch (Exception)
		{
			// Best effort — identity is observational.
		}

		return Environment.UserDomainName + "\\" + Environment.UserName;
	}

	/// <summary>Map a Windows EventLogException-style failure into the discriminated probe
	/// outcome. Used by the long-running collector/backfill so they can surface consistent
	/// outcomes via the shared probe DTO contract.</summary>
	public static (string Outcome, string Message) ClassifyChannelException(Exception ex)
	{
		ArgumentNullException.ThrowIfNull(ex);
		return ex switch
		{
			UnauthorizedAccessException => ("AccessDenied",
				"Service account lacks 'Manage auditing and security log' or membership in 'Event Log Readers'."),
			EventLogNotFoundException => ("ChannelNotFound",
				"Security channel not found on this host."),
			_ => ("Error", ex.Message),
		};
	}
}
