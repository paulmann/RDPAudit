// File:    src/RdpAudit.Service/Processors/SecurityCorrelationWatchdog.cs
// Module:  RdpAudit.Service.Processors
// Purpose: Detects "TS-RCM 261 / RdpCoreTS 131 fires but no Security 4624/4625/4648 arrives in
//          the same time window" — the operator-visible symptom of audit-logon-failure policy
//          being disabled, the service lacking Security log read privilege, or a stale bookmark
//          on the Security channel. The watchdog updates ServiceMetrics so the configurator can
//          surface a precise diagnostic instead of leaving Live Events / Attack Statistics with
//          unexplained empty IP / user columns.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;

namespace RdpAudit.Service.Processors;

/// <summary>
/// Stateful per-process watchdog that compares the running cadence of <em>pre-authentication</em>
/// RDP observations (TS-RCM 261, RdpCoreTS 131) against the cadence of authoritative Security-log
/// authentication events (4624 successful logon, 4625 failed logon, 4648 explicit credentials).
/// When several pre-auth events accumulate without a corresponding Security event inside a
/// configurable correlation window, the watchdog records a diagnostic that explains the most
/// likely cause: audit-logon-failure / audit-logon-success policy is off, the service is not
/// privileged to read the Security channel, the Security channel itself is unavailable, the
/// XPath filter is wrong, or the persisted bookmark has skipped past the events.
/// </summary>
public sealed class SecurityCorrelationWatchdog
{
	/// <summary>Default time window in which a pre-auth observation expects to be paired with a
	/// Security 4624/4625/4648. Five minutes is long enough to tolerate normal Windows audit-log
	/// emission delay while still short enough that an operator's first failed logon trips the
	/// diagnostic immediately.</summary>
	public static readonly TimeSpan DefaultWindow = TimeSpan.FromMinutes(5);

	/// <summary>How many unpaired pre-auth observations must accumulate before the watchdog raises
	/// its first diagnostic. Set to 3 so a single noisy 131 burst does not trip the alarm — but a
	/// real "RDP brute force with no Security events" scenario fires after the third attempt.</summary>
	public const int DefaultOrphanThreshold = 3;

	private readonly ServiceMetrics _metrics;
	private readonly TimeSpan _window;
	private readonly int _orphanThreshold;
	private readonly object _gate = new();
	private int _consecutiveOrphans;
	private DateTime? _lastSecurityUtc;
	private DateTime? _lastPreAuthUtc;
	private bool _diagnosticEmitted;

	public SecurityCorrelationWatchdog(ServiceMetrics metrics)
		: this(metrics, DefaultWindow, DefaultOrphanThreshold)
	{
	}

	internal SecurityCorrelationWatchdog(ServiceMetrics metrics, TimeSpan window, int orphanThreshold)
	{
		_metrics = metrics;
		_window = window;
		_orphanThreshold = Math.Max(1, orphanThreshold);
	}

	/// <summary>
	/// Apply a batch of normalised <see cref="RawEvent"/> rows to the watchdog. Updates the
	/// per-process metrics counters, identifies pre-auth-without-Security-pairing anomalies, and
	/// raises a one-shot diagnostic string on <see cref="ServiceMetrics.SecurityCorrelationDiagnostic"/>
	/// when the orphan threshold is crossed. Idempotent: re-applying the same batch will not
	/// double-count.
	/// </summary>
	public void Apply(IReadOnlyList<RawEvent> entities)
	{
		if (entities.Count == 0)
		{
			return;
		}

		lock (_gate)
		{
			foreach (RawEvent e in entities)
			{
				if (IsSecurityAuthEvent(e))
				{
					ProcessSecurity(e);
				}
				else if (IsPreAuthEvent(e))
				{
					ProcessPreAuth(e);
				}
			}

			MaybeEmitDiagnostic();
		}
	}

	private void ProcessSecurity(RawEvent e)
	{
		switch (e.EventId)
		{
			case 4624:
				_metrics.IncrementSecurity4624(e.TimeUtc);
				break;
			case 4625:
				_metrics.IncrementSecurity4625(e.TimeUtc);
				break;
			case 4648:
				_metrics.IncrementSecurity4648(e.TimeUtc);
				break;
		}

		if (_lastSecurityUtc is null || e.TimeUtc > _lastSecurityUtc)
		{
			_lastSecurityUtc = e.TimeUtc;
		}

		// Receiving any Security authentication event clears the orphan streak and re-arms the
		// diagnostic so the next gap can fire its own warning. The diagnostic string on
		// ServiceMetrics is cleared too — the configurator should stop showing the "audit policy
		// looks broken" banner once a real Security event flows through again.
		_consecutiveOrphans = 0;
		if (_diagnosticEmitted)
		{
			_metrics.SetSecurityCorrelationDiagnostic(null);
		}

		_diagnosticEmitted = false;
	}

	private void ProcessPreAuth(RawEvent e)
	{
		_metrics.NotePreAuth(e.TimeUtc);

		if (_lastPreAuthUtc is null || e.TimeUtc > _lastPreAuthUtc)
		{
			_lastPreAuthUtc = e.TimeUtc;
		}

		// A pre-auth event is "orphaned" when the most recent Security 4624/4625/4648 is either
		// absent entirely or older than the correlation window. Older events are not orphans; the
		// scenario we care about is the operator-visible "I just tried to log in but nothing in
		// Live Events shows the username / IP". We tally every orphan into ServiceMetrics so the
		// IPC dashboard can show "N attempts went unanswered" even before the diagnostic string
		// is emitted; the diagnostic string itself is set once per gap (re-armed when a Security
		// event next arrives).
		if (_lastSecurityUtc is null || (e.TimeUtc - _lastSecurityUtc.Value) > _window)
		{
			_consecutiveOrphans++;
			_metrics.NoteOrphanIncrement();
		}
	}

	private void MaybeEmitDiagnostic()
	{
		if (_diagnosticEmitted || _consecutiveOrphans < _orphanThreshold)
		{
			return;
		}

		string diagnostic = BuildDiagnostic();
		_metrics.SetSecurityCorrelationDiagnostic(diagnostic);
		_diagnosticEmitted = true;
	}

	private string BuildDiagnostic()
	{
		string sinceClause = _lastSecurityUtc is DateTime last
			? $"Last Security auth event observed at {last:O}."
			: "No Security 4624/4625/4648 has been observed since the service started.";

		return string.Concat(
			$"Detected {_consecutiveOrphans} consecutive RDP pre-authentication observations ",
			"(TS-RCM 261 / RdpCoreTS 131) without a matching Security 4624/4625/4648 inside the ",
			$"{_window.TotalMinutes:F0}-minute correlation window. ",
			sinceClause,
			" Likely causes: (1) audit-logon-failure / audit-logon-success policy is disabled — ",
			"run 'auditpol /get /subcategory:\"Logon\",\"Logoff\"' and enable Failure auditing; ",
			"(2) the RdpAuditService account lacks Security log read privilege — grant ",
			"'Manage auditing and security log' (SeSecurityPrivilege) or add it to the Event Log ",
			"Readers group; (3) the Security channel is unavailable on this host; ",
			"(4) the persisted bookmark for the Security channel skipped past the events — ",
			"delete the Bookmarks row for channel='Security' and restart the service; ",
			"(5) the EventLogWatcher XPath filter is rejecting the events — verify EventCatalog ",
			"lists 4624/4625/4648 under the Security channel.");
	}

	private static bool IsSecurityAuthEvent(RawEvent e)
	{
		if (!string.Equals(e.Channel, "Security", StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}

		return e.EventId == 4624 || e.EventId == 4625 || e.EventId == 4648;
	}

	private static bool IsPreAuthEvent(RawEvent e)
	{
		const string TsRcm = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
		const string RdpCoreTs = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";

		// TS-RCM 261 (listener pre-auth) and RdpCoreTS 131 (connection attempt) both fire before any
		// Security auth event — they are the canonical "RDP traffic touched the box" signals.
		if (e.EventId == 261 && string.Equals(e.Channel, TsRcm, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		if (e.EventId == 131 && string.Equals(e.Channel, RdpCoreTs, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		return false;
	}
}
