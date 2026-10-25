// File:    src/RdpAudit.Service/Services/ConfigRepairReporter.cs
// Module:  RdpAudit.Service.Services
// Purpose: Thread-safe singleton that records the most recent stale-appsettings repair report
//          (Security channel added, required event IDs added, reason). Surfaced via the
//          Diagnostic IPC command so the Configurator can show operators when a stale config
//          was patched at startup.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;

namespace RdpAudit.Service.Services;

/// <summary>Thread-safe holder for the most recent <see cref="MonitoringConfigRepairReport"/>.
/// PostConfigure callbacks write to it; the diagnostics dispatcher reads it.</summary>
public sealed class ConfigRepairReporter
{
	private readonly object _gate = new();
	private MonitoringConfigRepairReport? _last;
	private DateTime? _lastUtc;
	private long _changedRuns;

	/// <summary>Record a fresh repair report. Always replaces the previous snapshot.</summary>
	public void Record(MonitoringConfigRepairReport report)
	{
		ArgumentNullException.ThrowIfNull(report);
		lock (_gate)
		{
			_last = report;
			_lastUtc = DateTime.UtcNow;
			if (report.Changed)
			{
				_changedRuns++;
			}
		}
	}

	/// <summary>Latest snapshot, or null if no repair has been recorded yet.</summary>
	public MonitoringConfigRepairReport? LastReport
	{
		get { lock (_gate) { return _last; } }
	}

	/// <summary>UTC of the most recent <see cref="Record"/> call, or null when never invoked.</summary>
	public DateTime? LastReportUtc
	{
		get { lock (_gate) { return _lastUtc; } }
	}

	/// <summary>Number of times <see cref="Record"/> was called with a report whose
	/// <see cref="MonitoringConfigRepairReport.Changed"/> bit was true.</summary>
	public long ChangedRunCount
	{
		get { lock (_gate) { return _changedRuns; } }
	}
}
