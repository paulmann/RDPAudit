// File:    src/RdpAudit.Core/Config/ProcessMonitoringOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Configuration for the process-monitoring feature (PROCESS_NEW detection + optional
//          automated session close). All numeric values resolve through clamped Resolve* helpers
//          so unsafe hand-edited values fall back to safe bounds. The feature watches Windows
//          Security 4688 process-creation events against the persistent KnownProcesses baseline;
//          baseline windows are evaluated independently (7 / 30 / 365 days), and "new" means
//          the identity was never observed within AlertWindowDays. Auto-close of the affected
//          RDP session is OFF by default and always respects SessionControl.Enabled/AllowLogoff.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Configuration for process monitoring and automated session close.</summary>
public sealed class ProcessMonitoringOptions
{
	/// <summary>Master switch. When false NewProcessRule is not registered in the pipeline.</summary>
	public bool Enabled { get; set; } = true;

	/// <summary>Baseline look-back windows in days, evaluated independently. Default 7, 30, 365.</summary>
	public List<int> BaselineWindowsDays { get; set; } = new() { 7, 30, 365 };

	/// <summary>Alert window: an identity not observed within this many days is considered "new"
	/// and raises PROCESS_NEW. Default 7. Clamped to 1..365.</summary>
	public int AlertWindowDays { get; set; } = 7;

	/// <summary>Global default for auto-closing the affected RDP session on a new process.
	/// OFF by default - operators opt in explicitly. Always respects SessionControl gates.</summary>
	public bool AutoCloseSessionOnNewProcess { get; set; }

	/// <summary>When true, system-account processes may raise PROCESS_NEW. Default true.</summary>
	public bool EnableAlertOnSystemProcesses { get; set; } = true;

	/// <summary>Maximum rows retained in ProcessObservations. Clamped to 100..100000; default 5000.</summary>
	public int MaxObservations { get; set; } = 5000;

	/// <summary>Hard per-minute rate limit for automated session-close logoff operations.
	/// Clamped to 1..120; default 10.</summary>
	public int MaxAutoCloseOperationsPerMinute { get; set; } = 10;

	/// <summary>Poll interval (seconds) for ProcessAlertAutoResponder. Clamped to 1..300; default 10.</summary>
	public int AutoClosePollIntervalSeconds { get; set; } = 10;

	/// <summary>Minimum allowed baseline window (days).</summary>
	public const int BaselineWindowMinDays = 1;

	/// <summary>Maximum allowed baseline window (days).</summary>
	public const int BaselineWindowMaxDays = 365;

	/// <summary>Resolves the effective baseline windows, filtering to distinct values in
	/// [1..365], sorted ascending, and refusing to return an empty list (falls back to {7}).</summary>
	public IReadOnlyList<int> ResolveBaselineWindowsDays()
	{
		List<int> source = BaselineWindowsDays ?? new List<int>();
		List<int> distinct = new();
		foreach (int raw in source)
		{
			int clamped = Math.Clamp(raw, BaselineWindowMinDays, BaselineWindowMaxDays);
			if (!distinct.Contains(clamped))
			{
				distinct.Add(clamped);
			}
		}

		if (distinct.Count == 0)
		{
			distinct.Add(7);
		}

		distinct.Sort();
		return distinct;
	}

	/// <summary>Resolves the alert window to a safe [1..365] value.</summary>
	public int ResolveAlertWindowDays() => Math.Clamp(AlertWindowDays, 1, 365);

	/// <summary>Resolves the observation-journal row cap to a safe [100..100000] value.</summary>
	public int ResolveMaxObservations() => Math.Clamp(MaxObservations, 100, 100000);

	/// <summary>Resolves the auto-close rate limit to a safe [1..120] value.</summary>
	public int ResolveMaxAutoCloseOperationsPerMinute() => Math.Clamp(MaxAutoCloseOperationsPerMinute, 1, 120);

	/// <summary>Resolves the responder poll interval to a safe [1..300] seconds value.</summary>
	public int ResolveAutoClosePollIntervalSeconds() => Math.Clamp(AutoClosePollIntervalSeconds, 1, 300);
}
