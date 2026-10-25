/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageBenchmarkExitCode.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: The process exit codes the runner returns, in one place so a script that wraps it can tell
//          "the command line was wrong" apart from "the run refused to start" apart from "the run
//          happened but a probe failed". A caller that cannot make that distinction would treat a
//          refused run as a successful measurement of nothing.
// Depends: System.Object
// Extends: Add a code when a new failure class appears; never reuse a code for two meanings.

namespace RdpAudit.StorageBenchmarks;

/// <summary>Exit codes of the storage benchmark runner.</summary>
public static class StorageBenchmarkExitCode
{
	/// <summary>The run completed and its report was written.</summary>
	public const int Success = 0;

	/// <summary>The command line was rejected.</summary>
	public const int UsageError = 1;

	/// <summary>The run refused to start: a store that already holds a database, or a path inside the
	/// production RdpAudit data directory.</summary>
	public const int Refused = 2;

	/// <summary>The run completed and wrote its report, but at least one probe failed. The report names
	/// the failed probes; the metrics they would have produced are reported as failed, not as zero.</summary>
	public const int ProbeFailures = 3;
}
