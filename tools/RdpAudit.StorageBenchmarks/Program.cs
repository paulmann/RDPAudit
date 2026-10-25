/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : Program.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: The process entry point. It does three things and nothing else: it hands the command line to
//          the runner, it prints the refusal when the run must not start, and it turns any unexpected
//          exception into a non-zero exit code with the exception on stderr. All the work - and all the
//          decisions about what is measured and what is not - lives in StorageBenchmarkRunner, which is
//          also what the smoke test calls in-process.
// Depends: StorageBenchmarkRunner, StorageBenchmarkExitCode
// Extends: Keep this file free of measurement logic; add probes to the runner, not here.

using RdpAudit.StorageBenchmarks;

try
{
	using CancellationTokenSource cancellation = new();
	Console.CancelKeyPress += (_, eventArgs) =>
	{
		eventArgs.Cancel = true;
		cancellation.Cancel();
	};

	return await StorageBenchmarkRunner.RunAsync(args, Console.Out, cancellation.Token).ConfigureAwait(false);
}
catch (OperationCanceledException)
{
	Console.Error.WriteLine("cancelled before the report was written.");
	return StorageBenchmarkExitCode.ProbeFailures;
}
catch (Exception ex)
{
	Console.Error.WriteLine("the benchmark failed: " + ex);
	return StorageBenchmarkExitCode.ProbeFailures;
}
