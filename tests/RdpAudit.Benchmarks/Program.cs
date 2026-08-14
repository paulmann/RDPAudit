/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : Program.cs
// Project: RdpAudit.Benchmarks (RdpAudit.Benchmarks)
// Purpose: BenchmarkDotNet entry point. Delegates command-line dispatch to BenchmarkSwitcher
//          so callers can pick a subset (--filter *RingBuffer* etc.) or run the full grid.
// Depends: BenchmarkDotNet.Running.BenchmarkSwitcher
// Extends: When adding a new benchmark class, add it below RingBufferBenchmark; no other
//          changes are required — BenchmarkSwitcher discovers types via reflection.

using BenchmarkDotNet.Running;

namespace RdpAudit.Benchmarks;

/// <summary>Entry point for the benchmarks assembly. Kept intentionally minimal so the
/// contract is: <c>dotnet run -c Release -- --filter *</c>.</summary>
public static class Program
{
	public static int Main(string[] args)
	{
		BenchmarkSwitcher
			.FromAssembly(typeof(Program).Assembly)
			.Run(args);
		return 0;
	}
}
