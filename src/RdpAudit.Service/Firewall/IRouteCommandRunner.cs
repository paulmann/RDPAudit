// File:    src/RdpAudit.Service/Firewall/IRouteCommandRunner.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Indirection for spawning route.exe with a sanitised argument vector. The production
//          runner spawns the real process through ExternalCommandRunner.RunDirectAsync (no shell
//          wrapping); tests substitute an in-memory implementation so the route-blackhole provider
//          is fully unit-testable cross-platform.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Firewall;

/// <summary>Outcome of a single route.exe invocation.</summary>
/// <param name="ExitCode">Process exit code; 0 indicates success.</param>
/// <param name="StdOut">Captured standard output, never containing secret material.</param>
/// <param name="StdErr">Captured standard error, never containing secret material.</param>
public readonly record struct RouteCommandResult(int ExitCode, string StdOut, string StdErr)
{
	/// <summary>True when the process exited with code zero.</summary>
	public bool Success => ExitCode == 0;
}

/// <summary>Indirection for spawning route.exe; production runner uses the OS process, tests fake it.</summary>
public interface IRouteCommandRunner
{
	/// <summary>Runs route.exe with the supplied argument vector and returns the captured result.</summary>
	Task<RouteCommandResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct);
}

/// <summary>Default <see cref="IRouteCommandRunner"/> implementation spawning route.exe directly.</summary>
public sealed class RouteCommandRunner : IRouteCommandRunner
{
	private readonly IExternalCommandRunner _runner;
	private readonly TimeSpan _timeout;

	[SupportedOSPlatform("windows")]
	public RouteCommandRunner()
		: this(new ExternalCommandRunner(), ExternalCommandRunner.DefaultTimeout)
	{
	}

	internal RouteCommandRunner(IExternalCommandRunner runner, TimeSpan timeout)
	{
		ArgumentNullException.ThrowIfNull(runner);
		_runner = runner;
		_timeout = timeout > TimeSpan.Zero ? timeout : ExternalCommandRunner.DefaultTimeout;
	}

	/// <inheritdoc/>
	[SupportedOSPlatform("windows")]
	public async Task<RouteCommandResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(args);
		ExternalCommandResult result = await _runner
			.RunDirectAsync(
				commandLabel: "route " + string.Join(' ', args),
				executable: "route.exe",
				arguments: args,
				timeout: _timeout,
				ct: ct)
			.ConfigureAwait(false);
		return new RouteCommandResult(
			result.TimedOut ? -1 : result.ExitCode,
			result.StdOut,
			result.StdErr);
	}
}
