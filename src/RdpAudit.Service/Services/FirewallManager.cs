// File:    src/RdpAudit.Service/Services/FirewallManager.cs
// Module:  RdpAudit.Service.Services
// Purpose: Creates / updates / removes Windows Firewall block rules for source IPs that
//          exceeded brute-force thresholds. Uses netsh advfirewall with sanitised arguments.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>Result of a firewall operation.</summary>
public sealed record FirewallOperationResult(bool Success, int ExitCode, string? Stderr);

/// <summary>Creates / updates / removes Windows Firewall block rules for source IPs.</summary>
public sealed class FirewallManager
{
	private readonly ILogger<FirewallManager> _logger;
	private readonly IFirewallCommandRunner _runner;

	public FirewallManager(ILogger<FirewallManager> logger)
		: this(logger, new NetshFirewallCommandRunner())
	{
	}

	internal FirewallManager(ILogger<FirewallManager> logger, IFirewallCommandRunner runner)
	{
		_logger = logger;
		_runner = runner;
	}

	/// <summary>Validates rule name and IP, then constructs the netsh argument list.</summary>
	internal static IReadOnlyList<string> BuildBlockArgs(string ruleName, string ip)
	{
		ValidateRuleName(ruleName);
		ValidateIp(ip);
		string fullName = string.Format(CultureInfo.InvariantCulture, "{0}-{1}", ruleName, ip);
		return new List<string>
		{
			"advfirewall", "firewall", "add", "rule",
			string.Format(CultureInfo.InvariantCulture, "name={0}", fullName),
			"dir=in",
			"action=block",
			string.Format(CultureInfo.InvariantCulture, "remoteip={0}", ip),
			"protocol=any",
			"enable=yes",
		};
	}

	/// <summary>Constructs the netsh argument list for unblocking a previously blocked IP.</summary>
	internal static IReadOnlyList<string> BuildUnblockArgs(string ruleName, string ip)
	{
		ValidateRuleName(ruleName);
		ValidateIp(ip);
		string fullName = string.Format(CultureInfo.InvariantCulture, "{0}-{1}", ruleName, ip);
		return new List<string>
		{
			"advfirewall", "firewall", "delete", "rule",
			string.Format(CultureInfo.InvariantCulture, "name={0}", fullName),
		};
	}

	private static void ValidateRuleName(string ruleName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		// Allow only alphanumeric, dash, underscore, and dot — defensive against argument injection.
		foreach (char c in ruleName)
		{
			if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_' || c == '.'))
			{
				throw new ArgumentException(
					"Rule name contains characters that could change netsh argument parsing: '" + ruleName + "'",
					nameof(ruleName));
			}
		}
	}

	private static void ValidateIp(string ip)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		if (!IPAddress.TryParse(ip, out _))
		{
			throw new ArgumentException("Not a valid IPv4 / IPv6 address: '" + ip + "'", nameof(ip));
		}
	}

	/// <summary>Creates an inbound block rule for the given source IP. Idempotent: deletes any prior rule first.</summary>
	[SupportedOSPlatform("windows")]
	public async Task<FirewallOperationResult> BlockAsync(string ruleName, string ip, CancellationToken ct)
	{
		// Best-effort delete first to keep behaviour idempotent, then add.
		await _runner.RunAsync(BuildUnblockArgs(ruleName, ip), ct).ConfigureAwait(false);
		FirewallOperationResult res = await _runner.RunAsync(BuildBlockArgs(ruleName, ip), ct).ConfigureAwait(false);
		if (!res.Success)
		{
			_logger.LogWarning("Firewall block failed for IP {Ip}: exit={Exit} stderr={Stderr}", ip, res.ExitCode, res.Stderr);
		}
		else
		{
			_logger.LogInformation("Firewall block rule installed for {Ip}", ip);
		}
		return res;
	}

	/// <summary>Removes the inbound block rule previously installed for the given source IP.</summary>
	[SupportedOSPlatform("windows")]
	public async Task<FirewallOperationResult> UnblockAsync(string ruleName, string ip, CancellationToken ct)
	{
		FirewallOperationResult res = await _runner.RunAsync(BuildUnblockArgs(ruleName, ip), ct).ConfigureAwait(false);
		if (!res.Success)
		{
			_logger.LogDebug("Firewall unblock returned non-zero (rule may not exist) for {Ip}: exit={Exit}", ip, res.ExitCode);
		}
		else
		{
			_logger.LogInformation("Firewall block rule removed for {Ip}", ip);
		}
		return res;
	}
}

/// <summary>Indirection for testability — production runner spawns netsh.exe.</summary>
internal interface IFirewallCommandRunner
{
	Task<FirewallOperationResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct);
}

internal sealed class NetshFirewallCommandRunner : IFirewallCommandRunner
{
	private readonly IExternalCommandRunner _runner;
	private readonly TimeSpan _timeout;

	[SupportedOSPlatform("windows")]
	public NetshFirewallCommandRunner()
		: this(new ExternalCommandRunner(), ExternalCommandRunner.DefaultTimeout)
	{
	}

	internal NetshFirewallCommandRunner(IExternalCommandRunner runner, TimeSpan timeout)
	{
		ArgumentNullException.ThrowIfNull(runner);
		_runner = runner;
		_timeout = timeout > TimeSpan.Zero ? timeout : ExternalCommandRunner.DefaultTimeout;
	}

	[SupportedOSPlatform("windows")]
	public async Task<FirewallOperationResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(args);
		try
		{
			ExternalCommandResult result = await _runner.RunDirectAsync(
				commandLabel: "netsh " + string.Join(' ', args),
				executable: "netsh.exe",
				arguments: args,
				timeout: _timeout,
				ct: ct).ConfigureAwait(false);

			return new FirewallOperationResult(
				Success: result.Success,
				ExitCode: result.TimedOut ? -1 : result.ExitCode,
				Stderr: result.StdErr);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			return new FirewallOperationResult(false, -1, ex.Message);
		}
	}
}
