// File:    src/RdpAudit.Service/Firewall/RouteBlackholeProvider.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Experimental IFirewallProvider that realises a block by adding a per-IP host route to
//          an unreachable blackhole gateway via the route.exe command, with a sanitised argument
//          list (never shell concatenation). Windows has no native Linux-style discard route, so
//          this mainly drops OUTBOUND replies to the attacker IP — it is a defence-in-depth
//          supplement to the firewall, not a replacement. The provider validates that the
//          configured gateway is genuinely unreachable before relying on it; if it is reachable
//          the block is refused (forwarding attacker traffic to a live next-hop would be worse
//          than no route at all).
// Extends: RdpAudit.Core.Firewall.IFirewallProvider
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;

namespace RdpAudit.Service.Firewall;

/// <summary>Probes whether a candidate blackhole gateway is reachable on the host.</summary>
/// <remarks>Indirection for testability — production sends one ICMP echo with a short timeout.</remarks>
public interface IGatewayReachabilityProbe
{
	/// <summary>True when the gateway answered within the timeout; false when unreachable.</summary>
	Task<bool> IsReachableAsync(string gateway, CancellationToken ct);
}

/// <summary>Production reachability probe using a single ICMP echo.</summary>
public sealed class PingGatewayReachabilityProbe : IGatewayReachabilityProbe
{
	private static readonly TimeSpan PingTimeout = TimeSpan.FromMilliseconds(800);

	/// <inheritdoc/>
	public async Task<bool> IsReachableAsync(string gateway, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(gateway);
		ct.ThrowIfCancellationRequested();
		if (!IPAddress.TryParse(gateway, out IPAddress? parsed))
		{
			return false;
		}

		try
		{
			using Ping ping = new();
			PingReply reply = await ping
				.SendPingAsync(parsed, (int)PingTimeout.TotalMilliseconds)
				.ConfigureAwait(false);
			return reply.Status == IPStatus.Success;
		}
		catch (PingException)
		{
			return false;
		}
		catch (InvalidOperationException)
		{
			return false;
		}
	}
}

/// <summary>Experimental route-blackhole <see cref="IFirewallProvider"/>.</summary>
public sealed class RouteBlackholeProvider : IFirewallProvider
{
	private readonly ILogger<RouteBlackholeProvider> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IRouteCommandRunner _runner;
	private readonly IGatewayReachabilityProbe _probe;

	[SupportedOSPlatform("windows")]
	public RouteBlackholeProvider(
		ILogger<RouteBlackholeProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options)
		: this(logger, options, new RouteCommandRunner(), new PingGatewayReachabilityProbe())
	{
	}

	internal RouteBlackholeProvider(
		ILogger<RouteBlackholeProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		IRouteCommandRunner runner,
		IGatewayReachabilityProbe probe)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(runner);
		ArgumentNullException.ThrowIfNull(probe);
		_logger = logger;
		_options = options;
		_runner = runner;
		_probe = probe;
	}

	public string ProviderId => "RouteBlackhole";

	public async Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		if (!OperatingSystem.IsWindows())
		{
			return new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Unreachable,
				ProviderId = ProviderId,
				Message = "Route-blackhole backend is only available on Windows hosts.",
			};
		}

		string gateway = _options.CurrentValue.Firewall.RouteBlackholeGateway;
		bool reachable = await _probe.IsReachableAsync(gateway, ct).ConfigureAwait(false);
		BlackholeGatewayValidation validation = RouteBlackholeCommandBuilder.ClassifyGateway(gateway, reachable);

		return validation == BlackholeGatewayValidation.UsableUnreachable
			? new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Available,
				ProviderId = ProviderId,
				Message = "Experimental route-blackhole backend: gateway is unreachable and usable as a blackhole next-hop.",
			}
			: new FirewallStatusReport
			{
				Status = FirewallProviderStatus.NotConfigured,
				ProviderId = ProviderId,
				Message = "Experimental route-blackhole backend: configured gateway is not a usable blackhole next-hop (" + validation + ").",
			};
	}

	public async Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);
		ct.ThrowIfCancellationRequested();
		if (!OperatingSystem.IsWindows())
		{
			return FirewallActionResult.UnavailableFor(ProviderId, "Route-blackhole backend only runs on Windows hosts.");
		}

		string gateway = _options.CurrentValue.Firewall.RouteBlackholeGateway;
		bool reachable = await _probe.IsReachableAsync(gateway, ct).ConfigureAwait(false);
		BlackholeGatewayValidation validation = RouteBlackholeCommandBuilder.ClassifyGateway(gateway, reachable);
		if (validation != BlackholeGatewayValidation.UsableUnreachable)
		{
			_logger.LogWarning(
				"Route-blackhole block refused for {Ip}: gateway {Gateway} validation={Validation}",
				request.Ip,
				gateway,
				validation);
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.Refused,
				ProviderId = ProviderId,
				Message = "Blackhole gateway is not a usable unreachable next-hop (" + validation + "); refusing to install a route that could forward attacker traffic.",
			};
		}

		IReadOnlyList<string> addArgs;
		try
		{
			addArgs = RouteBlackholeCommandBuilder.BuildAddRouteArgs(request.Ip, gateway);
		}
		catch (ArgumentException ex)
		{
			_logger.LogWarning("Route-blackhole block refused: {Message}", ex.Message);
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.InvalidRequest,
				ProviderId = ProviderId,
				Message = "Destination IP or gateway failed validation for a host route.",
			};
		}

		// Idempotency: best-effort delete first, then add.
		await _runner.RunAsync(RouteBlackholeCommandBuilder.BuildDeleteRouteArgs(request.Ip), ct).ConfigureAwait(false);
		RouteCommandResult addResult = await _runner.RunAsync(addArgs, ct).ConfigureAwait(false);
		string ruleId = "route:" + RouteBlackholeCommandBuilder.ParseAndValidateDestination(request.Ip);

		if (!addResult.Success)
		{
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.Unavailable,
				ProviderId = ProviderId,
				RuleId = ruleId,
				Message = "route add returned a non-zero exit code.",
			};
		}

		_logger.LogInformation(
			"Route-blackhole installed for {Ip} via gateway {Gateway}",
			request.Ip,
			gateway);
		return new FirewallActionResult
		{
			Status = FirewallActionStatus.Success,
			ProviderId = ProviderId,
			RuleId = ruleId,
			Message = "Experimental blackhole host route installed (drops outbound replies to the IP).",
		};
	}

	public async Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		ct.ThrowIfCancellationRequested();
		if (!OperatingSystem.IsWindows())
		{
			return FirewallActionResult.UnavailableFor(ProviderId, "Route-blackhole backend only runs on Windows hosts.");
		}

		IReadOnlyList<string> delArgs;
		try
		{
			delArgs = RouteBlackholeCommandBuilder.BuildDeleteRouteArgs(ip);
		}
		catch (ArgumentException)
		{
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.InvalidRequest,
				ProviderId = ProviderId,
				Message = "Destination IP failed validation.",
			};
		}

		RouteCommandResult res = await _runner.RunAsync(delArgs, ct).ConfigureAwait(false);
		string ruleId = "route:" + RouteBlackholeCommandBuilder.ParseAndValidateDestination(ip);
		return new FirewallActionResult
		{
			Status = res.Success ? FirewallActionStatus.Success : FirewallActionStatus.NotFound,
			ProviderId = ProviderId,
			RuleId = ruleId,
			Message = res.Success ? "Blackhole host route removed." : "No matching host route (already removed).",
		};
	}

	public Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		// Route enumeration parsing is host-locale dependent and out of scope for this backend's
		// listing contract; ActiveBlocks rows are the source of truth for route-blackhole blocks.
		return Task.FromResult<IReadOnlyList<FirewallBlockEntry>>(Array.Empty<FirewallBlockEntry>());
	}
}
