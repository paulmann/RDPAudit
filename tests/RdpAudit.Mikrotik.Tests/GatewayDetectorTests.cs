/*
 * File   : GatewayDetectorTests.cs
 * Project: RdpAudit.Mikrotik.Tests
 * Purpose: Verifies GatewayDetector behaves safely and consistently regardless of the host network
 *          configuration of the CI/build machine — it must never throw, must return a distinct list,
 *          and DetectPrimaryGatewayIp must always agree with the head of DetectGatewayIps.
 * Depends: RdpAudit.Mikrotik.Helpers.GatewayDetector, Xunit
 * Extends: When a new discovery source (e.g. ARP neighbours) is merged in, add invariants for it here.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Net;
using RdpAudit.Mikrotik.Helpers;
using Xunit;

namespace RdpAudit.Mikrotik.Tests;

public sealed class GatewayDetectorTests
{
	// ── No-Throw Guarantee ─────────────────────────────────────────────────────────

	[Fact]
	public void DetectGatewayIps_NeverThrows_AndReturnsNonNull()
	{
		GatewayDetector detector = new();

		IReadOnlyList<string> result = detector.DetectGatewayIps();

		Assert.NotNull(result);
	}

	[Fact]
	public void DetectPrimaryGatewayIp_NeverThrows()
	{
		GatewayDetector detector = new();

		// Must not throw on any host configuration; null is an acceptable outcome.
		_ = detector.DetectPrimaryGatewayIp();
	}

	// ── Invariants (host-independent) ───────────────────────────────────────────────

	[Fact]
	public void DetectGatewayIps_ReturnsDistinctEntries()
	{
		GatewayDetector detector = new();

		IReadOnlyList<string> result = detector.DetectGatewayIps();

		Assert.Equal(result.Count, result.Distinct(StringComparer.OrdinalIgnoreCase).Count());
	}

	[Fact]
	public void DetectGatewayIps_AllEntriesAreParsableIPv4_AndNotLoopbackOrZero()
	{
		GatewayDetector detector = new();

		IReadOnlyList<string> result = detector.DetectGatewayIps();

		foreach (string entry in result)
		{
			Assert.True(IPAddress.TryParse(entry, out IPAddress? addr), $"Not a valid IP: {entry}");
			Assert.False(IPAddress.IsLoopback(addr!), $"Loopback leaked: {entry}");
			Assert.NotEqual("0.0.0.0", entry);
		}
	}

	[Fact]
	public void DetectPrimaryGatewayIp_AgreesWithHeadOfList()
	{
		GatewayDetector detector = new();

		IReadOnlyList<string> all = detector.DetectGatewayIps();
		string? primary = detector.DetectPrimaryGatewayIp();

		if (all.Count == 0)
		{
			Assert.Null(primary);
		}
		else
		{
			Assert.Equal(all[0], primary);
		}
	}
}
