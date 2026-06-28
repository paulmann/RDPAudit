// File:    tests/RdpAudit.Core.Tests/LocalTimeFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: v1.2.1 — pin the local-time rendering contract used by every operator-facing grid /
//          status strip / diagnostic block. The DB remains UTC; the rendering boundary MUST
//          produce a local-clock string so the operator sees timestamps that match the wall
//          clock they are looking at. Assertions are timezone-agnostic: we compare against
//          the same conversion the helper performs so the tests work in any CI timezone.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class LocalTimeFormatterTests
{
	[Fact]
	public void ToLocal_UtcKind_ReturnsHostLocalEquivalent()
	{
		DateTime utc = new(2026, 5, 20, 12, 30, 45, DateTimeKind.Utc);
		DateTime local = LocalTimeFormatter.ToLocal(utc);
		Assert.Equal(DateTimeKind.Local, local.Kind);
		Assert.Equal(utc, local.ToUniversalTime());
	}

	[Fact]
	public void ToLocal_UnspecifiedKind_IsTreatedAsUtc()
	{
		// DB layer reads back DateTime values as Unspecified — the conversion MUST treat them
		// as UTC, never as already-local, otherwise we would render a host-clock offset twice.
		DateTime db = new(2026, 5, 20, 12, 30, 45, DateTimeKind.Unspecified);
		DateTime local = LocalTimeFormatter.ToLocal(db);
		Assert.Equal(DateTime.SpecifyKind(db, DateTimeKind.Utc).ToLocalTime(), local);
	}

	[Fact]
	public void FormatLocal_DefaultDateTime_ReturnsEmptyString()
	{
		Assert.Equal(string.Empty, LocalTimeFormatter.FormatLocal(default(DateTime)));
	}

	[Fact]
	public void FormatLocal_Nullable_NullReturnsFallback()
	{
		Assert.Equal("(never)", LocalTimeFormatter.FormatLocal((DateTime?)null));
		Assert.Equal(string.Empty, LocalTimeFormatter.FormatLocal((DateTime?)null, fallback: string.Empty));
	}

	[Fact]
	public void FormatLocal_PopulatedUtc_RoundTripsThroughExpectedFormat()
	{
		DateTime utc = new(2026, 5, 20, 12, 0, 0, DateTimeKind.Utc);
		string rendered = LocalTimeFormatter.FormatLocal(utc);
		string expected = utc.ToLocalTime().ToString(LocalTimeFormatter.GridFormat, CultureInfo.InvariantCulture);
		Assert.Equal(expected, rendered);
	}

	[Fact]
	public void FormatBoth_RendersLocalThenUtc()
	{
		DateTime utc = new(2026, 5, 20, 12, 0, 0, DateTimeKind.Utc);
		string both = LocalTimeFormatter.FormatBoth(utc);
		Assert.Contains("(local)", both, StringComparison.Ordinal);
		Assert.Contains("(UTC)", both, StringComparison.Ordinal);
		// Reproducible: the rendered UTC half MUST match the canonical wall-clock format.
		Assert.Contains(utc.ToString(LocalTimeFormatter.GridFormat, CultureInfo.InvariantCulture), both, StringComparison.Ordinal);
	}
}
