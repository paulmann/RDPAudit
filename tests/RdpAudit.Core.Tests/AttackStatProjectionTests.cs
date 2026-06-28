// File:    tests/RdpAudit.Core.Tests/AttackStatProjectionTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the AttackStatProjection helper: JSON top-10 round-trip, deterministic
//          ordering, capping, malformed-input safety, and duration arithmetic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Validates the <see cref="AttackStatProjection"/> helper.</summary>
public class AttackStatProjectionTests
{
	[Fact]
	public void SerializeTopLogins_EmitsJsonArray()
	{
		string json = AttackStatProjection.SerializeTopLogins(new[] { "admin", "root" });
		Assert.Equal("[\"admin\",\"root\"]", json);
	}

	[Fact]
	public void SerializeTopLogins_CapsAtTen()
	{
		string[] logins = Enumerable.Range(0, 20).Select(i => $"u{i}").ToArray();

		string json = AttackStatProjection.SerializeTopLogins(logins);
		IReadOnlyList<string> roundTripped = AttackStatProjection.DeserializeTopLogins(json);

		Assert.Equal(AttackStatProjection.TopLoginsLimit, roundTripped.Count);
		Assert.Equal("u0", roundTripped[0]);
		Assert.Equal("u9", roundTripped[9]);
	}

	[Fact]
	public void SerializeTopLogins_SkipsNullAndWhitespace()
	{
		string json = AttackStatProjection.SerializeTopLogins(new[] { "admin", null, "   ", "root" });
		IReadOnlyList<string> roundTripped = AttackStatProjection.DeserializeTopLogins(json);

		Assert.Equal(new[] { "admin", "root" }, roundTripped);
	}

	[Fact]
	public void SerializeTopLogins_NullInputYieldsEmptyArray()
	{
		Assert.Equal("[]", AttackStatProjection.SerializeTopLogins(null!));
	}

	[Fact]
	public void DeserializeTopLogins_NullOrEmptyYieldsEmpty()
	{
		Assert.Empty(AttackStatProjection.DeserializeTopLogins(null));
		Assert.Empty(AttackStatProjection.DeserializeTopLogins(string.Empty));
		Assert.Empty(AttackStatProjection.DeserializeTopLogins("   "));
	}

	[Fact]
	public void DeserializeTopLogins_MalformedYieldsEmpty()
	{
		Assert.Empty(AttackStatProjection.DeserializeTopLogins("{not-json"));
		Assert.Empty(AttackStatProjection.DeserializeTopLogins("12345"));
	}

	[Fact]
	public void ComputeDurationSeconds_ClampsNegativeToZero()
	{
		DateTime later = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
		DateTime earlier = later.AddSeconds(-30);

		Assert.Equal(30, AttackStatProjection.ComputeDurationSeconds(earlier, later));
		Assert.Equal(0, AttackStatProjection.ComputeDurationSeconds(later, earlier));
	}

	[Fact]
	public void ComputeTopLogins_OrdersByFrequencyThenAlphabetically()
	{
		string[] attempts = { "admin", "root", "admin", "root", "user", "admin" };

		IReadOnlyList<string> top = AttackStatProjection.ComputeTopLogins(attempts);

		Assert.Equal(new[] { "admin", "root", "user" }, top);
	}

	[Fact]
	public void ComputeTopLogins_IsCaseInsensitive()
	{
		string[] attempts = { "Admin", "ADMIN", "admin", "root" };

		IReadOnlyList<string> top = AttackStatProjection.ComputeTopLogins(attempts);

		Assert.Equal(2, top.Count);
		Assert.Contains("admin", top, StringComparer.OrdinalIgnoreCase);
		Assert.Contains("root", top, StringComparer.OrdinalIgnoreCase);
	}

	[Fact]
	public void ComputeTopLogins_HonoursLimit()
	{
		string[] attempts = Enumerable.Range(0, 50).Select(i => $"u{i:D2}").ToArray();

		IReadOnlyList<string> top = AttackStatProjection.ComputeTopLogins(attempts, limit: 3);

		Assert.Equal(3, top.Count);
	}
}
