/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionPolicyOptionsTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Locks the information-density retention defaults and clamping policy: disabled and
//          legal-hold-free by default, every documented default value, every Resolve* bound, the
//          fail-safe protected event set (an empty JSON array must not disarm it), the anchor-scope
//          fallback for an out-of-range ordinal, and the legal-hold / trigger-presence helpers. A
//          regression here could let a hand-edited appsettings.json widen a ceiling, shorten the
//          protected tail, or drop the protected event classes entirely.
// Depends: RetentionPolicyOptions, RetentionAnchorScope, Xunit
// Extends: Add a case per new field and per new Resolve* helper.

using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pins the information-density retention option defaults and clamping behaviour.</summary>
public class RetentionPolicyOptionsTests
{
	[Fact]
	public void Defaults_AreDisabledWithSafeSettings()
	{
		RetentionPolicyOptions options = new();
		Assert.False(options.Enabled);
		Assert.False(options.LegalHold);
		Assert.Equal(RetentionAnchorScope.PerCode, options.AnchorScope);
		Assert.Equal(512, options.TailKeepPerCode);
		Assert.Equal(1_000, options.CandidateMinRows);
		Assert.Equal(7, options.MinAgeDays);
		Assert.Equal(50_000, options.MaxRowsPerPass);
		Assert.Equal(250, options.MaxWriterLockMs);
		Assert.Equal(2_000, options.DeleteBatchRows);
		Assert.Equal(0L, options.MaxDatabaseBytes);
		Assert.Equal(0L, options.MaxRawEventRows);
		Assert.Equal(0L, options.MinFreeDiskBytes);
	}

	[Fact]
	public void Defaults_DisarmNoPressureTrigger()
	{
		RetentionPolicyOptions options = new();
		Assert.False(options.HasAnyPressureTrigger());
		Assert.False(options.IsPressureDeletionAllowed());
	}

	[Fact]
	public void Defaults_CarryTheFullProtectedEventSet()
	{
		RetentionPolicyOptions options = new();
		HashSet<int> protectedCodes = options.ResolveProtectedEventIds();
		foreach (int expected in RetentionPolicyOptions.DefaultProtectedEventIds)
		{
			Assert.Contains(expected, protectedCodes);
		}

		Assert.Equal(14, protectedCodes.Count);
		Assert.Equal(14, options.ProtectedEventIds.Length);
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-5, 1)]
	[InlineData(1, 1)]
	[InlineData(512, 512)]
	[InlineData(100_000, 100_000)]
	[InlineData(100_001, 100_000)]
	public void ResolveTailKeepPerCode_ClampsToSupportedRange(int input, int expected)
	{
		RetentionPolicyOptions options = new() { TailKeepPerCode = input };
		Assert.Equal(expected, options.ResolveTailKeepPerCode());
	}

	[Theory]
	[InlineData(0, 10)]
	[InlineData(-1, 10)]
	[InlineData(10, 10)]
	[InlineData(1_000, 1_000)]
	[InlineData(100_000_000, 100_000_000)]
	[InlineData(100_000_001, 100_000_000)]
	public void ResolveCandidateMinRows_ClampsToSupportedRange(int input, int expected)
	{
		RetentionPolicyOptions options = new() { CandidateMinRows = input };
		Assert.Equal(expected, options.ResolveCandidateMinRows());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-30, 1)]
	[InlineData(1, 1)]
	[InlineData(7, 7)]
	[InlineData(3_650, 3_650)]
	[InlineData(9_999, 3_650)]
	public void ResolveMinAgeDays_ClampsToSupportedRange(int input, int expected)
	{
		RetentionPolicyOptions options = new() { MinAgeDays = input };
		Assert.Equal(expected, options.ResolveMinAgeDays());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-1, 1)]
	[InlineData(1, 1)]
	[InlineData(50_000, 50_000)]
	[InlineData(10_000_000, 10_000_000)]
	[InlineData(10_000_001, 10_000_000)]
	public void ResolveMaxRowsPerPass_ClampsToSupportedRange(int input, int expected)
	{
		RetentionPolicyOptions options = new() { MaxRowsPerPass = input };
		Assert.Equal(expected, options.ResolveMaxRowsPerPass());
	}

	[Theory]
	[InlineData(0, 10)]
	[InlineData(-1, 10)]
	[InlineData(10, 10)]
	[InlineData(250, 250)]
	[InlineData(60_000, 60_000)]
	[InlineData(60_001, 60_000)]
	public void ResolveMaxWriterLockMs_ClampsToSupportedRange(int input, int expected)
	{
		RetentionPolicyOptions options = new() { MaxWriterLockMs = input };
		Assert.Equal(expected, options.ResolveMaxWriterLockMs());
	}

	[Theory]
	[InlineData(0, 100)]
	[InlineData(-1, 100)]
	[InlineData(100, 100)]
	[InlineData(2_000, 2_000)]
	[InlineData(100_000, 100_000)]
	[InlineData(100_001, 100_000)]
	public void ResolveDeleteBatchRows_ClampsToSupportedRange(int input, int expected)
	{
		RetentionPolicyOptions options = new() { DeleteBatchRows = input };
		Assert.Equal(expected, options.ResolveDeleteBatchRows());
	}

	[Theory]
	[InlineData(-1L, 0L)]
	[InlineData(0L, 0L)]
	[InlineData(1L, 1L)]
	[InlineData(long.MaxValue, long.MaxValue)]
	public void ResolveByteCeilings_ClampToZeroOrAbove(long input, long expected)
	{
		RetentionPolicyOptions options = new()
		{
			MaxDatabaseBytes = input,
			MaxRawEventRows = input,
			MinFreeDiskBytes = input,
		};
		Assert.Equal(expected, options.ResolveMaxDatabaseBytes());
		Assert.Equal(expected, options.ResolveMaxRawEventRows());
		Assert.Equal(expected, options.ResolveMinFreeDiskBytes());
	}

	[Fact]
	public void ResolveProtectedEventIds_EmptyArrayFallsBackToTheDefaultSet()
	{
		RetentionPolicyOptions options = new() { ProtectedEventIds = [] };
		HashSet<int> protectedCodes = options.ResolveProtectedEventIds();
		Assert.Equal(14, protectedCodes.Count);
		Assert.Contains(4720, protectedCodes);
		Assert.Contains(7045, protectedCodes);
	}

	[Fact]
	public void ResolveProtectedEventIds_NullFallsBackToTheDefaultSet()
	{
		RetentionPolicyOptions options = new() { ProtectedEventIds = null! };
		Assert.Equal(14, options.ResolveProtectedEventIds().Count);
	}

	[Fact]
	public void ResolveProtectedEventIds_HonoursAnExplicitNarrowerSet()
	{
		RetentionPolicyOptions options = new() { ProtectedEventIds = [4720, 7045] };
		HashSet<int> protectedCodes = options.ResolveProtectedEventIds();
		Assert.Equal(2, protectedCodes.Count);
		Assert.Contains(4720, protectedCodes);
		Assert.Contains(7045, protectedCodes);
		Assert.DoesNotContain(4771, protectedCodes);
	}

	[Fact]
	public void ResolveProtectedEventIds_DropsNonPositiveCodes()
	{
		RetentionPolicyOptions options = new() { ProtectedEventIds = [0, -5, 4720] };
		HashSet<int> protectedCodes = options.ResolveProtectedEventIds();
		Assert.Single(protectedCodes);
		Assert.Contains(4720, protectedCodes);
	}

	[Theory]
	[InlineData(RetentionAnchorScope.PerCode, RetentionAnchorScope.PerCode)]
	[InlineData(RetentionAnchorScope.PerCodeAndIp, RetentionAnchorScope.PerCodeAndIp)]
	[InlineData((RetentionAnchorScope)99, RetentionAnchorScope.PerCode)]
	[InlineData((RetentionAnchorScope)(-1), RetentionAnchorScope.PerCode)]
	public void ResolveAnchorScope_FallsBackToPerCodeForAnUndefinedOrdinal(
		RetentionAnchorScope input,
		RetentionAnchorScope expected)
	{
		RetentionPolicyOptions options = new() { AnchorScope = input };
		Assert.Equal(expected, options.ResolveAnchorScope());
	}

	[Fact]
	public void LegalHold_BlocksPressureDeletionEvenWhenEnabled()
	{
		RetentionPolicyOptions options = new() { Enabled = true, LegalHold = true };
		Assert.False(options.IsPressureDeletionAllowed());
	}

	[Fact]
	public void EnabledWithoutLegalHold_AllowsPressureDeletion()
	{
		RetentionPolicyOptions options = new() { Enabled = true };
		Assert.True(options.IsPressureDeletionAllowed());
	}

	[Fact]
	public void HasAnyPressureTrigger_ReportsEachCeiling()
	{
		Assert.False(new RetentionPolicyOptions().HasAnyPressureTrigger());
		Assert.True(new RetentionPolicyOptions { MaxDatabaseBytes = 1 }.HasAnyPressureTrigger());
		Assert.True(new RetentionPolicyOptions { MaxRawEventRows = 1 }.HasAnyPressureTrigger());
		Assert.True(new RetentionPolicyOptions { MinFreeDiskBytes = 1 }.HasAnyPressureTrigger());
		Assert.False(new RetentionPolicyOptions { MaxDatabaseBytes = -1 }.HasAnyPressureTrigger());
	}

	[Fact]
	public void Constants_ExposeSupportedBounds()
	{
		Assert.Equal(1, RetentionPolicyOptions.MinTailKeepPerCode);
		Assert.Equal(100_000, RetentionPolicyOptions.MaxTailKeepPerCode);
		Assert.Equal(10, RetentionPolicyOptions.MinCandidateMinRows);
		Assert.Equal(100_000_000, RetentionPolicyOptions.MaxCandidateMinRows);
		Assert.Equal(1, RetentionPolicyOptions.MinMinAgeDays);
		Assert.Equal(3_650, RetentionPolicyOptions.MaxMinAgeDays);
		Assert.Equal(1, RetentionPolicyOptions.MinMaxRowsPerPass);
		Assert.Equal(10_000_000, RetentionPolicyOptions.MaxMaxRowsPerPass);
		Assert.Equal(10, RetentionPolicyOptions.MinMaxWriterLockMs);
		Assert.Equal(60_000, RetentionPolicyOptions.MaxMaxWriterLockMs);
		Assert.Equal(100, RetentionPolicyOptions.MinDeleteBatchRows);
		Assert.Equal(100_000, RetentionPolicyOptions.MaxDeleteBatchRows);
	}

	[Fact]
	public void ResolveProtectedEventIds_ReturnsMutableDefaultsIsolation()
	{
		RetentionPolicyOptions options = new();
		HashSet<int> first = options.ResolveProtectedEventIds();
		first.Add(1234);
		Assert.DoesNotContain(1234, options.ResolveProtectedEventIds());
	}

	[Fact]
	public void StorageOptions_ExposesRetentionPolicy_DisabledByDefault()
	{
		StorageOptions storage = new();
		Assert.NotNull(storage.RetentionPolicy);
		Assert.False(storage.RetentionPolicy.Enabled);
		Assert.False(storage.RetentionPolicy.LegalHold);
	}

	[Fact]
	public void Describe_NamesEveryEffectiveSetting()
	{
		RetentionPolicyOptions options = new() { Enabled = true };
		string description = options.Describe();
		Assert.Contains("Enabled=True", description);
		Assert.Contains("TailKeepPerCode=512", description);
		Assert.Contains("CandidateMinRows=1000", description);
		Assert.Contains("MinAgeDays=7", description);
		Assert.Contains("ProtectedCodes=14", description);
	}
}
