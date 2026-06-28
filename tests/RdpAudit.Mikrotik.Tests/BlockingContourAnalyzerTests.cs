/*
 * File   : BlockingContourAnalyzerTests.cs
 * Project: RdpAudit.Mikrotik.Tests
 * Purpose: Verifies BlockingContourAnalyzer.Decide chooses the correct drop-rule placement for every
 *          combination of fasttrack presence, RAW-chain support and operator preference — the core
 *          correctness guarantee that fast-tracked attacker packets are never silently bypassed.
 * Depends: RdpAudit.Mikrotik.Core.BlockingContourAnalyzer, BlockPlacement, Xunit
 * Extends: When a new BlockPlacement value or decision branch is introduced, add a matching case here.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using RdpAudit.Mikrotik.Core;
using Xunit;

namespace RdpAudit.Mikrotik.Tests;

public sealed class BlockingContourAnalyzerTests
{
	// ── RAW Prerouting (highest priority) ──────────────────────────────────────────

	[Theory]
	[InlineData(false, false)]
	[InlineData(true, false)]
	[InlineData(false, true)]
	[InlineData(true, true)]
	public void Decide_RawPreferredAndSupported_AlwaysChoosesRawPrerouting(bool hasFastTrack, bool _)
	{
		(BlockPlacement placement, string explanation) =
			BlockingContourAnalyzer.Decide(hasFastTrack, supportsRawChain: true, preferRawChain: true);

		Assert.Equal(BlockPlacement.RawPrerouting, placement);
		Assert.Contains("RAW prerouting", explanation);
	}

	[Fact]
	public void Decide_RawPreferredButUnsupported_FallsBackToFilter()
	{
		// preferRawChain=true but supportsRawChain=false → must NOT pick RAW.
		(BlockPlacement placement, _) =
			BlockingContourAnalyzer.Decide(hasFastTrack: false, supportsRawChain: false, preferRawChain: true);

		Assert.Equal(BlockPlacement.FilterInputAppend, placement);
	}

	// ── FastTrack Handling ─────────────────────────────────────────────────────────

	[Fact]
	public void Decide_FastTrackPresent_NoRaw_InsertsBeforeFastTrack()
	{
		(BlockPlacement placement, string explanation) =
			BlockingContourAnalyzer.Decide(hasFastTrack: true, supportsRawChain: true, preferRawChain: false);

		Assert.Equal(BlockPlacement.FilterBeforeFastTrack, placement);
		Assert.Contains("BEFORE the fasttrack", explanation);
	}

	[Fact]
	public void Decide_FastTrackPresent_RawSupportedButNotPreferred_StaysInFilter()
	{
		(BlockPlacement placement, _) =
			BlockingContourAnalyzer.Decide(hasFastTrack: true, supportsRawChain: true, preferRawChain: false);

		Assert.Equal(BlockPlacement.FilterBeforeFastTrack, placement);
	}

	// ── Plain Filter Append (default) ────────────────────────────────────────────────

	[Fact]
	public void Decide_NoFastTrack_NoRaw_AppendsToFilterInput()
	{
		(BlockPlacement placement, string explanation) =
			BlockingContourAnalyzer.Decide(hasFastTrack: false, supportsRawChain: false, preferRawChain: false);

		Assert.Equal(BlockPlacement.FilterInputAppend, placement);
		Assert.Contains("No fasttrack", explanation);
	}

	[Fact]
	public void Decide_AllThreeOutcomes_AreReachable()
	{
		BlockPlacement raw = BlockingContourAnalyzer.Decide(false, true, true).Placement;
		BlockPlacement beforeFt = BlockingContourAnalyzer.Decide(true, false, false).Placement;
		BlockPlacement append = BlockingContourAnalyzer.Decide(false, false, false).Placement;

		Assert.Equal(BlockPlacement.RawPrerouting, raw);
		Assert.Equal(BlockPlacement.FilterBeforeFastTrack, beforeFt);
		Assert.Equal(BlockPlacement.FilterInputAppend, append);
	}
}
