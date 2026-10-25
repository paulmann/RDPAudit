/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabasePageShardsTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Verifies the Shards section of the Database tab: the policy editor exposes every field the
//          service governs, the two mutating actions stay disabled while nothing has been read and while
//          the service is unreachable, a save shows a field-by-field old-to-new diff and writes NOTHING
//          when the operator declines, a no-change save does not prompt at all, the capacity banner
//          switches to its red treatment only for a real refusal, and the collection prompt lists every
//          eligible candidate with path, address, size, records and age.
//          Every test avoids a real window handle and never blocks the STA thread: the harness pumps the
//          message queue with deadlines.
// Depends: DatabasePage, StaTestHarness, xunit
// Extends: Add a case here whenever a Shards control, gate or banner state is added.

using System.Runtime.Versioning;
using System.Windows.Forms;
using RdpAudit.Configurator.Forms;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Config;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class DatabasePageShardsTests
{
	private readonly StaTestHarness _ui = new(nameof(DatabasePageShardsTests));

	// ── Structure ────────────────────────────────────────────────────────────────

	/// <summary>Given the Database tab, when the Shards section is inspected, then it carries the whole
	/// capacity policy editor, the two governed actions and the explicit statement about the one shard
	/// action that does not exist.</summary>
	[Fact]
	public void ShardsTab_ExposesTheWholeCapacityPolicyEditor()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			TabPage shards = FindTab(page, "Shards");

			Assert.NotNull(FindButtonIn(shards, "Refresh inventory"));
			Assert.NotNull(FindButtonIn(shards, "Save policy"));
			Assert.NotNull(FindButtonIn(shards, "Collect orphans"));

			// Eleven numeric fields: ring capacity, writer pool, file budget, the three byte/disk ceilings,
			// the orphan grace period and the four cardinality-guard thresholds.
			Assert.Equal(11, AllControls(shards).OfType<NumericUpDown>().Count());

			// The two switches and the actions root are editable text/checkbox controls.
			Assert.Contains(
				AllControls(shards).OfType<CheckBox>(),
				check => check.Text.Contains("Shard writing enabled", StringComparison.Ordinal));
			Assert.Contains(
				AllControls(shards).OfType<CheckBox>(),
				check => check.Text.Contains("Cardinality guard enabled", StringComparison.Ordinal));
			Assert.Contains(AllControls(shards).OfType<TextBox>(), text => text.Width >= 400);

			// Compaction is stated as not implemented, and no button pretends otherwise.
			Assert.Contains(
				AllControls(shards).OfType<Label>(),
				label => string.Equals(label.Text, DatabasePage.ShardCompactionStubText, StringComparison.Ordinal));
			Assert.Contains("Compaction is not implemented yet", DatabasePage.ShardCompactionStubText, StringComparison.Ordinal);
			Assert.DoesNotContain(
				AllControls(shards).OfType<Button>(),
				button => (button.Text ?? string.Empty).Contains("compact", StringComparison.OrdinalIgnoreCase));
		});
	}

	/// <summary>Given nothing has been read yet from the service, when the section is built, then both
	/// mutating actions are disabled: there is no policy to diff against and no candidate list to
	/// confirm, so neither action may be armed.</summary>
	[Fact]
	public void ShardsTab_StartsWithBothMutatingActionsDisabled()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			Assert.False(page.ShardsSaveEnabled);
			Assert.False(page.ShardsCollectEnabled);
		});
	}

	/// <summary>Given the service is unreachable, when the inventory is refreshed, then the failure is
	/// reported and both mutating actions stay disabled - the page never presents an editor it cannot
	/// save.</summary>
	[Fact]
	public void Refresh_WithoutAService_ReportsFailureAndKeepsTheActionsDisabled()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			_ui.Await(page.LoadShardsAsync(), "LoadShardsAsync");

			Assert.Contains("unavailable", page.StatusText, StringComparison.OrdinalIgnoreCase);
			Assert.False(page.ShardsSaveEnabled);
			Assert.False(page.ShardsCollectEnabled);
			Assert.Contains("unknown", page.ShardBannerText, StringComparison.OrdinalIgnoreCase);
			Assert.False(page.ShardBannerShowsRefusal);
		});
	}

	/// <summary>Given the service is unreachable, when the operator tries to collect orphans, then the
	/// dry run fails, the failure is reported as an error and nothing is deleted.</summary>
	[Fact]
	public void CollectOrphans_WithoutAService_ReportsFailure()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			bool prompted = false;
			page.ConfirmPrompt = (_, _) =>
			{
				prompted = true;
				return true;
			};

			_ui.Await(page.CollectShardGarbageAsync(), "CollectShardGarbageAsync");

			Assert.Contains("Orphan dry run failed", page.StatusText, StringComparison.Ordinal);
			Assert.False(prompted);
		});
	}

	// ── Confirmation gate ───────────────────────────────────────────────────────

	/// <summary>Given no policy has been loaded, when Save is pressed, then it refuses without prompting:
	/// there is no baseline to diff against, and the operator is told why.</summary>
	[Fact]
	public void Save_WithoutALoadedPolicy_RefusesWithoutPrompting()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			bool prompted = false;
			page.ConfirmPrompt = (_, _) =>
			{
				prompted = true;
				return true;
			};

			_ui.Await(page.SaveShardsPolicyAsync(), "SaveShardsPolicyAsync");

			Assert.Contains("never loaded", page.StatusText, StringComparison.OrdinalIgnoreCase);
			Assert.False(prompted);
		});
	}

	/// <summary>Given a loaded policy whose values were changed, when the operator declines the
	/// confirmation, then the prompt showed the changed field as old → new and nothing was sent: the gate
	/// is what stands between the editor and a write.</summary>
	[Fact]
	public void Save_ShowsTheDiffAndWritesNothingWhenDeclined()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			page.ApplyShardPolicyToControls(NewPolicyDto(values => values.MaxShardFiles = 4096));

			// Change exactly one field through the editor's own capture path.
			NumericUpDown files = FindNumeric(page, "Max shard files", 4096);
			files.Value = 512;

			string? prompt = null;
			page.ConfirmPrompt = (message, _) =>
			{
				prompt = message;
				return false;
			};

			_ui.Await(page.SaveShardsPolicyAsync(), "SaveShardsPolicyAsync");

			Assert.NotNull(prompt);
			Assert.Contains("Changes (old → new)", prompt, StringComparison.Ordinal);
			Assert.Contains("MaxShardFiles: 4096 → 512", prompt, StringComparison.Ordinal);
			Assert.DoesNotContain("OrphanGraceDays", prompt, StringComparison.Ordinal);
			Assert.Contains("cancelled", page.StatusText, StringComparison.OrdinalIgnoreCase);
		});
	}

	/// <summary>Given a loaded policy that was not changed, when Save is pressed, then nothing is
	/// prompted and the status says there is nothing to save.</summary>
	[Fact]
	public void Save_WithNoChanges_DoesNotPrompt()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			page.ApplyShardPolicyToControls(NewPolicyDto(values => values.MaxShardFiles = 4096));
			bool prompted = false;
			page.ConfirmPrompt = (_, _) =>
			{
				prompted = true;
				return true;
			};

			_ui.Await(page.SaveShardsPolicyAsync(), "SaveShardsPolicyAsync");

			Assert.False(prompted);
			Assert.Contains("No changes to save", page.StatusText, StringComparison.Ordinal);
		});
	}

	// ── Diff, capture and banner ────────────────────────────────────────────────

	/// <summary>Given two policies, when the diff is built, then only the fields that actually differ
	/// appear, each as old → new.</summary>
	[Fact]
	public void Diff_ListsOnlyChangedFields()
	{
		ShardingPolicyValuesDto loaded = ShardingPolicyValuesDto.FromOptions(new ShardingOptions());
		ShardingPolicyMutationRequest request = new()
		{
			Enabled = loaded.Enabled,
			ActionsRoot = loaded.ActionsRoot,
			ShardCapacityRecords = loaded.ShardCapacityRecords,
			MaxOpenWriters = loaded.MaxOpenWriters,
			MaxShardFiles = 512,
			MaxShardBytes = 0,
			MaxTotalShardBytes = 1_000_000,
			MinFreeDiskBytes = loaded.MinFreeDiskBytes,
			OrphanGraceDays = loaded.OrphanGraceDays,
			SubnetAggregation = new SubnetAggregationMutationDto
			{
				Enabled = loaded.SubnetAggregationEnabled,
				TotalFileThreshold = loaded.SubnetAggregationTotalFileThreshold,
				NewFilesPerIntervalLimit = loaded.SubnetAggregationNewFilesPerIntervalLimit,
				IntervalSeconds = loaded.SubnetAggregationIntervalSeconds,
				MinSourceRowsPerInterval = loaded.SubnetAggregationMinSourceRowsPerInterval,
			},
		};

		List<string> diff = DatabasePage.BuildShardPolicyDiff(loaded, request);

		Assert.Equal(2, diff.Count);
		Assert.Contains("MaxShardFiles: 4096 → 512", diff);
		Assert.Contains("MaxTotalShardBytes: 0 → 1000000", diff);

		List<string> none = DatabasePage.BuildShardPolicyDiff(
			ShardingPolicyValuesDto.FromOptions(new ShardingOptions()),
			new ShardingPolicyMutationRequest
			{
				MaxShardFiles = 4096,
				OrphanGraceDays = 14,
				SubnetAggregation = new SubnetAggregationMutationDto(),
			});
		Assert.Empty(none);
	}

	/// <summary>Given a policy reported by the service, when it is pushed into the editor and read back,
	/// then every field round-trips - the editor never invents or drops a value.</summary>
	[Fact]
	public void Capture_RoundTripsTheAppliedPolicy()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			page.ApplyShardPolicyToControls(NewPolicyDto(values =>
			{
				values.Enabled = true;
				values.ActionsRoot = @"D:\shards";
				values.ShardCapacityRecords = 2048;
				values.MaxOpenWriters = 16;
				values.MaxShardFiles = 512;
				values.MaxShardBytes = 65_536;
				values.MaxTotalShardBytes = 1_073_741_824;
				values.MinFreeDiskBytes = 5_368_709_120;
				values.OrphanGraceDays = 30;
				values.SubnetAggregationEnabled = true;
				values.SubnetAggregationTotalFileThreshold = 100;
				values.SubnetAggregationNewFilesPerIntervalLimit = 10;
				values.SubnetAggregationIntervalSeconds = 30;
				values.SubnetAggregationMinSourceRowsPerInterval = 4;
			}));

			ShardingPolicyMutationRequest captured = page.CaptureShardPolicyRequest();

			Assert.True(captured.Enabled);
			Assert.Equal(@"D:\shards", captured.ActionsRoot);
			Assert.Equal(2048, captured.ShardCapacityRecords);
			Assert.Equal(16, captured.MaxOpenWriters);
			Assert.Equal(512, captured.MaxShardFiles);
			Assert.Equal(65_536L, captured.MaxShardBytes);
			Assert.Equal(1_073_741_824L, captured.MaxTotalShardBytes);
			Assert.Equal(5_368_709_120L, captured.MinFreeDiskBytes);
			Assert.Equal(30, captured.OrphanGraceDays);
			Assert.True(captured.SubnetAggregation.Enabled);
			Assert.Equal(100, captured.SubnetAggregation.TotalFileThreshold);
			Assert.Equal(10, captured.SubnetAggregation.NewFilesPerIntervalLimit);
			Assert.Equal(30, captured.SubnetAggregation.IntervalSeconds);
			Assert.Equal(4, captured.SubnetAggregation.MinSourceRowsPerInterval);
		});
	}

	/// <summary>Given a service that reports a refusal, when the banner is updated, then it takes the
	/// degraded treatment and states why; given a healthy report it stays calm and says what it observed.</summary>
	[Fact]
	public void Banner_TakesTheDegradedTreatmentOnlyForARealRefusal()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();

			page.UpdateShardBanner(new ShardCapacityStatusDto
			{
				RefusalActive = true,
				LastRefusalReason = ShardRefusalReason.ByteBudget,
				RefusedSourceCount = 12,
				ByteBudgetExceeded = true,
				Message = "new shards refused since 2026-09-15 10:00:00 (ByteBudget); 12 source(s) unsharded so far",
			});
			Assert.True(page.ShardBannerShowsRefusal);
			Assert.Contains("ByteBudget", page.ShardBannerText, StringComparison.Ordinal);
			Assert.Contains("12", page.ShardBannerText, StringComparison.Ordinal);

			page.UpdateShardBanner(new ShardCapacityStatusDto
			{
				CardinalityGuardEnabled = true,
				CardinalityGuardActive = true,
				AggregatedSourceCount = 3,
				TotalShardBytes = 4096,
				MaxTotalShardBytes = 1_048_576,
			});
			Assert.True(page.ShardBannerShowsRefusal);
			Assert.Contains("guard engaged", page.ShardBannerText, StringComparison.Ordinal);

			page.UpdateShardBanner(new ShardCapacityStatusDto
			{
				CardinalityGuardEnabled = true,
				TotalShardBytes = 4096,
				MaxTotalShardBytes = 1_048_576,
				ActionsVolumeFreeBytes = 10_000_000_000,
			});
			Assert.False(page.ShardBannerShowsRefusal);
			Assert.Contains("guard armed", page.ShardBannerText, StringComparison.Ordinal);

			page.UpdateShardBanner(null);
			Assert.False(page.ShardBannerShowsRefusal);
			Assert.Contains("not reported", page.ShardBannerText, StringComparison.OrdinalIgnoreCase);
		});
	}

	// ── Collection prompt ───────────────────────────────────────────────────────

	/// <summary>Given a candidate list, when the collection prompt is built, then every candidate is
	/// named with its path, address, size, retained records and age, and each candidate's disposition is
	/// already decided by the service - the dialog only shows what will happen.</summary>
	[Fact]
	public void CollectionPrompt_NamesEveryCandidate()
	{
		List<ShardGarbageCandidateDto> eligible =
		[
			new()
			{
				RelativePath = "actions/cb/00/cb007100.rdpshard",
				IpText = "203.0.113.10",
				Bytes = 1152,
				Records = 4,
				AgeDays = 41.5,
				Disposition = ShardGarbageDisposition.Eligible,
			},
			new()
			{
				RelativePath = "actions/cb/00/cb007101.rdpshard",
				IpText = "203.0.113.11",
				Bytes = 1152,
				Records = 0,
				AgeDays = 30,
				Disposition = ShardGarbageDisposition.Eligible,
			},
		];

		string prompt = DatabasePage.BuildOrphanPrompt(
			eligible,
			new ShardGarbageCollectionReportDto { OrphanGraceDays = 14 }).ToString();

		Assert.Contains("Delete 2 orphan shard file(s) older than 14 day(s)?", prompt, StringComparison.Ordinal);
		Assert.Contains("actions/cb/00/cb007100.rdpshard | 203.0.113.10 | 1152 | 4 | 41.5 d", prompt, StringComparison.Ordinal);
		Assert.Contains("actions/cb/00/cb007101.rdpshard | 203.0.113.11 | 1152 | 0 | 30 d", prompt, StringComparison.Ordinal);
		Assert.Contains("re-validated on the service", prompt, StringComparison.Ordinal);
	}

	/// <summary>Given a candidate list far larger than the dialog can show, when the prompt is built,
	/// then it is capped and the remaining count is stated instead of being silently dropped.</summary>
	[Fact]
	public void CollectionPrompt_CapsTheListAndStatesTheRemainder()
	{
		List<ShardGarbageCandidateDto> eligible = new();
		for (int index = 0; index < 60; index++)
		{
			eligible.Add(new ShardGarbageCandidateDto
			{
				RelativePath = "actions/cb/00/cb0071" + index.ToString("X2", System.Globalization.CultureInfo.InvariantCulture) + ".rdpshard",
				IpText = "203.0.113." + index.ToString(System.Globalization.CultureInfo.InvariantCulture),
				Bytes = 1152,
				Records = 1,
				AgeDays = 30,
				Disposition = ShardGarbageDisposition.Eligible,
			});
		}

		string prompt = DatabasePage.BuildOrphanPrompt(
			eligible,
			new ShardGarbageCollectionReportDto { OrphanGraceDays = 14 }).ToString();

		Assert.Contains("Delete 60 orphan shard file(s)", prompt, StringComparison.Ordinal);
		Assert.Contains("and 10 more candidate(s)", prompt, StringComparison.Ordinal);
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	private static DatabasePage NewPage() => new(new IpcClient());

	private static IEnumerable<Control> AllControls(Control root)
	{
		foreach (Control child in root.Controls)
		{
			yield return child;
			foreach (Control grand in AllControls(child))
			{
				yield return grand;
			}
		}
	}

	private static TabPage FindTab(Control root, string title)
		=> AllControls(root).OfType<TabControl>()
			.SelectMany(control => control.TabPages.Cast<TabPage>())
			.Single(page => string.Equals(page.Text, title, StringComparison.Ordinal));

	private static Button? FindButtonIn(Control root, string textPrefix)
		=> AllControls(root).OfType<Button>().FirstOrDefault(button =>
			(button.Text ?? string.Empty).StartsWith(textPrefix, StringComparison.Ordinal));

	/// <summary>Finds the numeric editor that sits next to the supplied caption, so a test drives the
	/// same control an operator would.</summary>
	private static NumericUpDown FindNumeric(Control root, string caption, decimal expectedValue)
	{
		foreach (Control control in AllControls(root))
		{
			if (control is not Label label || !string.Equals(label.Text, caption, StringComparison.Ordinal))
			{
				continue;
			}

			NumericUpDown? input = AllControls(control.Parent!).OfType<NumericUpDown>()
				.FirstOrDefault(numeric => numeric.Value == expectedValue);
			if (input is not null)
			{
				return input;
			}
		}

		throw new Xunit.Sdk.XunitException("No numeric editor was found next to the caption '" + caption + "'.");
	}

	private static ShardingPolicyDto NewPolicyDto(Action<ShardingPolicyValuesDto> configure)
	{
		ShardingPolicyValuesDto values = ShardingPolicyValuesDto.FromOptions(new ShardingOptions());
		configure(values);
		return new ShardingPolicyDto
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = DateTime.UtcNow,
			Policy = values,
			Bounds = new ShardingPolicyBoundsDto(),
			SettingsPath = @"C:\ProgramData\RdpAudit\appsettings.json",
			HotReloaded = true,
		};
	}
}
