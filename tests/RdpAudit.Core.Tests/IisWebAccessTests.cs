// File:    tests/RdpAudit.Core.Tests/IisWebAccessTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the IIS-leg contract for the Configurator Web Access tab: the DISM state
//          parser is locale-stable, the Install IIS command sets are deterministic and
//          complete, and the status probe turns platform answers into a fail-closed
//          snapshot without inventing facts when a source could not answer. All tests use
//          a stub platform probe and assert the actual interactions (call counts and
//          arguments) rather than merely exercising the path.
//
// Depends: IisStatusProbe, IisInstallCommandSet, DismFeatureOutputParser, xUnit
// Extends: Add a case here when the probe learns a new question.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using RdpAudit.Core.WebUi;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Deterministic stub behind <see cref="IIisPlatformProbe"/> that also records interactions.</summary>
internal sealed class FakeIisPlatformProbe : IIisPlatformProbe
{
	public bool? InstalledAnswer { get; set; }
	public bool? ServiceAnswer { get; set; }
	public List<string> ServiceProbeNames { get; } = new();
	public int InstalledCalls { get; private set; }

	public string Provider => "Fake";

	public Task<bool?> IsIisInstalledAsync(CancellationToken cancellationToken)
	{
		InstalledCalls++;
		return Task.FromResult(InstalledAnswer);
	}

	public Task<bool?> ServiceExistsAsync(string serviceName, CancellationToken cancellationToken)
	{
		ServiceProbeNames.Add(serviceName);
		return Task.FromResult(ServiceAnswer);
	}
}

/// <summary>Locale-stable parsing of the read-only DISM /Get-FeatureInfo state line.</summary>
public sealed class DismFeatureOutputParserTests
{
	[Fact]
	public void Parse_EnabledState_ReturnsTrue()
	{
		bool? state = DismFeatureOutputParser.TryGetState(
			"Feature Information:\r\nState : Enabled\r\n");

		Assert.True(state);
	}

	[Fact]
	public void Parse_EnablePendingState_ReturnsTrue()
	{
		bool? state = DismFeatureOutputParser.TryGetState(
			"State : Enable Pending\r\nRestart Required : Possible\r\n");

		Assert.True(state);
	}

	[Fact]
	public void Parse_DisabledState_ReturnsFalse()
	{
		bool? state = DismFeatureOutputParser.TryGetState("State : Disabled");

		Assert.False(state);
	}

	[Fact]
	public void Parse_WithoutStateLine_ReturnsNull()
	{
		bool? state = DismFeatureOutputParser.TryGetState(
			"Feature Name : IIS-WebServerRole\r\nDisplay Name : Web Server (IIS)");

		Assert.Null(state);
	}

	[Fact]
	public void Parse_EmptyOrNull_ReturnsNull()
	{
		Assert.Null(DismFeatureOutputParser.TryGetState(string.Empty));
		Assert.Null(DismFeatureOutputParser.TryGetState(null));
	}
}

/// <summary>Deterministic command sets shown to the operator by the Install IIS workflow.</summary>
public sealed class IisInstallCommandSetTests
{
	[Fact]
	public void StaticFeaturesAndDismFeatures_DescribeTheSameCapability()
	{
		// The Windows feature ids (Web-*) and the DISM ids (IIS-*) name the same capability through two
		// vocabularies. The DISM catalog carries exactly one extra entry: the IIS-WebServerRole parent.
		// The ServerManager/Install-WindowsFeature builder that used this list was removed: it only ran
		// through Windows PowerShell 5.1 compatibility and the product always installs through DISM.
		Assert.Equal(IisFeatureCatalog.StaticFeatures.Count + 1, IisFeatureCatalog.DismFeatures.Count);
		Assert.Contains("IIS-WebServerRole", IisFeatureCatalog.DismFeatures);
		Assert.Contains("Web-Server", IisFeatureCatalog.StaticFeatures);
	}

	[Fact]
	public void DismArguments_ContainAllFeaturesAndNoRestart()
	{
		IReadOnlyList<string> args = IisInstallCommandSet.BuildDismArguments();

		Assert.Contains("/Online", args);
		Assert.Contains("/Enable-Feature", args);
		foreach (string feature in IisFeatureCatalog.DismFeatures)
		{
			Assert.Contains("/FeatureName:" + feature, args);
		}

		Assert.Contains("/NoRestart", args);
		Assert.DoesNotContain("/Restart", args);
	}

	[Fact]
	public void DismScriptIsGone_NoWindowsPowerShellOnlyBuilderRemains()
	{
		// BuildServerManagerScript/BuildDismScript were operator-facing STRING builders for the
		// ServerManager (Windows PowerShell 5.1-only) route. Removed so no WinPS-only command shape can
		// be displayed or executed; the executed route is the DISM argument vector above.
		Assert.Null(typeof(IisInstallCommandSet).GetMethod("BuildServerManagerScript"));
		Assert.Null(typeof(IisInstallCommandSet).GetMethod("BuildDismScript"));
	}

	[Fact]
	public void DismArgumentVectors_CoverEveryFeatureWithoutRestart()
	{
		// Two capabilities, two DISM runs: IisInstallService enables the static set and the management
		// tools as separate, individually reported plan rows, so the no-argument builder is the static
		// step only. What must never drift is the UNION - every feature the installer enables is carried
		// by exactly one of the two vectors, and neither vector asks for a restart.
		IReadOnlyList<string> staticArgs = IisInstallCommandSet.BuildDismArguments();
		IReadOnlyList<string> toolsArgs =
			IisInstallCommandSet.BuildDismArguments(IisFeatureCatalog.DismManagementFeatures);

		foreach (IReadOnlyList<string> args in new[] { staticArgs, toolsArgs })
		{
			Assert.Contains("/Online", args);
			Assert.Equal("/Enable-Feature", args[1]);
			Assert.Contains("/NoRestart", args);
			Assert.DoesNotContain("/Restart", args);
		}

		foreach (string feature in IisFeatureCatalog.DismFeatures)
		{
			Assert.Contains("/FeatureName:" + feature, staticArgs);
		}

		foreach (string feature in IisFeatureCatalog.DismManagementFeatures)
		{
			Assert.Contains("/FeatureName:" + feature, toolsArgs);
			Assert.DoesNotContain("/FeatureName:" + feature, staticArgs);
		}

		Assert.Equal(
			IisFeatureCatalog.AllDismFeatureNames.Count,
			IisFeatureCatalog.DismFeatures.Count + IisFeatureCatalog.DismManagementFeatures.Count);
	}

	[Fact]
	public void AllDismFeatureNames_KeepsTheStaticSetFirstAndAppendsTheManagementTools()
	{
		IReadOnlyList<string> all = IisFeatureCatalog.AllDismFeatureNames;

		Assert.Equal(IisFeatureCatalog.DismFeatures.Count + IisFeatureCatalog.DismManagementFeatures.Count, all.Count);
		for (int i = 0; i < IisFeatureCatalog.DismFeatures.Count; i++)
		{
			Assert.Equal(IisFeatureCatalog.DismFeatures[i], all[i]);
		}

		Assert.Contains("IIS-WebServerManagementTools", all);
		Assert.Contains("IIS-ManagementScriptingTools", all);
	}

	[Fact]
	public void BuildDismArguments_ForASubset_EnablesExactlyThatSubset()
	{
		IReadOnlyList<string> args = IisInstallCommandSet.BuildDismArguments(IisFeatureCatalog.DismManagementFeatures);

		Assert.Equal(new[] { "/Online", "/Enable-Feature" }, args.Take(2));
		foreach (string feature in IisFeatureCatalog.DismManagementFeatures)
		{
			Assert.Contains("/FeatureName:" + feature, args);
		}

		// The static-file features must NOT leak into a management-tools-only run.
		foreach (string feature in IisFeatureCatalog.DismFeatures)
		{
			Assert.DoesNotContain("/FeatureName:" + feature, args);
		}

		Assert.Contains("/NoRestart", args);
		Assert.DoesNotContain("/Restart", args);
	}

	[Fact]
	public void BuildDismArguments_WithoutFeatures_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => IisInstallCommandSet.BuildDismArguments(null!));
		Assert.Throws<ArgumentException>(() => IisInstallCommandSet.BuildDismArguments(Array.Empty<string>()));
	}

	[Fact]
	public void HostingBundleInstallArguments_AreUnattendedAndPinnedToTheExactPackage()
	{
		IReadOnlyList<string> args = HostingBundleCommandSet.BuildInstallArguments();

		Assert.Equal("install", args[0]);
		Assert.Contains("--id", args);
		Assert.Contains(HostingBundlePackage.WingetPackageId, args);
		Assert.Contains("--exact", args);
		Assert.Contains("--silent", args);
		Assert.Contains("--accept-source-agreements", args);
		Assert.Contains("--accept-package-agreements", args);
	}

	[Fact]
	public void AspNetCoreModuleProbe_ReportsInstalledOnlyWhenBothBinariesExist()
	{
		HashSet<string> present = new(StringComparer.OrdinalIgnoreCase)
		{
			Path.Combine("C:\\inetsrv", HostingBundlePackage.ModuleFileName),
			Path.Combine("C:\\inetsrv", HostingBundlePackage.InProcessModuleFileName),
		};
		AspNetCoreModuleProbe probe = new("C:\\inetsrv", present.Contains);

		Assert.True(probe.IsModuleInstalled());
		Assert.Empty(probe.MissingFileNames());
	}

	[Fact]
	public void AspNetCoreModuleProbe_NamesTheMissingBinaryInsteadOfJustFailing()
	{
		// Only the out-of-process module is on disk: in-process hosting would still not work.
		string only = Path.Combine("C:\\inetsrv", HostingBundlePackage.ModuleFileName);
		AspNetCoreModuleProbe probe = new("C:\\inetsrv", path => string.Equals(path, only, StringComparison.OrdinalIgnoreCase));

		Assert.False(probe.IsModuleInstalled());
		Assert.Equal(new[] { HostingBundlePackage.InProcessModuleFileName }, probe.MissingFileNames());
	}

	[Fact]
	public void AspNetCoreModuleProbe_UnreadableLocation_IsNotReportedAsInstalled()
	{
		AspNetCoreModuleProbe probe = new("C:\\inetsrv", _ => throw new UnauthorizedAccessException("denied"));

		Assert.False(probe.IsModuleInstalled());
		Assert.Equal(2, probe.MissingFileNames().Count);
	}
}

/// <summary>Behaviour of the fail-closed Web Access status probe.</summary>
public sealed class IisStatusProbeTests
{
	[Fact]
	public async Task Probe_AllFactsKnown_SnapshotMatchesAndNoFailure()
	{
		FakeIisPlatformProbe platform = new()
		{
			InstalledAnswer = true,
			ServiceAnswer = true,
		};
		IisStatusProbe probe = new(platform, Path.GetTempPath());

		IisStatusSnapshot snapshot = await probe.ProbeAsync();

		Assert.True(snapshot.IisInstalled);
		Assert.True(snapshot.W3SvcPresent);
		Assert.True(snapshot.IisStateDetermined);
		Assert.True(snapshot.W3SvcStateDetermined);
		Assert.True(snapshot.CanDeclare);
		Assert.Null(snapshot.FailureReason);
		Assert.Contains("installed", snapshot.Summary, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public async Task Probe_NotInstalled_SnapshotReportsBothFalse()
	{
		FakeIisPlatformProbe platform = new()
		{
			InstalledAnswer = false,
			ServiceAnswer = false,
		};
		IisStatusProbe probe = new(platform, Path.GetTempPath());

		IisStatusSnapshot snapshot = await probe.ProbeAsync();

		Assert.False(snapshot.IisInstalled);
		Assert.False(snapshot.W3SvcPresent);
		Assert.True(snapshot.IisStateDetermined);
		Assert.True(snapshot.W3SvcStateDetermined);
		Assert.Null(snapshot.FailureReason);
		Assert.True(snapshot.CanDeclare);
	}

	[Fact]
	public async Task Probe_WhenSourcesCannotAnswer_FailsClosed()
	{
		FakeIisPlatformProbe platform = new()
		{
			InstalledAnswer = null,
			ServiceAnswer = null,
		};
		IisStatusProbe probe = new(platform, Path.GetTempPath());

		IisStatusSnapshot snapshot = await probe.ProbeAsync();

		Assert.False(snapshot.IisInstalled);
		Assert.False(snapshot.W3SvcPresent);
		Assert.False(snapshot.IisStateDetermined);
		Assert.False(snapshot.W3SvcStateDetermined);
		Assert.False(snapshot.CanDeclare);
		Assert.NotNull(snapshot.FailureReason);
	}

	[Fact]
	public async Task Probe_OnlyServiceAnswer_FailureNamesTheUnknownChannel()
	{
		FakeIisPlatformProbe platform = new()
		{
			InstalledAnswer = null,
			ServiceAnswer = true,
		};
		IisStatusProbe probe = new(platform, Path.GetTempPath());

		IisStatusSnapshot snapshot = await probe.ProbeAsync();

		Assert.True(snapshot.W3SvcPresent);
		Assert.False(snapshot.IisInstalled);
		Assert.Contains("installation state", snapshot.FailureReason ?? string.Empty, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public async Task Probe_AsksPlatformExactlyOnceForEachChannel()
	{
		FakeIisPlatformProbe platform = new()
		{
			InstalledAnswer = true,
			ServiceAnswer = true,
		};
		IisStatusProbe probe = new(platform, Path.GetTempPath());

		await probe.ProbeAsync();

		Assert.Equal(1, platform.InstalledCalls);
		Assert.Equal(new[] { WindowsIisPlatformProbe.W3SvcServiceName }, platform.ServiceProbeNames);
	}

	[Fact]
	public async Task Probe_PublishedWebUiPresent_MirrorsTheTargetFolder()
	{
		string root = Path.Combine(Path.GetTempPath(), "rdpaudit-iis-" + Guid.NewGuid().ToString("N"));
		string webUi = Path.Combine(root, "WebUI");
		string wwwroot = Path.Combine(webUi, "wwwroot");
		Directory.CreateDirectory(wwwroot);
		try
		{
			FakeIisPlatformProbe platform = new() { InstalledAnswer = true, ServiceAnswer = true };
			IisStatusProbe probe = new(platform, webUi);

			IisStatusSnapshot empty = await probe.ProbeAsync();
			Assert.False(empty.PublishedWebUiPresent);

			File.WriteAllText(Path.Combine(wwwroot, "index.html"), "<html>x</html>");
			IisStatusSnapshot published = await probe.ProbeAsync();
			Assert.True(published.PublishedWebUiPresent);
		}
		finally
		{
			try
			{
				Directory.Delete(root, recursive: true);
			}
			catch (IOException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
		}
	}

	[Fact]
	public void Constructor_RequiresPlatformAndDirectory()
	{
		Assert.Throws<ArgumentNullException>(() => new IisStatusProbe(null!, Path.GetTempPath()));
		Assert.Throws<ArgumentException>(
			() => new IisStatusProbe(new FakeIisPlatformProbe(), "  "));
	}
}
