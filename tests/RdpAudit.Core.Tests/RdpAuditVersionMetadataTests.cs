// File:    tests/RdpAudit.Core.Tests/RdpAuditVersionMetadataTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the current release version to exactly 1.6.1 across every assembly metadata
//          surface that publish.ps1 and the running Service surface to the operator: the
//          AssemblyInformationalVersion (the SemVer driving the Service tab "Runtime version"
//          line), AssemblyVersion / FileVersion (the four-part identifiers embedded in the
//          PE file and surfaced by FileVersionInfo), plus a hard guard against the previous
//          1.0.0 placeholder default and the 1.5.x stream leaking back into the build.
//          If the release stream advances, this test must move with it - never weaken the
//          assertion to "starts with".
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Reflection;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Locks the released version metadata at exactly 1.6.1 across the Core assembly,
/// blocking the prior 1.0.0 placeholder default and the 1.5.x stream from regressing.</summary>
public class RdpAuditVersionMetadataTests
{
	private const string ExpectedSemVer    = "1.6.1";
	private const string ExpectedFourPart  = "1.6.1.0";
	private const string ForbiddenLegacy   = "1.0.0";
	private const string ForbiddenPrev     = "1.5.";

	[Fact]
	public void Core_AssemblyInformationalVersion_IsPinnedTo110()
	{
		Assembly core = typeof(ServiceLayout).Assembly;
		string? informational = core
			.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		Assert.False(string.IsNullOrWhiteSpace(informational));
		string trimmed = TrimBuildMetadata(informational!);
		Assert.Equal(ExpectedSemVer, trimmed);
	}

	[Fact]
	public void Core_AssemblyVersion_IsPinnedTo1100()
	{
		Assembly core = typeof(ServiceLayout).Assembly;
		Version? version = core.GetName().Version;
		Assert.NotNull(version);
		Assert.Equal(ExpectedFourPart, version!.ToString());
	}

	[Fact]
	public void Core_AssemblyFileVersion_IsPinnedTo1100()
	{
		Assembly core = typeof(ServiceLayout).Assembly;
		string? fileVersion = core
			.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version;
		Assert.False(string.IsNullOrWhiteSpace(fileVersion));
		Assert.Equal(ExpectedFourPart, fileVersion);
	}

	[Fact]
	public void Core_VersionMetadata_DoesNotReportLegacy120()
	{
		Assembly core = typeof(ServiceLayout).Assembly;
		string? informational = core
			.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		string? fileVersion = core
			.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version;
		string? assemblyVersion = core.GetName().Version?.ToString();

		Assert.DoesNotContain(ForbiddenLegacy, informational ?? string.Empty, StringComparison.Ordinal);
		Assert.DoesNotContain(ForbiddenLegacy, fileVersion ?? string.Empty, StringComparison.Ordinal);
		Assert.DoesNotContain(ForbiddenLegacy, assemblyVersion ?? string.Empty, StringComparison.Ordinal);
		// Block the previous release stream (1.5.x) from regressing into the binary metadata.
		Assert.DoesNotContain(ForbiddenPrev, informational ?? string.Empty, StringComparison.Ordinal);
		Assert.DoesNotContain(ForbiddenPrev, fileVersion ?? string.Empty, StringComparison.Ordinal);
		Assert.DoesNotContain(ForbiddenPrev, assemblyVersion ?? string.Empty, StringComparison.Ordinal);
	}

	private static string TrimBuildMetadata(string informational)
	{
		int plus = informational.IndexOf('+', StringComparison.Ordinal);
		return plus > 0 ? informational[..plus] : informational;
	}
}
