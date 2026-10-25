// File:    tests/RdpAudit.Core.Tests/RdpAuditVersionMetadataTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Proves that every metadata surface of the Core assembly reports the version the build
//          actually declares, and that the previous release streams cannot regress into it.
//          The expected value is read from Directory.Build.props at run time instead of being
//          copied into this file: a hardcoded number has to be edited on every legitimate release
//          bump, and the stream advanced from 2.0.2 to 2.0.3 leaving this gate (and three others)
//          red while the binaries themselves were correct. What used to be "exactly 2.0.2" is now
//          "exactly what the single source says, on every surface" - stronger, because a divergence
//          between AssemblyVersion, FileVersion and AssemblyInformationalVersion is caught as well.
//          publish.ps1 resolves the same VersionPrefix element, so the published stream and this
//          gate cannot drift apart.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Xml.Linq;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Locks the Core assembly version metadata to the declared VersionPrefix and blocks the
/// prior 1.0.0 placeholder default and the 1.5.x / 1.6.x streams from regressing.</summary>
public class RdpAuditVersionMetadataTests
{
	private const string ForbiddenLegacy = "1.0.0";
	private const string ForbiddenPrev   = "1.6.";

	[Fact]
	public void Core_AssemblyInformationalVersion_MatchesDeclaredVersionPrefix()
	{
		string declared = DeclaredVersionPrefix();
		Assembly core = typeof(ServiceLayout).Assembly;
		string? informational = core
			.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		Assert.False(string.IsNullOrWhiteSpace(informational));
		Assert.Equal(declared, TrimBuildMetadata(informational!));
	}

	[Fact]
	public void Core_AssemblyVersion_MatchesDeclaredVersionPrefix()
	{
		string declared = DeclaredVersionPrefix();
		Assembly core = typeof(ServiceLayout).Assembly;
		Version? version = core.GetName().Version;
		Assert.NotNull(version);
		Assert.Equal(declared + ".0", version!.ToString());
	}

	[Fact]
	public void Core_AssemblyFileVersion_MatchesDeclaredVersionPrefix()
	{
		string declared = DeclaredVersionPrefix();
		Assembly core = typeof(ServiceLayout).Assembly;
		string? fileVersion = core
			.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version;
		Assert.False(string.IsNullOrWhiteSpace(fileVersion));
		Assert.Equal(declared + ".0", fileVersion);
	}

	/// <summary>The three surfaces must agree even if Directory.Build.props itself is edited
	/// inconsistently: the Service tab, the PE version block and the installer all read a different
	/// one of them, so a split shows the operator two versions of one binary.</summary>
	[Fact]
	public void Core_VersionSurfaces_AgreeWithEachOther()
	{
		Assembly core = typeof(ServiceLayout).Assembly;
		string informational = TrimBuildMetadata(
			core.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion!);
		string fileVersion = core.GetCustomAttribute<AssemblyFileVersionAttribute>()!.Version!;
		string assemblyVersion = core.GetName().Version!.ToString();

		Assert.Equal(informational + ".0", fileVersion);
		Assert.Equal(fileVersion, assemblyVersion);
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

	/// <summary>Reads VersionPrefix from Directory.Build.props at the repository root - the single
	/// version surface the build, publish.ps1 and this gate all consult.</summary>
	private static string DeclaredVersionPrefix()
	{
		FileInfo? props = FindUpwards("Directory.Build.props");
		Assert.True(
			props is not null,
			"Directory.Build.props was not found above " + AppContext.BaseDirectory + ".");
		XElement? element = XDocument.Load(props!.FullName).Descendants("VersionPrefix").FirstOrDefault();
		Assert.True(element is not null, "Directory.Build.props declares no VersionPrefix element.");
		string value = element!.Value.Trim();
		Assert.False(string.IsNullOrWhiteSpace(value), "VersionPrefix is empty in " + props.FullName + ".");
		return value;
	}

	private static FileInfo? FindUpwards(string fileName)
	{
		DirectoryInfo? directory = new(AppContext.BaseDirectory);
		while (directory is not null)
		{
			FileInfo candidate = new(Path.Combine(directory.FullName, fileName));
			if (candidate.Exists)
			{
				return candidate;
			}

			directory = directory.Parent;
		}

		return null;
	}

	private static string TrimBuildMetadata(string informational)
	{
		int plus = informational.IndexOf('+', StringComparison.Ordinal);
		return plus > 0 ? informational[..plus] : informational;
	}
}
