// File:    tests/RdpAudit.Service.Tests/RuntimeVersionResolverPinTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Locks the Service runtime version surfaced via IPC ServiceStatus.Version to the version
//          Directory.Build.props declares - the SemVer publish.ps1 emits and the value the
//          Configurator's Service tab contrasts against the installed and distribution binaries.
//          The expected value is read from the single source instead of being copied here, so a
//          legitimate release bump does not redden this gate while the binaries are correct (that
//          is exactly what the 2.0.2 -> 2.0.3 bump did). The forbidden-stream guards are unchanged.
//          The complementary Core gate lives in RdpAuditVersionMetadataTests.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Xml.Linq;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Pins the Service runtime version to the declared VersionPrefix, blocking both the prior
/// 1.0.0 placeholder default and the previous 1.6.x/1.5.x release streams from regressing.</summary>
public class RuntimeVersionResolverPinTests
{
	private const string ForbiddenLegacy = "1.0.0";
	private const string ForbiddenPrev   = "1.6.3";

	[Fact]
	public void Resolve_FromServiceAssembly_ReturnsDeclaredVersion()
	{
		string declared = DeclaredVersionPrefix();
		Assembly serviceAssembly = typeof(RuntimeVersionResolver).Assembly;
		string version = RuntimeVersionResolver.Resolve(serviceAssembly, processPath: null);
		Assert.Equal(declared, version);
	}

	[Fact]
	public void Resolve_NeverReportsLegacy100()
	{
		Assembly serviceAssembly = typeof(RuntimeVersionResolver).Assembly;
		string version = RuntimeVersionResolver.Resolve(serviceAssembly, processPath: null);
		Assert.DoesNotContain(ForbiddenLegacy, version, StringComparison.Ordinal);
	}

	[Fact]
	public void Resolve_NeverReportsPreviousRelease163()
	{
		Assembly serviceAssembly = typeof(RuntimeVersionResolver).Assembly;
		string version = RuntimeVersionResolver.Resolve(serviceAssembly, processPath: null);
		Assert.DoesNotContain(ForbiddenPrev, version, StringComparison.Ordinal);
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
}
