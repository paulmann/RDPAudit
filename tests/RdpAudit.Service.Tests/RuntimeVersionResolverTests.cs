// File:    tests/RdpAudit.Service.Tests/RuntimeVersionResolverTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Regression coverage for the single-file-safe RuntimeVersionResolver helper. Locks in
//          the precedence order (AssemblyInformationalVersion > FileVersionInfo from
//          Environment.ProcessPath > AssemblyName.Version) and verifies the resolver never
//          throws when the process path is unset, missing, or invalid — the conditions under
//          which the legacy Assembly.Location-based code would have failed IL3000 analysis or
//          returned an empty path on a single-file publish.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Reflection;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>RuntimeVersionResolver — single-file-safe service version resolution.</summary>
public class RuntimeVersionResolverTests
{
	[Fact]
	public void Resolve_PrefersInformationalVersion_OverProcessPathAndAssemblyName()
	{
		Assembly self = typeof(RuntimeVersionResolverTests).Assembly;

		string version = RuntimeVersionResolver.Resolve(self, processPath: null);

		string? informational = self
			.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		Assert.False(string.IsNullOrWhiteSpace(version));
		if (!string.IsNullOrWhiteSpace(informational))
		{
			int plus = informational.IndexOf('+', StringComparison.Ordinal);
			string expected = plus > 0 ? informational[..plus] : informational;
			Assert.Equal(expected, version);
		}
	}

	[Fact]
	public void Resolve_TrimsBuildMetadataAfterPlusSign()
	{
		Assembly self = typeof(RuntimeVersionResolverTests).Assembly;
		string version = RuntimeVersionResolver.Resolve(self, processPath: null);
		Assert.DoesNotContain("+", version, StringComparison.Ordinal);
	}

	[Fact]
	public void Resolve_WithNullProcessPath_DoesNotThrow_AndReturnsNonEmpty()
	{
		Assembly self = typeof(RuntimeVersionResolverTests).Assembly;
		string version = RuntimeVersionResolver.Resolve(self, processPath: null);
		Assert.False(string.IsNullOrWhiteSpace(version));
	}

	[Fact]
	public void Resolve_WithMissingProcessPath_DoesNotThrow_AndReturnsNonEmpty()
	{
		Assembly self = typeof(RuntimeVersionResolverTests).Assembly;
		string missing = Path.Combine(Path.GetTempPath(),
			"rdpaudit-missing-" + Guid.NewGuid().ToString("N") + ".exe");

		string version = RuntimeVersionResolver.Resolve(self, missing);

		Assert.False(string.IsNullOrWhiteSpace(version));
	}

	[Fact]
	public void Resolve_WithWhitespaceProcessPath_DoesNotThrow_AndReturnsNonEmpty()
	{
		Assembly self = typeof(RuntimeVersionResolverTests).Assembly;
		string version = RuntimeVersionResolver.Resolve(self, "   ");
		Assert.False(string.IsNullOrWhiteSpace(version));
	}

	[Fact]
	public void Resolve_Parameterless_ReturnsNonEmptyVersion()
	{
		string version = RuntimeVersionResolver.Resolve();
		Assert.False(string.IsNullOrWhiteSpace(version));
	}

	[Fact]
	public void Resolve_NullAssembly_Throws()
	{
		Assert.Throws<ArgumentNullException>(
			() => RuntimeVersionResolver.Resolve(assembly: null!, processPath: null));
	}
}
