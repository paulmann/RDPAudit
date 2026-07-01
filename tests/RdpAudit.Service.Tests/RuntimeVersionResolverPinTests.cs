// File:    tests/RdpAudit.Service.Tests/RuntimeVersionResolverPinTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Locks the Service runtime version surfaced via IPC ServiceStatus.Version at exactly
//          1.3.5 — the SemVer publish.ps1 emits and the value the Configurator's Service tab
//          contrasts against the installed and distribution binaries. The complementary core
//          gate lives in RdpAuditVersionMetadataTests; this one targets the Service assembly
//          and the resolver path the running service actually uses at runtime. The 1.3.3 release
//          adds the crash-proof OperationLogs subsystem, CrashGuard, resilient workers, the Logs
//          tab / global DEBUG / Overview progress UI, backed by IPC commands 58/59. If the
//          release stream advances, this test must move with it.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Reflection;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Pins the Service runtime version at exactly 1.5.0, blocking both the prior 1.0.0
/// placeholder default and the previous 1.2.x release stream from regressing.</summary>
public class RuntimeVersionResolverPinTests
{
	private const string ExpectedSemVer = "1.5.0";
	private const string ForbiddenLegacy = "1.0.0";
	private const string ForbiddenPrev = "1.2.";

	[Fact]
	public void Resolve_FromServiceAssembly_ReturnsPinnedSemVer()
	{
		Assembly serviceAssembly = typeof(RuntimeVersionResolver).Assembly;
		string version = RuntimeVersionResolver.Resolve(serviceAssembly, processPath: null);
		Assert.Equal(ExpectedSemVer, version);
	}

	[Fact]
	public void Resolve_NeverReportsLegacy100()
	{
		Assembly serviceAssembly = typeof(RuntimeVersionResolver).Assembly;
		string version = RuntimeVersionResolver.Resolve(serviceAssembly, processPath: null);
		Assert.DoesNotContain(ForbiddenLegacy, version, StringComparison.Ordinal);
	}

	[Fact]
	public void Resolve_NeverReportsPreviousRelease12x()
	{
		Assembly serviceAssembly = typeof(RuntimeVersionResolver).Assembly;
		string version = RuntimeVersionResolver.Resolve(serviceAssembly, processPath: null);
		Assert.DoesNotContain(ForbiddenPrev, version, StringComparison.Ordinal);
	}
}
