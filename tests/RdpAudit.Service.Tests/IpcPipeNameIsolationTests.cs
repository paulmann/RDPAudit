/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : IpcPipeNameIsolationTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Guard for the B4 test-isolation fix. The real-pipe integration tests in this project bind
//          a per-run pipe name (TestPipeNames.Unique, i.e. RdpAuditService-<pid>-<guid>), which is
//          what stops a test host from being reachable by the Configurator test project during a
//          parallel `dotnet test RdpAudit.sln` run. These tests pin the two halves of that contract:
//          the PRODUCTION name and its resolution path are unchanged and cannot be redirected (no
//          environment variable, no other construction path), and the TEST name is unpredictable,
//          unique per call and never equal to the production name. Without the second half a future
//          edit could quietly go back to sharing one name; without the first, a "fix" could have
//          weakened production instead of isolating the tests.
// Depends: IpcServerWorker (internal PipeName seam), IpcConstants, xunit
// Extends: Extend the pinned name list here if the IPC transport ever moves to a different pipe.

using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Ipc;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcPipeNameIsolationTests
{
	/// <summary>Environment variables a "configurable pipe name" implementation would most plausibly
	/// read. None of them may influence the name a production-constructed worker serves.</summary>
	private static readonly string[] RedirectAttempts =
	[
		"RDPAUDIT_IPC_PIPE",
		"RDPAUDIT_PIPE_NAME",
		"RDPAUDIT_IPC_PIPE_NAME",
		"RDPAUDIT_SERVICE_PIPE",
	];

	/// <summary>Given the pipe name is part of the service's external contract (the Configurator, the
	/// notifier and the MikroTik bridge all connect to it by name), when the constant is read, then it
	/// still is the shipped name. A rename here would silently break every client, which is exactly
	/// why the B4 fix parameterised the TEST seam instead of the production name.</summary>
	[Fact]
	public void ProductionPipeName_IsPinned()
	{
		Assert.Equal("RdpAuditService", IpcConstants.PipeName);
	}

	/// <summary>Given production always resolves the pipe name from the constant, when a worker is
	/// constructed the way the composition root constructs it (two arguments, no pipe-name argument),
	/// then it serves the production name - even with every plausible override variable set in the
	/// process environment. This is the counterfactual for "the production path is untouched": the
	/// only way to change the name is the internal seam, which no production code path sets.</summary>
	[Fact]
	public void Worker_ConstructedLikeProduction_AlwaysServesTheProductionName()
	{
		Dictionary<string, string?> previous = new(StringComparer.Ordinal);
		try
		{
			foreach (string name in RedirectAttempts)
			{
				previous[name] = Environment.GetEnvironmentVariable(name);
				Environment.SetEnvironmentVariable(name, "RdpAuditService-hijacked");
			}

			IpcServerWorker worker = new(NullServiceProvider.Instance, NullLogger<IpcServerWorker>.Instance);
			Assert.Equal(IpcConstants.PipeName, worker.PipeName);
		}
		finally
		{
			foreach (KeyValuePair<string, string?> entry in previous)
			{
				Environment.SetEnvironmentVariable(entry.Key, entry.Value);
			}
		}
	}

	/// <summary>Given the test seam exists only so several test hosts can run at once, when the test
	/// name is allocated, then it is derived from the production name (so a log line still identifies
	/// the transport), carries the owning PID (so the pipe namespace names its owner) and is unique
	/// per call - no other process can guess it, and two tests can never collide on it.</summary>
	[Fact]
	public void TestPipeName_IsPerRunUnique_AndNeverTheProductionName()
	{
		HashSet<string> names = new(StringComparer.Ordinal);
		for (int index = 0; index < 64; index++)
		{
			string name = TestPipeNames.Unique();
			Assert.NotEqual(IpcConstants.PipeName, name);
			Assert.StartsWith(IpcConstants.PipeName + "-", name, StringComparison.Ordinal);
			Assert.Contains("-" + Environment.ProcessId + "-", name, StringComparison.Ordinal);
			Assert.True(names.Add(name), "TestPipeNames.Unique() returned a duplicate: " + name);
		}
	}

	/// <summary>Given the seam is an object initialiser on an internal property, when a test sets it,
	/// then ONLY that instance is affected: a worker constructed without it keeps serving the
	/// production name, so the isolation cannot leak between instances.</summary>
	[Fact]
	public void TestPipeName_IsPerInstance_AndCannotLeakToTheNextWorker()
	{
		IpcServerWorker redirected = new(NullServiceProvider.Instance, NullLogger<IpcServerWorker>.Instance)
		{
			PipeName = "RdpAuditService-test-only",
		};
		IpcServerWorker plain = new(NullServiceProvider.Instance, NullLogger<IpcServerWorker>.Instance);

		Assert.Equal("RdpAuditService-test-only", redirected.PipeName);
		Assert.Equal(IpcConstants.PipeName, plain.PipeName);
	}

	private sealed class NullServiceProvider : IServiceProvider
	{
		public static readonly NullServiceProvider Instance = new();

		public object? GetService(Type serviceType) => null;
	}
}
