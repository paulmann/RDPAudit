/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : TestPipeNames.cs
// Project: RdpAudit.Service.Tests
// Purpose: Per-run identity for the REAL named pipes that a handful of integration tests in this
//          project bind. Those tests previously served \\.\pipe\RdpAuditService - the production
//          name - from inside the test host. When the solution is tested in parallel (more than one
//          test project at a time, i.e. `dotnet test RdpAudit.sln` without -m:1) the Configurator
//          test host connected to that pipe while it was up: the two DatabasePage overview tests
//          that require the service to be UNREACHABLE then read a live answer
//          ("Database overview loaded.") instead of their degraded-service status line. Reproduced
//          deterministically on an elevated host (8/8 Configurator runs failed while this project
//          held the production name). A shared, guessed name is therefore not a test detail but an
//          isolation defect: the fix is to give every test that starts a real IPC server its own
//          name, so no other process can reach it by construction - not to relax the assertions.
//          The name is unique per test instance (xunit constructs one instance per test case), which
//          also keeps two pipe tests inside this project from serving the same name.
// Depends: RdpAudit.Core.Ipc.IpcConstants, IpcServerWorker.PipeName (internal test seam)
// Extends: Use TestPipeNames.Unique() for every real pipe a test starts or connects to.

using RdpAudit.Core.Ipc;

namespace RdpAudit.Service.Tests;

/// <summary>Allocates the per-run pipe name used by the real-pipe integration tests.</summary>
internal static class TestPipeNames
{
	/// <summary>Returns a pipe name no other process can know or connect to:
	/// <c>RdpAuditService-&lt;pid&gt;-&lt;guid&gt;</c>, derived from the production name so a log line
	/// still identifies the transport. The <c>pid</c> makes the owner obvious when reading the pipe
	/// namespace, the <c>guid</c> makes the name unpredictable - the Configurator test host (and the
	/// product client) resolve the production name and can therefore never attach to a test server.
	/// The ACL of the test pipe is the production one, unchanged; a non-elevated test host is
	/// unaffected by this helper (its own clients are refused by that ACL either way).</summary>
	internal static string Unique() =>
		IpcConstants.PipeName + "-" + Environment.ProcessId + "-" + Guid.NewGuid().ToString("N");
}
