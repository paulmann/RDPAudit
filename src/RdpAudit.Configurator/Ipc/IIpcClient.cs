// File:    src/RdpAudit.Configurator/Ipc/IIpcClient.cs
// Module:  RdpAudit.Configurator.Ipc
// Purpose: The narrow IPC seam the Database tab (and its subject-purge dialog) depends on (B17).
//          Before this type existed both classes took the concrete IpcClient, so the only branch a test
//          could reach was "the named pipe is not there": every success path - overview, retention policy
//          load and save, the dry-run preview, snapshot create/list/verify, the shard Collect cycle, the
//          ledger page and the gate refusals - was unreachable without a live service, and the table of
//          contents of the Run called that out as verification debt.
//          The interface deliberately exposes ONE member: the single overload those two classes actually
//          call. It is not a general IPC abstraction and must not grow into one - a page that needs
//          `SendAsync`, `SendRawAsync` or `PingAsync` should inject IpcClient, because widening this seam
//          re-creates exactly the untestable coupling it exists to remove.
//          IpcClient implements it unchanged, so production composition (MainForm constructs IpcClient and
//          passes it to DatabasePage) is untouched.
// Depends: IpcCommand, IpcCallResult
// Extends: Add a member here only when a class already injected with IIpcClient actually needs it.

using RdpAudit.Core.Ipc;

namespace RdpAudit.Configurator.Ipc;

/// <summary>The IPC capability the Database tab and the subject-purge dialog use: one structured
/// request/response round trip.</summary>
public interface IIpcClient
{
	/// <summary>Sends a command and returns the structured outcome, including the deserialized payload when
	/// the service answered and the classified failure when it did not.</summary>
	/// <typeparam name="T">Expected payload type.</typeparam>
	/// <param name="command">Command to dispatch.</param>
	/// <param name="payload">Command payload, or null for commands that take none.</param>
	/// <param name="ct">Cancellation token.</param>
	Task<IpcCallResult<T>> SendDetailedAsync<T>(IpcCommand command, object? payload = null, CancellationToken ct = default);
}
