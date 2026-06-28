// File:    src/RdpAudit.Core/Ipc/IpcException.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: Exception type thrown by IPC client / server protocol failures.
// Extends: System.Exception
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Ipc;

/// <summary>Exception type thrown by IPC protocol failures.</summary>
public sealed class IpcException : Exception
{
	public IpcException(string message) : base(message)
	{
	}

	public IpcException(string message, Exception inner) : base(message, inner)
	{
	}
}
