// File:    src/RdpAudit.Core/Security/SecretProtectionException.cs
// Module:  RdpAudit.Core.Security
// Purpose: Exception raised by ISecretProtector implementations on protect/unprotect failures.
//          The message is curated: it never contains plaintext values, envelope bytes, or stack data.
// Extends: System.Exception
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Security;

/// <summary>Exception raised by <see cref="ISecretProtector"/> implementations on protect/unprotect failures.</summary>
/// <remarks>
/// The exception message is curated and safe to surface in IPC responses; it must NEVER contain
/// plaintext secrets, envelope bytes, key handles, or low-level CSP error data.
/// </remarks>
public sealed class SecretProtectionException : Exception
{
	public SecretProtectionException()
	{
	}

	public SecretProtectionException(string message)
		: base(message)
	{
	}

	public SecretProtectionException(string message, Exception inner)
		: base(message, inner)
	{
	}
}
