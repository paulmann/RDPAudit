// File:    src/RdpAudit.Core/Security/ISecretProtector.cs
// Module:  RdpAudit.Core.Security
// Purpose: Abstraction for protecting / unprotecting configuration secrets at rest. Producers store
//          a protected envelope (JSON object with "$protected" key) inside appsettings.json; the
//          service unprotects the envelope at runtime when a secret is actually needed.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Security;

/// <summary>Scope of the DPAPI / equivalent key material backing a protected envelope.</summary>
/// <remarks>Append-only enum: values must never be reused or reordered.</remarks>
public enum SecretScope
{
	/// <summary>Key material is bound to the local machine — any process on the host can unprotect.</summary>
	LocalMachine = 0,

	/// <summary>Key material is bound to the current user account; not used by the service today.</summary>
	CurrentUser = 1,
}

/// <summary>Abstraction for protecting / unprotecting configuration secrets at rest.</summary>
/// <remarks>
/// Implementations MUST NOT log secret values or include them in exception messages. Failures to
/// unprotect must surface a generic <see cref="SecretProtectionException"/> with no plaintext leak.
/// </remarks>
public interface ISecretProtector
{
	/// <summary>True when this protector can actually protect / unprotect on the current host.</summary>
	bool IsAvailable { get; }

	/// <summary>Wraps a plaintext secret into a protected JSON envelope string.</summary>
	/// <param name="plaintext">The plaintext value to protect. Must not be null.</param>
	/// <param name="scope">Backing key scope. Defaults to <see cref="SecretScope.LocalMachine"/>.</param>
	/// <returns>A JSON document of the form <c>{ "$protected": "...", "scope": "LocalMachine" }</c>.</returns>
	string Protect(string plaintext, SecretScope scope = SecretScope.LocalMachine);

	/// <summary>Recovers the plaintext from a protected envelope. Pass-through for unwrapped values.</summary>
	/// <param name="envelopeOrPlaintext">
	/// Either a protected envelope produced by <see cref="Protect"/> or — for migration / first-run —
	/// a plaintext string. Plaintext is returned unchanged but the caller is responsible for upgrading.
	/// </param>
	string Unprotect(string envelopeOrPlaintext);

	/// <summary>True when the supplied value is a protected envelope (not a plaintext string).</summary>
	bool IsProtectedEnvelope(string? value);
}
