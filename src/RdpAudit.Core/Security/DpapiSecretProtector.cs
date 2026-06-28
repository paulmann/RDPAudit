// File:    src/RdpAudit.Core/Security/DpapiSecretProtector.cs
// Module:  RdpAudit.Core.Security
// Purpose: Windows DPAPI-backed implementation of ISecretProtector. Uses LocalMachine scope by
//          default so the SYSTEM service account and an administrative configurator can both
//          read the same envelope. Plaintext never leaves managed memory in cleartext form
//          beyond the immediate call site.
// Extends: RdpAudit.Core.Security.ISecretProtector
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace RdpAudit.Core.Security;

/// <summary>Windows DPAPI-backed implementation of <see cref="ISecretProtector"/>.</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
	private static readonly byte[] s_entropy = Encoding.UTF8.GetBytes("RdpAudit/v1");

	/// <inheritdoc />
	public bool IsAvailable => OperatingSystem.IsWindows();

	/// <inheritdoc />
	public bool IsProtectedEnvelope(string? value) => ProtectedEnvelope.IsEnvelope(value);

	/// <inheritdoc />
	public string Protect(string plaintext, SecretScope scope = SecretScope.LocalMachine)
	{
		ArgumentNullException.ThrowIfNull(plaintext);
		if (!OperatingSystem.IsWindows())
		{
			throw new SecretProtectionException("DPAPI protection is only available on Windows.");
		}

		try
		{
			byte[] data = Encoding.UTF8.GetBytes(plaintext);
			DataProtectionScope dpScope = scope == SecretScope.CurrentUser
				? DataProtectionScope.CurrentUser
				: DataProtectionScope.LocalMachine;
			byte[] cipher = ProtectedData.Protect(data, s_entropy, dpScope);
			Array.Clear(data, 0, data.Length);
			return ProtectedEnvelope.Create(cipher, scope);
		}
		catch (CryptographicException ex)
		{
			throw new SecretProtectionException("Failed to protect secret via DPAPI.", ex);
		}
	}

	/// <inheritdoc />
	public string Unprotect(string envelopeOrPlaintext)
	{
		ArgumentNullException.ThrowIfNull(envelopeOrPlaintext);
		if (!ProtectedEnvelope.IsEnvelope(envelopeOrPlaintext))
		{
			// Caller passed in a non-envelope plaintext value (migration path); return unchanged.
			return envelopeOrPlaintext;
		}

		if (!OperatingSystem.IsWindows())
		{
			throw new SecretProtectionException("DPAPI unprotection is only available on Windows.");
		}

		(byte[] cipher, SecretScope scope) = ProtectedEnvelope.Parse(envelopeOrPlaintext);
		try
		{
			DataProtectionScope dpScope = scope == SecretScope.CurrentUser
				? DataProtectionScope.CurrentUser
				: DataProtectionScope.LocalMachine;
			byte[] data = ProtectedData.Unprotect(cipher, s_entropy, dpScope);
			try
			{
				return Encoding.UTF8.GetString(data);
			}
			finally
			{
				Array.Clear(data, 0, data.Length);
			}
		}
		catch (CryptographicException ex)
		{
			throw new SecretProtectionException("Failed to unprotect secret via DPAPI.", ex);
		}
	}
}
