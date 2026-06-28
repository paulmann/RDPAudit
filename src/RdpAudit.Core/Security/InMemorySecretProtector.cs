// File:    src/RdpAudit.Core/Security/InMemorySecretProtector.cs
// Module:  RdpAudit.Core.Security
// Purpose: Deterministic, non-production ISecretProtector used for unit tests and non-Windows CI.
//          Wraps the plaintext in the protected-envelope JSON format but stores it XOR'd with a
//          fixed key so round-tripping is testable without DPAPI / OS dependencies.
// Extends: RdpAudit.Core.Security.ISecretProtector
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text;

namespace RdpAudit.Core.Security;

/// <summary>Deterministic non-production protector used for unit tests / non-Windows CI environments.</summary>
/// <remarks>
/// This implementation deliberately offers no real confidentiality — its only purpose is to exercise
/// the envelope / round-trip contract on hosts where DPAPI is unavailable. It must NEVER be wired
/// into the Service host's DI graph in production.
/// </remarks>
public sealed class InMemorySecretProtector : ISecretProtector
{
	private static readonly byte[] s_obfuscationKey = Encoding.UTF8.GetBytes("RdpAudit.Tests/InMemory/v1");

	/// <inheritdoc />
	public bool IsAvailable => true;

	/// <inheritdoc />
	public bool IsProtectedEnvelope(string? value) => ProtectedEnvelope.IsEnvelope(value);

	/// <inheritdoc />
	public string Protect(string plaintext, SecretScope scope = SecretScope.LocalMachine)
	{
		ArgumentNullException.ThrowIfNull(plaintext);
		byte[] data = Encoding.UTF8.GetBytes(plaintext);
		byte[] cipher = Obfuscate(data);
		Array.Clear(data, 0, data.Length);
		return ProtectedEnvelope.Create(cipher, scope);
	}

	/// <inheritdoc />
	public string Unprotect(string envelopeOrPlaintext)
	{
		ArgumentNullException.ThrowIfNull(envelopeOrPlaintext);
		if (!ProtectedEnvelope.IsEnvelope(envelopeOrPlaintext))
		{
			return envelopeOrPlaintext;
		}

		(byte[] cipher, _) = ProtectedEnvelope.Parse(envelopeOrPlaintext);
		byte[] data = Obfuscate(cipher);
		try
		{
			return Encoding.UTF8.GetString(data);
		}
		finally
		{
			Array.Clear(data, 0, data.Length);
		}
	}

	private static byte[] Obfuscate(byte[] input)
	{
		byte[] output = new byte[input.Length];
		for (int i = 0; i < input.Length; i++)
		{
			output[i] = (byte)(input[i] ^ s_obfuscationKey[i % s_obfuscationKey.Length]);
		}

		return output;
	}
}
