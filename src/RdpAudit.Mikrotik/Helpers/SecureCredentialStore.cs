/*
 * File   : SecureCredentialStore.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Helpers)
 * Purpose: DPAPI-backed (CurrentUser scope) at-rest protection for the MikroTik service-account
 *          password and the persisted bootstrap result. Plaintext secrets never touch disk: every
 *          value is wrapped with ProtectedData.Protect under an application entropy salt before it
 *          is written to %APPDATA%\RdpAudit\mikrotik_creds.dat.
 * Depends: System.Security.Cryptography.ProtectedData, RdpAudit.Core.MikroTik.MikrotikConfig,
 *          RdpAudit.Core.Util.JsonOptions
 * Extends: To persist an additional protected artifact, add a typed Save/Load pair that round-trips
 *          through ProtectBytes/UnprotectBytes; never add a code path that writes a plaintext secret.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.Util;

namespace RdpAudit.Mikrotik.Helpers;

/// <summary>DPAPI-backed at-rest protection for MikroTik credentials and bootstrap state.</summary>
public sealed class SecureCredentialStore
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Application entropy salt mixed into every DPAPI blob to scope protection to RdpAudit.</summary>
	private static readonly byte[] AppEntropy = Encoding.UTF8.GetBytes("RdpAudit.Mikrotik/v1/entropy");

	private readonly string _directory;
	private readonly string _credentialsPath;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates a store rooted at %APPDATA%\RdpAudit, or at <paramref name="overrideDirectory"/>.</summary>
	public SecureCredentialStore(string? overrideDirectory = null)
	{
		_directory = overrideDirectory
			?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RdpAudit");
		_credentialsPath = Path.Combine(_directory, "mikrotik_creds.dat");
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Absolute path of the protected credentials file.</summary>
	public string CredentialsPath => _credentialsPath;

	/// <summary>Wraps <paramref name="plaintext"/> as a Base64 DPAPI (CurrentUser) envelope string.</summary>
	public static string ProtectString(string plaintext)
	{
		ArgumentNullException.ThrowIfNull(plaintext);
		byte[] cipher = ProtectBytes(Encoding.UTF8.GetBytes(plaintext));
		return Convert.ToBase64String(cipher);
	}

	/// <summary>Unwraps a Base64 DPAPI envelope produced by <see cref="ProtectString"/>.</summary>
	public static string UnprotectString(string envelope)
	{
		ArgumentNullException.ThrowIfNull(envelope);
		byte[] plain = UnprotectBytes(Convert.FromBase64String(envelope));
		return Encoding.UTF8.GetString(plain);
	}

	/// <summary>Encrypts and persists the bootstrap result (including the DPAPI-wrapped password) to disk.</summary>
	public void SaveConfig(MikrotikConfig config)
	{
		ArgumentNullException.ThrowIfNull(config);
		Directory.CreateDirectory(_directory);

		string json = JsonSerializer.Serialize(config, JsonOptions.Default);
		byte[] cipher = ProtectBytes(Encoding.UTF8.GetBytes(json));
		File.WriteAllBytes(_credentialsPath, cipher);
	}

	/// <summary>Loads and decrypts the persisted bootstrap result, or null when no file exists.</summary>
	public MikrotikConfig? LoadConfig()
	{
		if (!File.Exists(_credentialsPath))
		{
			return null;
		}

		byte[] cipher = File.ReadAllBytes(_credentialsPath);
		byte[] plain = UnprotectBytes(cipher);
		string json = Encoding.UTF8.GetString(plain);
		return JsonSerializer.Deserialize<MikrotikConfig>(json, JsonOptions.Default);
	}

	/// <summary>Deletes the persisted credentials file if present. Idempotent.</summary>
	public void Clear()
	{
		if (File.Exists(_credentialsPath))
		{
			File.Delete(_credentialsPath);
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static byte[] ProtectBytes(byte[] plain)
		=> ProtectedData.Protect(plain, AppEntropy, DataProtectionScope.CurrentUser);

	private static byte[] UnprotectBytes(byte[] cipher)
		=> ProtectedData.Unprotect(cipher, AppEntropy, DataProtectionScope.CurrentUser);
}
