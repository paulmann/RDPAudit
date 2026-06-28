// File:    src/RdpAudit.Configurator/Services/LicenseStore.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Local persistence and server-side activation of the product license key. Activation POSTs
//          key=[key] to the activation endpoint and treats a plain "1" body as success and "0" as an
//          invalid key; any other body, an empty body, an HTTP error or a network failure is reported
//          distinctly so the UI can tell the user what happened. A successful key is stored under HKCU
//          so it survives restarts. The legacy offline stub remains for reference / offline testing.
// Depends: Microsoft.Win32.Registry (HKCU persistence), System.Net.Http (server activation)
// Extends: To change the activation protocol, edit ActivateOnlineAsync and the ActivationResult enum.
//          To relocate the stored key (e.g. to a file under %ProgramData%), change RegistrySubKey /
//          Load / Save only. To change the endpoint, edit ActivationEndpoint.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.4

using System.Runtime.Versioning;
using Microsoft.Win32;

namespace RdpAudit.Configurator.Services;

/// <summary>Local persistence and stub activation of the product license key.</summary>
[SupportedOSPlatform("windows")]
public sealed class LicenseStore
{
	// ── Fields & Constants ───────────────────────────────────────────────────────
	private const string RegistrySubKey = @"Software\RdpAudit";
	private const string KeyValueName = "LicenseKey";

	/// <summary>Production activation endpoint. The server is expected to answer with a plain body of
	/// "1" (activation succeeded) or "0" (rejected) for a form POST of <c>key=[key]</c>.</summary>
	private const string ActivationEndpoint = "https://activate.3389port.com/";

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Reads the persisted license key, or returns <c>null</c> when none is stored.</summary>
	public string? Load()
	{
		try
		{
			using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegistrySubKey, writable: false);
			string? value = key?.GetValue(KeyValueName) as string;
			return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
		}
		catch (Exception)
		{
			// Treat any registry read failure as "no license" — the UI then shows the input field.
			return null;
		}
	}

	/// <summary>Persists the license key under HKCU. Overwrites any previously stored value.</summary>
	public void Save(string licenseKey)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(licenseKey);

		using RegistryKey key = Registry.CurrentUser.CreateSubKey(RegistrySubKey, writable: true);
		key.SetValue(KeyValueName, licenseKey.Trim(), RegistryValueKind.String);
	}

	/// <summary>Removes the persisted license key, returning the UI to the unactivated state.</summary>
	public void Clear()
	{
		try
		{
			using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RegistrySubKey, writable: true);
			if (key?.GetValue(KeyValueName) is not null)
			{
				key.DeleteValue(KeyValueName, throwOnMissingValue: false);
			}
		}
		catch (Exception)
		{
			// Best-effort delete: if the value is already gone the UI state is correct regardless.
		}
	}

	// ── Offline Stub (reference / offline testing) ──────────────────────────────────

	/// <summary>Legacy offline stub: accepts any non-empty key and persists it without contacting the
	/// server. Retained for offline testing only; the live UI uses <see cref="ActivateOnlineAsync"/>.</summary>
	public bool ActivateOffline(string licenseKey)
	{
		if (string.IsNullOrWhiteSpace(licenseKey))
		{
			return false;
		}

		Save(licenseKey);
		return true;
	}

	// ── Server Activation ─────────────────────────────────────────────────────────

	/// <summary>Server-side activation. Sends a form-encoded POST of <c>key=[key]</c> to the activation
	/// endpoint and classifies the outcome: a "1" body is <see cref="ActivationResult.Activated"/> (and
	/// the key is persisted locally), a "0" body is <see cref="ActivationResult.InvalidKey"/>, an empty
	/// or unrecognised body is <see cref="ActivationResult.EmptyResponse"/>, and any HTTP / network
	/// failure (including timeout and cancellation) is <see cref="ActivationResult.NetworkError"/>.
	/// Honors the supplied <paramref name="ct"/>.</summary>
	public async Task<ActivationResult> ActivateOnlineAsync(string licenseKey, CancellationToken ct = default)
	{
		if (string.IsNullOrWhiteSpace(licenseKey))
		{
			return ActivationResult.InvalidKey;
		}

		try
		{
			using HttpClient http = new()
			{
				Timeout = TimeSpan.FromSeconds(15),
			};

			using FormUrlEncodedContent content = new(new[]
			{
				new KeyValuePair<string, string>("key", licenseKey.Trim()),
			});

			using HttpResponseMessage response =
				await http.PostAsync(new Uri(ActivationEndpoint), content, ct).ConfigureAwait(false);
			response.EnsureSuccessStatusCode();

			string body = (await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)).Trim();

			if (string.Equals(body, "1", StringComparison.Ordinal))
			{
				Save(licenseKey);
				return ActivationResult.Activated;
			}

			if (string.Equals(body, "0", StringComparison.Ordinal))
			{
				return ActivationResult.InvalidKey;
			}

			// Reachable server but unexpected / empty payload ─ cannot trust either verdict.
			return ActivationResult.EmptyResponse;
		}
		catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or InvalidOperationException or UriFormatException)
		{
			_ = ex;
			return ActivationResult.NetworkError;
		}
	}
}

/// <summary>Outcome of a server-side activation attempt.</summary>
public enum ActivationResult
{
	/// <summary>Server returned "1": the key is valid and has been persisted.</summary>
	Activated,

	/// <summary>Server returned "0": the key was rejected as invalid.</summary>
	InvalidKey,

	/// <summary>Server was reached but returned nothing usable (empty or unrecognised body).</summary>
	EmptyResponse,

	/// <summary>The activation server could not be reached (timeout, DNS / TLS / HTTP error, cancellation).</summary>
	NetworkError,
}
