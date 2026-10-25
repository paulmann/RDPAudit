// File:    src/RdpAudit.Core/WebUi/IisStatusProbe.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Read-only IIS status probe behind the Configurator Web Access tab. The probe decides
//          two facts - whether IIS is installed and whether the World Wide Web Publishing
//          Service (W3SVC) exists - plus one product fact: whether the published WebUI folder
//          contains index.html. Everything is fail-closed: a fact is only reported when a
//          source actually determined it, and a probe that cannot obtain information (no admin
//          rights, missing tooling) reports "unknown" instead of inventing a state. The probe
//          NEVER enables features, starts services, or writes anything; DISM is invoked only
//          with /Get-FeatureInfo in /English mode so the output is locale-stable, and the
//          registry fast path avoids spawning DISM at all when the InetStp key is present.
//
//          IIisPlatformProbe is the stub seam: unit tests supply deterministic fakes for
//          DISM / ServerManager style sources, and the production implementation
//          (WindowsIisPlatformProbe) is the thin read-only adapter over the registry and the
//          centralized command runner.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.WebUi;

/// <summary>
/// Stub seam behind <see cref="IisStatusProbe"/>. Implementations answer two read-only
/// questions with a tri-state: <c>true</c> / <c>false</c> when the source determined the
/// answer, <c>null</c> when it could not (missing rights, unavailable tooling).
/// </summary>
public interface IIisPlatformProbe
{
	/// <summary>Determines whether IIS is installed on this machine. Never writes / changes state.</summary>
	Task<bool?> IsIisInstalledAsync(CancellationToken cancellationToken);

	/// <summary>Determines whether the named Windows service exists (SCM / registry view).</summary>
	Task<bool?> ServiceExistsAsync(string serviceName, CancellationToken cancellationToken);

	/// <summary>Names the technique this implementation uses, for the Web Access status label.</summary>
	string Provider { get; }
}

/// <summary>
/// Orchestrates the platform probe and the published-content check into one
/// <see cref="IisStatusSnapshot"/>. Fail-closed: unknown channels are surfaced as
/// <see cref="IisStatusSnapshot.FailureReason"/> and never as invented facts.
/// </summary>
public sealed class IisStatusProbe
{
	private readonly IIisPlatformProbe _platform;
	private readonly string _webUiDirectory;

	public IisStatusProbe(IIisPlatformProbe platform, string webUiDirectory)
	{
		_platform = platform ?? throw new ArgumentNullException(nameof(platform));
		if (string.IsNullOrWhiteSpace(webUiDirectory))
		{
			throw new ArgumentException("The web-UI directory is required.", nameof(webUiDirectory));
		}

		_webUiDirectory = webUiDirectory;
	}

	public async Task<IisStatusSnapshot> ProbeAsync(CancellationToken cancellationToken = default)
	{
		IisStatusSnapshot snapshot = new() { Provider = _platform.Provider };

		bool? installed = await ReadSafelyAsync(_platform.IsIisInstalledAsync, cancellationToken)
			.ConfigureAwait(false);
		bool? w3svc = await ReadSafelyAsync(
				ct => _platform.ServiceExistsAsync(WindowsIisPlatformProbe.W3SvcServiceName, ct),
				cancellationToken)
			.ConfigureAwait(false);

		snapshot.IisStateDetermined = installed.HasValue;
		snapshot.W3SvcStateDetermined = w3svc.HasValue;
		snapshot.IisInstalled = installed == true;
		snapshot.W3SvcPresent = w3svc == true;
		snapshot.PublishedWebUiPresent = IsPublishedWebUiPresent();

		if (!installed.HasValue && !w3svc.HasValue)
		{
			snapshot.FailureReason =
				"IIS state could not be determined - the Configurator needs administrator rights to inspect IIS.";
		}
		else if (!installed.HasValue)
		{
			snapshot.FailureReason = "The IIS installation state could not be determined.";
		}
		else if (!w3svc.HasValue)
		{
			snapshot.FailureReason = "The World Wide Web Publishing Service state could not be determined.";
		}

		return snapshot;
	}

	private static async Task<bool?> ReadSafelyAsync(Func<CancellationToken, Task<bool?>> read, CancellationToken ct)
	{
		try
		{
			return await read(ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException
			or IOException or InvalidOperationException or NotSupportedException)
		{
			// The source could not answer - report unknown instead of a half-truth.
			return null;
		}
	}

	private bool IsPublishedWebUiPresent()
	{
		try
		{
			return File.Exists(Path.Combine(_webUiDirectory, RdpAuditPaths.WebUiWwwRootFolderName, "index.html"));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			return false;
		}
	}
}

/// <summary>
/// Windows implementation of <see cref="IIisPlatformProbe"/>. Read-only by design:
/// installed-state comes from the InetStp registry fast path (every IIS install writes it)
/// with a locale-stable DISM /English /Get-FeatureInfo confirmation when the key is absent,
/// and service existence is a presence check on the SCM registry services key. Never enables
/// anything; without rights the answers degrade to <c>null</c> (unknown), never to guesses.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsIisPlatformProbe : IIisPlatformProbe
{
	public const string W3SvcServiceName = "W3SVC";
	public const string IisWebServerRoleFeatureName = "IIS-WebServerRole";
	public const string InetStpRegistryKeyPath = @"SOFTWARE\Microsoft\InetStp";
	public const string ServicesRegistryKeyPath = @"SYSTEM\CurrentControlSet\Services\";

	public static readonly TimeSpan DismTimeout = TimeSpan.FromSeconds(120);

	/// <summary>Cached search set for the service-name guard (CA1870).</summary>
	private static readonly SearchValues<char> InvalidServiceNameChars = SearchValues.Create("\\/");

	private readonly IExternalCommandRunner _runner;

	public WindowsIisPlatformProbe(IExternalCommandRunner runner)
	{
		_runner = runner ?? throw new ArgumentNullException(nameof(runner));
	}

	public string Provider => "Registry InetStp + DISM Get-FeatureInfo (read-only)";

	public Task<bool?> IsIisInstalledAsync(CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();

		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(InetStpRegistryKeyPath);
			if (key is not null)
			{
				return Task.FromResult<bool?>(key.GetValue("MajorVersion") is not null);
			}
		}
		catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
		{
			// Registry fast path unavailable - fall through to the read-only DISM confirmation.
		}

		return ProbeViaDismAsync(cancellationToken);
	}

	public Task<bool?> ServiceExistsAsync(string serviceName, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (string.IsNullOrWhiteSpace(serviceName)
			|| serviceName.AsSpan().IndexOfAny(InvalidServiceNameChars) >= 0)
		{
			throw new ArgumentException("Invalid Windows service name.", nameof(serviceName));
		}

		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(ServicesRegistryKeyPath + serviceName);
			return Task.FromResult<bool?>(key is not null);
		}
		catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
		{
			return Task.FromResult<bool?>(null);
		}
	}

	private async Task<bool?> ProbeViaDismAsync(CancellationToken cancellationToken)
	{
		try
		{
			ExternalCommandResult result = await _runner.RunDirectAsync(
					commandLabel: "DISM IIS feature probe",
					executable: "dism.exe",
					arguments: new[]
					{
						"/English",
						"/Online",
						"/Get-FeatureInfo",
						"/FeatureName:" + IisWebServerRoleFeatureName,
					},
					timeout: DismTimeout,
					ct: cancellationToken)
				.ConfigureAwait(false);

			if (result.TimedOut || result.ExitCode != 0)
			{
				return null;
			}

			return DismFeatureOutputParser.TryGetState(result.StdOut);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex) when (ex is UnauthorizedAccessException or IOException
			or InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
		{
			return null;
		}
	}
}

/// <summary>
/// Pure locale-stable parser for the state line of <c>dism /English /Online /Get-FeatureInfo</c>.
/// Unit tests feed it stubbed DISM transcripts, so the Windows probe stays a thin adapter.
/// </summary>
public static class DismFeatureOutputParser
{
	/// <summary>
	/// Returns <c>true</c> for enabled / enable-pending, <c>false</c> for disabled /
	/// disable-pending, and <c>null</c> when the output contains no readable state line.
	/// </summary>
	public static bool? TryGetState(string? output)
	{
		if (string.IsNullOrWhiteSpace(output))
		{
			return null;
		}

		foreach (string rawLine in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
		{
			string line = rawLine.Trim();
			int colon = line.IndexOf(':');
			if (colon <= 0)
			{
				continue;
			}

			string label = line.Substring(0, colon).Trim();
			if (!label.Equals("State", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			string value = line.Substring(colon + 1).Trim();
			if (value.Equals("Enabled", StringComparison.OrdinalIgnoreCase)
				|| value.Equals("Enable Pending", StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			if (value.Equals("Disabled", StringComparison.OrdinalIgnoreCase)
				|| value.Equals("Disable Pending", StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}

			return null;
		}

		return null;
	}
}
