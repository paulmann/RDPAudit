/*
 * File   : RouterOsSshClient.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Core)
 * Purpose: Thin async wrapper over SSH.NET used ONLY for the one-time bootstrap, where the
 *          production api-ssl/mTLS channel does not yet exist. It runs RouterOS CLI commands over
 *          SSH (certificate creation, api-ssl enablement, service-user creation) and returns the raw
 *          terminal output. After bootstrap the system switches to RouterOsApiClient and SSH is no
 *          longer used.
 * Depends: Renci.SshNet.SshClient, Microsoft.Extensions.Logging.ILogger
 * Extends: To add a bootstrap CLI step, call RunAsync with the RouterOS command string; to change
 *          authentication (e.g. key-based), add an alternate ConnectionInfo builder in the ctor.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace RdpAudit.Mikrotik.Core;

/// <summary>Outcome of one SSH CLI command.</summary>
/// <param name="ExitStatus">Remote exit status (0 == success for most RouterOS commands).</param>
/// <param name="Output">Captured stdout text.</param>
/// <param name="Error">Captured stderr text.</param>
public sealed record SshCommandResult(int ExitStatus, string Output, string Error)
{
	/// <summary>True when the command returned a zero exit status and no error text.</summary>
	public bool Succeeded => ExitStatus == 0 && string.IsNullOrWhiteSpace(Error);
}

/// <summary>Thin async wrapper over SSH.NET for the one-time RouterOS bootstrap.</summary>
public sealed class RouterOsSshClient : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ConnectionInfo _connectionInfo;
	private readonly ILogger<RouterOsSshClient> _logger;
	private SshClient? _client;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Builds a password-authenticated SSH connection descriptor for the bootstrap session.</summary>
	public RouterOsSshClient(string host, int port, string username, string password, ILogger<RouterOsSshClient> logger)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(host);
		ArgumentException.ThrowIfNullOrWhiteSpace(username);
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));

		PasswordAuthenticationMethod auth = new(username, password ?? string.Empty);
		_connectionInfo = new ConnectionInfo(host, port <= 0 ? 22 : port, username, auth)
		{
			Timeout = TimeSpan.FromSeconds(30),
		};
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Establishes the SSH session. Idempotent.</summary>
	public async Task ConnectAsync(CancellationToken ct)
	{
		if (_client is { IsConnected: true })
		{
			return;
		}

		_client = new SshClient(_connectionInfo);
		await Task.Run(() => _client.Connect(), ct).ConfigureAwait(false);
		_logger.LogDebug("SSH bootstrap session connected to {Host}.", _connectionInfo.Host);
	}

	/// <summary>
	/// Runs a single RouterOS CLI <paramref name="command"/> and returns its exit status and output.
	/// The call is honoured against <paramref name="ct"/> and never throws on a non-zero exit status —
	/// the caller inspects <see cref="SshCommandResult.Succeeded"/>.
	/// </summary>
	public async Task<SshCommandResult> RunAsync(string command, CancellationToken ct)
	{
		if (_client is not { IsConnected: true })
		{
			throw new InvalidOperationException("SSH client is not connected.");
		}

		return await Task.Run(() =>
		{
			using SshCommand cmd = _client.CreateCommand(command);
			string output = cmd.Execute();
			return new SshCommandResult(cmd.ExitStatus ?? -1, output, cmd.Error);
		}, ct).ConfigureAwait(false);
	}

	// ── Disposal ─────────────────────────────────────────────────────────────────

	/// <summary>Disconnects and disposes the SSH session.</summary>
	public void Dispose()
	{
		try
		{
			if (_client is { IsConnected: true })
			{
				_client.Disconnect();
			}
		}
		catch (SshException)
		{
			// Best-effort teardown.
		}
		finally
		{
			_client?.Dispose();
			_client = null;
		}
	}
}
