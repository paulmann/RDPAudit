// File:    src/RdpAudit.Service/Services/RdpSessionManager.cs
// Module:  RdpAudit.Service.Services
// Purpose: Service-side RDP session enumeration and control. Wraps the safe Windows
//          command-line tools used by the Configurator's Remote RDP Clients tab:
//          qwinsta (list), tsdiscon (disconnect) and logoff (terminate). The list path is
//          spawned through the parse-stable English console
//          (cmd.exe /d /c "chcp 437 >nul & qwinsta.exe") so the STATE column carries the
//          stable English tokens (Active / Disc / Conn / Listen) regardless of the host's
//          UI culture.
//
//          Stage 3 centralization:
//          * Both the English-console list path (qwinsta / quser) and the direct argument-list
//            destructive path (tsdiscon / logoff) now route through ExternalCommandRunner so
//            timeouts, kill-on-cancel and structured diagnostic capture are uniform.
//          * The shape of the cmd.exe argument string is still composed by the long-standing
//            SessionConsoleCommandFactory — its Stage-1 tests are preserved verbatim.
//          * Destructive tools (tsdiscon, logoff) keep argument-list execution; their stdout
//            is not parsed.
//          * Output is parsed by the pure RdpAudit.Core QwinstaParser so spawn / parse stages
//            can be unit-tested separately. The service-side path also augments qwinsta from
//            quser so rows with a blank SESSIONNAME (a disconnected user, e.g.) are recovered.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>Service-side RDP session enumeration and control.</summary>
[SupportedOSPlatform("windows")]
public sealed class RdpSessionManager
{
	private static readonly TimeSpan ToolTimeout = ExternalCommandRunner.DefaultTimeout;

	private readonly ILogger<RdpSessionManager> _logger;
	private readonly IExternalCommandRunner _runner;

	public RdpSessionManager(ILogger<RdpSessionManager> logger)
		: this(logger, new ExternalCommandRunner())
	{
	}

	internal RdpSessionManager(ILogger<RdpSessionManager> logger, IExternalCommandRunner runner)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(runner);
		_logger = logger;
		_runner = runner;
	}

	/// <summary>Lists currently known sessions on the local host using <c>qwinsta</c> spawned
	/// through the parse-stable English console (chcp 437). Augments rows with a blank
	/// SESSIONNAME from a parallel <c>quser</c> invocation when possible.</summary>
	public async Task<RdpSessionListDto> ListAsync(CancellationToken ct)
	{
		RdpSessionListDto result = new() { QueriedUtc = DateTime.UtcNow };

		ExternalCommandResult qwinsta;
		try
		{
			qwinsta = await _runner.RunEnglishConsoleAsync(
				TrustedEnglishConsoleTool.Qwinsta, args: null, ToolTimeout, ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "qwinsta enumeration failed");
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "qwinsta enumeration failed: " + ex.GetType().Name;
			return result;
		}

		if (!qwinsta.Success)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = qwinsta.BuildDiagnosticSummary();
			return result;
		}

		List<QwinstaSessionRow> rows = new(QwinstaParser.Parse(qwinsta.StdOut));

		int quserAugmented = 0;
		try
		{
			ExternalCommandResult quser = await _runner.RunEnglishConsoleAsync(
				TrustedEnglishConsoleTool.Quser, args: null, ToolTimeout, ct).ConfigureAwait(false);
			if (quser.Success)
			{
				IReadOnlyList<QuserSessionRow> quserRows = QuserParser.Parse(quser.StdOut);
				quserAugmented = QwinstaQuserMerger.Merge(rows, quserRows).RowsAugmented;
			}
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			// quser is best-effort — failure to spawn it never aborts the qwinsta listing.
			_logger.LogDebug(ex, "quser augmentation skipped");
		}

		IReadOnlyList<RdpSessionDto> dtos = QwinstaSessionMapper.MapAll(rows);
		foreach (RdpSessionDto dto in dtos)
		{
			result.Sessions.Add(dto);
		}

		result.Message = quserAugmented > 0
			? string.Format(CultureInfo.InvariantCulture,
				"Listed {0} session(s); {1} qwinsta row(s) repaired from quser.",
				result.Sessions.Count, quserAugmented)
			: string.Format(CultureInfo.InvariantCulture,
				"Listed {0} session(s).", result.Sessions.Count);
		return result;
	}

	/// <summary>Issues <c>tsdiscon &lt;sessionId&gt;</c>.</summary>
	public async Task<SessionActionResult> DisconnectAsync(int sessionId, CancellationToken ct)
	{
		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(sessionId);
		if (!v.Ok)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.InvalidRequest,
				SessionId = sessionId,
				Message = v.Error,
			};
		}

		SessionActionResult outcome = new() { SessionId = sessionId };
		try
		{
			ExternalCommandResult tool = await _runner.RunDirectAsync(
				commandLabel: "tsdiscon " + sessionId.ToString(CultureInfo.InvariantCulture),
				executable: "tsdiscon.exe",
				arguments: SessionCommandBuilder.BuildDisconnect(sessionId),
				timeout: ToolTimeout,
				ct: ct).ConfigureAwait(false);
			outcome.Status = tool.Success ? IpcResultStatus.Success : IpcResultStatus.Unavailable;
			outcome.Message = tool.Success
				? string.Format(CultureInfo.InvariantCulture, "Disconnect requested for session {0}.", sessionId)
				: tool.BuildDiagnosticSummary();
			_logger.LogInformation("Disconnect session {Id} exit={Exit}", sessionId, tool.ExitCode);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "tsdiscon failed for session {Id}", sessionId);
			outcome.Status = IpcResultStatus.Unavailable;
			outcome.Message = "tsdiscon failed: " + ex.GetType().Name;
		}

		return outcome;
	}

	/// <summary>Issues <c>logoff &lt;sessionId&gt;</c>.</summary>
	public async Task<SessionActionResult> LogoffAsync(int sessionId, CancellationToken ct)
	{
		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(sessionId);
		if (!v.Ok)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.InvalidRequest,
				SessionId = sessionId,
				Message = v.Error,
			};
		}

		SessionActionResult outcome = new() { SessionId = sessionId };
		try
		{
			ExternalCommandResult tool = await _runner.RunDirectAsync(
				commandLabel: "logoff " + sessionId.ToString(CultureInfo.InvariantCulture),
				executable: "logoff.exe",
				arguments: SessionCommandBuilder.BuildLogoff(sessionId),
				timeout: ToolTimeout,
				ct: ct).ConfigureAwait(false);
			outcome.Status = tool.Success ? IpcResultStatus.Success : IpcResultStatus.Unavailable;
			outcome.Message = tool.Success
				? string.Format(CultureInfo.InvariantCulture, "Logoff requested for session {0}.", sessionId)
				: tool.BuildDiagnosticSummary();
			_logger.LogInformation("Logoff session {Id} exit={Exit}", sessionId, tool.ExitCode);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "logoff failed for session {Id}", sessionId);
			outcome.Status = IpcResultStatus.Unavailable;
			outcome.Message = "logoff failed: " + ex.GetType().Name;
		}

		return outcome;
	}
}
