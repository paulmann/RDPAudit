// File:    src/RdpAudit.Configurator/Services/LocalRdpSessionProvider.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Configurator-side direct enumeration of local RDP sessions for the Remote RDP
//          Clients tab when the RdpAudit service IPC pipe is unreachable. Mirrors the
//          service-side RdpSessionManager behaviour: spawns the supported Windows
//          command-line tools (qwinsta.exe and, for repair, quser.exe), reads their column
//          output through the pure RdpAudit.Core QwinstaParser / QuserParser, merges the
//          two via QwinstaQuserMerger (so a qwinsta row with a blank SESSIONNAME gets its
//          name filled from the matching quser entry), and projects every parsed row into
//          the existing RdpSessionDto contract.
//
//          The provider runs qwinsta and quser through the parse-stable English console
//          composed by SessionConsoleCommandFactory — cmd.exe /d /c "chcp 437 >nul & tool" —
//          which pins the active code page to US-OEM. That is the documented technique for
//          getting English STATE tokens (Active / Disc / Conn / Listen) out of these tools
//          regardless of the operator's UI culture (Russian, in the field diagnostic). When
//          the active-code-page forcing has no effect the header-agnostic / Cyrillic-aware
//          parser still recovers the rows.
//
//          Shell-injection safety: the cmd /d /c argument string is built from FIXED
//          constants in SessionConsoleCommandFactory — no operator input ever flows into it.
//          ProcessStartInfo uses a single Arguments string composed entirely from those
//          constants so the user cannot inject additional tokens. A hard timeout kills the
//          process tree so a hung qwinsta/quser cannot freeze the UI worker. Read-only —
//          never spawns tsdiscon/logoff/mstsc.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Threading;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Indicates how the parsed qwinsta output was sourced and which language was
/// observed in the stdout stream. Surfaced to the orchestrator/UI so the operator can
/// tell whether the stable English/Latin path or the Cyrillic-tolerant fallback was
/// taken.</summary>
public enum LocalSessionOutputFlavour
{
	/// <summary>Output could not be parsed at all (no data rows).</summary>
	Unknown = 0,

	/// <summary>Output contained English column markers (e.g. SESSIONNAME / STATE).</summary>
	EnglishStable = 1,

	/// <summary>Output contained Cyrillic markers — the English forcing did not take.</summary>
	CyrillicFallback = 2,

	/// <summary>Output parsed cleanly but the language could not be classified.</summary>
	NeutralStable = 3,
}

/// <summary>Outcome of a local <see cref="LocalRdpSessionProvider.ListAsync"/> call.</summary>
public sealed record LocalSessionListResult(
	bool Success,
	IReadOnlyList<RdpSessionDto> Sessions,
	string? Error,
	LocalSessionOutputFlavour Flavour,
	int QuserAugmentedRows)
{
	/// <summary>Convenience factory for a successful listing.</summary>
	public static LocalSessionListResult Ok(IReadOnlyList<RdpSessionDto> sessions, LocalSessionOutputFlavour flavour, int quserAugmentedRows) =>
		new(true, sessions, null, flavour, quserAugmentedRows);

	/// <summary>Convenience factory for a failed listing.</summary>
	public static LocalSessionListResult Failed(string error) =>
		new(false, Array.Empty<RdpSessionDto>(), error, LocalSessionOutputFlavour.Unknown, 0);
}

/// <summary>Abstraction over spawning a single trusted session-query tool. Lets tests inject
/// deterministic stdout for both qwinsta and quser without touching the real Windows console.</summary>
public interface ILocalSessionToolSpawner
{
	/// <summary>Run the specified trusted tool and capture its stdout/stderr/exit code.</summary>
	Task<LocalSessionToolResult> RunAsync(TrustedSessionTool tool, CancellationToken ct);
}

/// <summary>Configurator-side enumeration of local RDP sessions via <c>qwinsta.exe</c> repaired
/// from <c>quser.exe</c>. Used by <see cref="Forms.RemoteRdpClientsPage"/> when the RdpAudit
/// service IPC pipe is unreachable so the operator still sees live session rows; historical
/// enrichment is unavailable in this mode.</summary>
[SupportedOSPlatform("windows")]
public sealed class LocalRdpSessionProvider
{
	/// <summary>Default hard timeout for the qwinsta invocation. The session listing usually
	/// completes in tens of milliseconds — five seconds is generous and still bounds UI hangs.</summary>
	internal const int DefaultTimeoutMs = 5_000;

	private readonly int _timeoutMs;
	private readonly ILocalSessionToolSpawner _spawner;

	/// <summary>Production constructor — spawns through the system English console.</summary>
	public LocalRdpSessionProvider()
		: this(DefaultTimeoutMs, new SystemConsoleSpawner())
	{
	}

	/// <summary>Test-friendly constructor that lets the unit suite inject a deterministic spawner.</summary>
	internal LocalRdpSessionProvider(int timeoutMs, ILocalSessionToolSpawner spawner)
	{
		_timeoutMs = timeoutMs > 0
			? timeoutMs
			: throw new ArgumentOutOfRangeException(nameof(timeoutMs));
		_spawner = spawner ?? throw new ArgumentNullException(nameof(spawner));
	}

	/// <summary>Lists currently known sessions on the local host. Never throws — failures are
	/// surfaced through <see cref="LocalSessionListResult.Error"/>.</summary>
	public async Task<LocalSessionListResult> ListAsync(CancellationToken ct = default)
	{
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(_timeoutMs);

		LocalSessionToolResult qwinsta;
		try
		{
			qwinsta = await _spawner.RunAsync(TrustedSessionTool.Qwinsta, cts.Token).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			return LocalSessionListResult.Failed("qwinsta timed out after "
				+ _timeoutMs.ToString(CultureInfo.InvariantCulture) + " ms.");
		}
		catch (Exception ex)
		{
			return LocalSessionListResult.Failed("qwinsta failed to start: "
				+ ex.GetType().Name + " — " + ex.Message);
		}

		if (!qwinsta.Ok)
		{
			return LocalSessionListResult.Failed(string.Format(CultureInfo.InvariantCulture,
				"qwinsta exit {0}: {1}", qwinsta.ExitCode, Truncate(qwinsta.StdErr, 200)));
		}

		List<QwinstaSessionRow> qwinstaRows = new(QwinstaParser.Parse(qwinsta.StdOut));

		int quserAugmented = 0;
		LocalSessionToolResult? quser = await TryRunQuserAsync(cts.Token).ConfigureAwait(false);
		if (quser is not null && quser.Ok)
		{
			IReadOnlyList<QuserSessionRow> quserRows = QuserParser.Parse(quser.StdOut);
			QwinstaQuserMergeResult merge = QwinstaQuserMerger.Merge(qwinstaRows, quserRows);
			quserAugmented = merge.RowsAugmented;
		}

		IReadOnlyList<RdpSessionDto> dtos = QwinstaSessionMapper.MapAll(qwinstaRows);
		LocalSessionOutputFlavour flavour = ClassifyOutputFlavour(qwinsta.StdOut, qwinstaRows.Count);
		return LocalSessionListResult.Ok(dtos, flavour, quserAugmented);
	}

	/// <summary>Adapter that returns the orchestrator-friendly <see cref="LocalSessionFallbackResult"/>
	/// shape so <see cref="RdpSessionFallbackOrchestrator"/> can be wired directly to this provider.</summary>
	public async Task<LocalSessionFallbackResult> FetchForOrchestratorAsync(CancellationToken ct)
	{
		LocalSessionListResult result = await ListAsync(ct).ConfigureAwait(false);
		if (!result.Success)
		{
			return LocalSessionFallbackResult.Failed(result.Error ?? "unknown error");
		}

		string detail = DescribeFlavour(result.Flavour);
		if (result.QuserAugmentedRows > 0)
		{
			detail += string.Format(CultureInfo.InvariantCulture,
				"; {0} qwinsta row(s) repaired from quser", result.QuserAugmentedRows);
		}

		return LocalSessionFallbackResult.Ok(result.Sessions, detail);
	}

	private async Task<LocalSessionToolResult?> TryRunQuserAsync(CancellationToken ct)
	{
		try
		{
			return await _spawner.RunAsync(TrustedSessionTool.Quser, ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			return null;
		}
		catch (Exception)
		{
			// quser is best-effort — failure to run it must not abort the qwinsta path.
			return null;
		}
	}

	/// <summary>Inspects the raw stdout for language markers so the UI can tell whether
	/// the stable English forcing took effect or the parser had to fall back to the
	/// localized Cyrillic tokens.</summary>
	internal static LocalSessionOutputFlavour ClassifyOutputFlavour(string stdOut, int parsedRowCount)
	{
		if (parsedRowCount == 0)
		{
			return LocalSessionOutputFlavour.Unknown;
		}

		if (string.IsNullOrEmpty(stdOut))
		{
			return LocalSessionOutputFlavour.NeutralStable;
		}

		string upper = stdOut.ToUpperInvariant();
		bool englishHeader = upper.Contains("SESSIONNAME", StringComparison.Ordinal)
			|| upper.Contains("USERNAME", StringComparison.Ordinal)
			|| upper.Contains("STATE", StringComparison.Ordinal);
		if (englishHeader)
		{
			return LocalSessionOutputFlavour.EnglishStable;
		}

		// Cyrillic markers — qwinsta header tokens and the state tokens themselves.
		foreach (string marker in CyrillicMarkers)
		{
			if (stdOut.Contains(marker, StringComparison.OrdinalIgnoreCase))
			{
				return LocalSessionOutputFlavour.CyrillicFallback;
			}
		}

		return LocalSessionOutputFlavour.NeutralStable;
	}

	private static readonly string[] CyrillicMarkers = new[]
	{
		"СЕАНС",
		"ПОЛЬЗОВАТЕЛЬ",
		"СТАТУС",
		"Активно",
		"Подключено",
		"Диск",
		"Отключено",
		"Прием",
		"Приём",
	};

	private static string DescribeFlavour(LocalSessionOutputFlavour flavour) => flavour switch
	{
		LocalSessionOutputFlavour.EnglishStable => "stable English qwinsta output",
		LocalSessionOutputFlavour.CyrillicFallback => "localized qwinsta output (Cyrillic-tolerant parse)",
		LocalSessionOutputFlavour.NeutralStable => "qwinsta output parsed (language-neutral)",
		_ => "qwinsta output not classified",
	};

	private static string Truncate(string? value, int max)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		string flat = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
		return flat.Length <= max ? flat : flat[..max];
	}

	/// <summary>Production spawner: delegates to the centralized <see cref="ExternalCommandRunner"/>
	/// so qwinsta / quser execute through cmd.exe with chcp 437 in effect. The runner pins the
	/// stdout encoding to the host OEM code page (cp866 on Russian builds, cp437 on English ones)
	/// so any Cyrillic state tokens that slip through still decode correctly for the localized
	/// parser fallback.</summary>
	private sealed class SystemConsoleSpawner : ILocalSessionToolSpawner
	{
		private static readonly TimeSpan SpawnTimeout = ExternalCommandRunner.DefaultTimeout;
		private readonly IExternalCommandRunner _runner;

		public SystemConsoleSpawner()
			: this(new ExternalCommandRunner())
		{
		}

		internal SystemConsoleSpawner(IExternalCommandRunner runner)
		{
			ArgumentNullException.ThrowIfNull(runner);
			_runner = runner;
		}

		public async Task<LocalSessionToolResult> RunAsync(TrustedSessionTool tool, CancellationToken ct)
		{
			TrustedEnglishConsoleTool generalized = tool switch
			{
				TrustedSessionTool.Qwinsta => TrustedEnglishConsoleTool.Qwinsta,
				TrustedSessionTool.Quser => TrustedEnglishConsoleTool.Quser,
				_ => throw new ArgumentOutOfRangeException(nameof(tool), tool, "Unknown trusted session tool."),
			};

			CultureInfo originalCulture = Thread.CurrentThread.CurrentCulture;
			CultureInfo originalUiCulture = Thread.CurrentThread.CurrentUICulture;
			Thread.CurrentThread.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
			Thread.CurrentThread.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");

			try
			{
				ExternalCommandResult result = await _runner.RunEnglishConsoleAsync(
					generalized, args: null, SpawnTimeout, ct).ConfigureAwait(false);
				return new LocalSessionToolResult(result.ExitCode, result.StdOut, result.StdErr);
			}
			finally
			{
				Thread.CurrentThread.CurrentCulture = originalCulture;
				Thread.CurrentThread.CurrentUICulture = originalUiCulture;
			}
		}
	}
}

/// <summary>Outcome of one external qwinsta invocation. Mirrors the service-side record so the
/// pure parsing path is identical on both sides.</summary>
public sealed record LocalSessionToolResult(int ExitCode, string StdOut, string StdErr)
{
	public bool Ok => ExitCode == 0;
}
