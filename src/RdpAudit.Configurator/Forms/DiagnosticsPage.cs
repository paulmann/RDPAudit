// File:    src/RdpAudit.Configurator/Forms/DiagnosticsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Diagnostic tab — renders the LLM-friendly DiagnosticsSnapshotDto returned by the
//          service. Shows effective channels and event IDs, Security watcher / backfill state,
//          DB counts grouped by channel and event ID, the most recent monitoring-config repair
//          report, the install path, and last pipeline errors. Operators can Copy the rendered
//          report to the clipboard or Export it to a timestamped .txt file. All DB lookups run
//          via Microsoft.Data.Sqlite through EF Core on the service side; no external sqlite3.exe
//          dependency is introduced.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Diagnostic tab — renders the LLM-friendly DiagnosticsSnapshotDto returned by the service.</summary>
[SupportedOSPlatform("windows")]
public sealed class DiagnosticsPage : TabPage
{
	private readonly IpcClient _ipc;
	private readonly TextBox _report;
	private readonly Button _refresh;
	private readonly Button _copy;
	private readonly Button _export;
	private readonly Button _probe;
	private readonly Label _status;

	public DiagnosticsPage(IpcClient ipc)
	{
		_ipc = ipc;
		Text = "Diagnostic";
		Padding = new Padding(8);

		FlowLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			Height = 36,
			AutoSize = false,
			FlowDirection = FlowDirection.LeftToRight,
		};

		_refresh = new Button { Text = "Refresh", Width = 110 };
		_copy = new Button { Text = "Copy to clipboard", Width = 150 };
		_export = new Button { Text = "Export to file…", Width = 150 };
		_probe = new Button { Text = "Run Security Auth Probe", Width = 200 };
		_refresh.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);
		_copy.Click += OnCopy;
		_export.Click += OnExport;
		_probe.Click += async (_, _) => await RunProbeAsync().ConfigureAwait(true);

		toolbar.Controls.AddRange(new Control[] { _refresh, _copy, _export, _probe });

		_status = new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "Awaiting first refresh…",
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(4, 2, 4, 2),
		};

		_report = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Both,
			WordWrap = false,
			Font = new Font(FontFamily.GenericMonospace, 9f),
		};

		Controls.Add(_report);
		Controls.Add(_status);
		Controls.Add(toolbar);

		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	private async Task RefreshAsync()
	{
		_status.Text = "Refreshing…";
		_refresh.Enabled = false;
		try
		{
			// Use the structured call shape so a connect-failure, a timeout, a service-side error and a
			// genuinely empty payload are each distinguishable — the historic SendAsync collapsed all of
			// them to null and produced the misleading bare "No diagnostics available". When the pipe is
			// reachable we always render an actionable structured failure (command, outcome, duration,
			// exception type/message, pipe state, plus a tail of recent OperationLog entries) rather than
			// a generic placeholder.
			IpcCallResult<DiagnosticsSnapshotDto> call =
				await _ipc.SendDetailedAsync<DiagnosticsSnapshotDto>(IpcCommand.GetDiagnostics).ConfigureAwait(true);

			if (call.IsSuccess && call.Value is { } snapshot)
			{
				_report.Text = DiagnosticsReportFormatter.Format(snapshot)
					+ Environment.NewLine
					+ SqliteSupportBundleReportFormatter.Format(AppContext.BaseDirectory);
				_status.Text = string.Format(
					CultureInfo.InvariantCulture,
					"Snapshot at {0:yyyy-MM-dd HH:mm:ss}Z  |  Status={1}  |  RawEvents={2}  AuthAttemptFacts={3}  RdpPort={4}",
					snapshot.GeneratedUtc,
					snapshot.Status,
					snapshot.RawEventsTotal,
					snapshot.AuthAttemptFactsTotal,
					snapshot.ResolvedRdpPort);
				return;
			}

			// Not a clean success. Build a structured failure report. If the pipe connected we can still
			// pull a tail of the durable OperationLog to give the operator real recent context.
			List<OperationLogDto> logTail = call.ServiceLikelyReachable
				? await TryLoadOperationLogTailAsync().ConfigureAwait(true)
				: new List<OperationLogDto>();

			_report.Text = DiagnosticsReportFormatter.FormatFailure(call, logTail)
				+ Environment.NewLine
				+ SqliteSupportBundleReportFormatter.Format(AppContext.BaseDirectory);
			_status.Text = "Diagnostics " + call.Headline();
		}
		catch (Exception ex)
		{
			_status.Text = "Service: error — " + ex.GetType().Name;
			_report.Text = "Unexpected error while requesting diagnostics: " + ex.GetType().Name + " — " + ex.Message;
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}

	/// <summary>Best-effort tail of the durable OperationLog used to enrich a structured diagnostics
	/// failure report. Never throws — on any error it returns an empty list so the failure report still
	/// renders.</summary>
	private async Task<List<OperationLogDto>> TryLoadOperationLogTailAsync()
	{
		try
		{
			OperationLogQueryRequest request = new()
			{
				DepthDays = 7,
				Page = 0,
				PageSize = 25,
			};
			IpcCallResult<OperationLogPageDto> call =
				await _ipc.SendDetailedAsync<OperationLogPageDto>(IpcCommand.QueryOperationLogs, request).ConfigureAwait(true);
			if (call.IsSuccess && call.Value is { } page && page.Status == IpcResultStatus.Success)
			{
				return page.Items.ToList();
			}
		}
		catch
		{
			// best-effort — the failure report is still useful without the tail
		}

		return new List<OperationLogDto>();
	}

	private async Task RunProbeAsync()
	{
		_status.Text = "Running Security auth probe…";
		_probe.Enabled = false;
		try
		{
			SecurityAuthProbeDto? probe = await _ipc.SendAsync<SecurityAuthProbeDto>(IpcCommand.RunSecurityAuthProbe).ConfigureAwait(true);
			if (probe is null)
			{
				_status.Text = "Service: probe returned nothing — is the service running?";
				_report.Text = "No probe result. Start the service and retry.";
				return;
			}

			_report.Text = SecurityAuthProbeReportFormatter.Format(probe);
			_status.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Probe at {0:yyyy-MM-dd HH:mm:ss}Z  |  Outcome={1}  |  Count={2}  |  Elapsed={3} ms",
				probe.GeneratedUtc,
				probe.Outcome,
				probe.Count,
				probe.ElapsedMilliseconds);
		}
		catch (Exception ex)
		{
			_status.Text = "Probe: error — " + ex.GetType().Name;
			_report.Text = ex.Message;
		}
		finally
		{
			_probe.Enabled = true;
		}
	}

	private void OnCopy(object? sender, EventArgs e)
	{
		if (string.IsNullOrEmpty(_report.Text))
		{
			return;
		}

		try
		{
			Clipboard.SetText(_report.Text);
			_status.Text = "Copied diagnostics to clipboard.";
		}
		catch (Exception ex)
		{
			_status.Text = "Clipboard copy failed: " + ex.Message;
		}
	}

	private void OnExport(object? sender, EventArgs e)
	{
		if (string.IsNullOrEmpty(_report.Text))
		{
			return;
		}

		using SaveFileDialog dlg = new()
		{
			Title = "Export RdpAudit diagnostics",
			Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
			FileName = string.Format(
				CultureInfo.InvariantCulture,
				"rdpaudit-diagnostics-{0:yyyyMMdd-HHmmss}.txt",
				DateTime.UtcNow),
			OverwritePrompt = true,
		};
		if (dlg.ShowDialog(FindForm()) != DialogResult.OK)
		{
			return;
		}

		try
		{
			File.WriteAllText(dlg.FileName, _report.Text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
			_status.Text = "Exported diagnostics to " + dlg.FileName;
		}
		catch (Exception ex)
		{
			_status.Text = "Export failed: " + ex.Message;
		}
	}
}

/// <summary>Pure formatter that turns a <see cref="DiagnosticsSnapshotDto"/> into a flat,
/// monospace-friendly report. Pulled out of the TabPage so it can be unit-tested without WinForms
/// and so the same string can be piped to either the clipboard or an exported .txt.</summary>
public static class DiagnosticsReportFormatter
{
	/// <summary>Format the snapshot for the Diagnostic tab. Always English; never throws.</summary>
	public static string Format(DiagnosticsSnapshotDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);
		StringBuilder sb = new();
		sb.AppendLine("RdpAudit diagnostics snapshot");
		sb.AppendLine("============================");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Generated (UTC):       {0:O}", dto.GeneratedUtc).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Result status:         {0}", dto.Status).AppendLine();
		if (!string.IsNullOrWhiteSpace(dto.Message))
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Message:               {0}", dto.Message).AppendLine();
		}
		sb.AppendFormat(CultureInfo.InvariantCulture, "Service version:       {0}", dto.ServiceVersion ?? "(unknown)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Install path:          {0}", dto.InstallPath ?? "(unknown)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Database path:         {0}", dto.DatabasePath ?? "(unknown)").AppendLine();
		sb.AppendLine();

		sb.AppendLine("RDP listener & firewall scope");
		sb.AppendLine("-----------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Resolved RDP port:     {0}", dto.ResolvedRdpPort).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Port source:           {0}", dto.ResolvedRdpPortSource ?? "(unknown)").AppendLine();
		if (!string.IsNullOrWhiteSpace(dto.ResolvedRdpPortDetail))
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Port detail:           {0}", dto.ResolvedRdpPortDetail).AppendLine();
		}
		sb.AppendFormat(CultureInfo.InvariantCulture, "Firewall block scope:  {0}", dto.FirewallBlockScope ?? "(unknown)").AppendLine();
		// Make the LocalPort semantics explicit so an operator can map scope -> firewall rule shape without
		// guessing: RdpPortOnly pins the resolved port; AllInbound deliberately matches every inbound port.
		if (string.Equals(dto.FirewallBlockScope, "RdpPortOnly", StringComparison.OrdinalIgnoreCase))
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "  -> RdpOnly rules block TCP LocalPort={0} (the resolved RDP port).", dto.ResolvedRdpPort).AppendLine();
		}
		else if (string.Equals(dto.FirewallBlockScope, "AllInbound", StringComparison.OrdinalIgnoreCase))
		{
			sb.AppendLine("  -> AllInbound rules block LocalPort=Any (every inbound port from the source IP).");
		}
		sb.AppendLine();

		sb.AppendLine("RDP Activity (AttackStats) freshness");
		sb.AppendLine("------------------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Latest RawEvent (local):        {0}", FormatLocalWithUtc(dto.LatestRawEventUtc)).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Latest AuthAttemptFact (local): {0}", FormatLocalWithUtc(dto.LatestAuthAttemptFactUtc)).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Latest AttackStat upd. (local): {0}", FormatLocalWithUtc(dto.LatestAttackStatUpdatedUtc)).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "AttackStats rows:               {0}", dto.AttackStatsTotal).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Stats worker last run (local):  {0}", FormatLocalWithUtc(dto.StatsWorkerLastRunUtc)).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Stats worker runs / last rows:  {0} / {1}", dto.StatsWorkerRunCount, dto.StatsWorkerLastRowsUpserted).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Stats worker last error:        {0}", dto.StatsWorkerLastError ?? "(none)").AppendLine();
		sb.AppendLine();

		sb.AppendLine("Effective monitoring configuration");
		sb.AppendLine("----------------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Channels ({0}):", dto.EnabledChannels.Count).AppendLine();
		if (dto.EnabledChannels.Count == 0)
		{
			sb.AppendLine("  (none — falling back to EventCatalog defaults)");
		}
		else
		{
			foreach (string c in dto.EnabledChannels)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  - {0}", c).AppendLine();
			}
		}
		sb.AppendFormat(CultureInfo.InvariantCulture, "Event IDs filter ({0}):", dto.EnabledEventIds.Count).AppendLine();
		if (dto.EnabledEventIds.Count == 0)
		{
			sb.AppendLine("  (empty — every catalog event ID for the enabled channels)");
		}
		else
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "  {0}", string.Join(", ", dto.EnabledEventIds)).AppendLine();
		}
		sb.AppendLine();

		sb.AppendLine("Monitoring config repair (stale appsettings.json)");
		sb.AppendLine("-------------------------------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Changed this run:      {0}", dto.MonitoringConfigRepairChanged).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Changed runs (total):  {0}", dto.MonitoringConfigRepairChangedRunCount).AppendLine();
		if (dto.MonitoringConfigRepairUtc is DateTime repUtc)
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Last run (UTC):        {0:O}", repUtc).AppendLine();
		}
		if (dto.MonitoringConfigRepairAddedChannels.Count > 0)
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Added channels:        {0}", string.Join(", ", dto.MonitoringConfigRepairAddedChannels)).AppendLine();
		}
		if (dto.MonitoringConfigRepairAddedEventIds.Count > 0)
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Added event IDs:       {0}", string.Join(", ", dto.MonitoringConfigRepairAddedEventIds)).AppendLine();
		}
		if (!string.IsNullOrWhiteSpace(dto.MonitoringConfigRepairReason))
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Reason:                {0}", dto.MonitoringConfigRepairReason).AppendLine();
		}
		sb.AppendLine();

		sb.AppendLine("Per-channel collector status");
		sb.AppendLine("----------------------------");
		if (dto.ChannelStatus.Count == 0)
		{
			sb.AppendLine("  (no channel arm/restart events recorded yet)");
		}
		else
		{
			foreach (KeyValuePair<string, string> kv in dto.ChannelStatus)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  {0,-70} {1}", kv.Key, kv.Value).AppendLine();
			}
		}
		sb.AppendLine();

		sb.AppendLine("Security watcher & backfill");
		sb.AppendLine("---------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Watcher armed:                  {0}", dto.SecurityWatcherEnabled).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Events read (live):             {0}", dto.SecurityEventsRead).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Events normalized:              {0}", dto.SecurityEventsNormalized).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Events rejected:                {0}", dto.SecurityEventsRejected).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Security 4624 / 4625 / 4648:    {0} / {1} / {2}", dto.Security4624Count, dto.Security4625Count, dto.Security4648Count).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Last Security event (local):    {0}", FormatLocalWithUtc(dto.LastSecurityEventUtc)).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Last Security channel error:    {0}", dto.LastSecurityChannelError ?? "(none)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Backfill last run (local):      {0}", FormatLocalWithUtc(dto.SecurityBackfillLastRunUtc)).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Backfill read / fwd / dup:      {0} / {1} / {2}", dto.SecurityBackfillRecordsRead, dto.SecurityBackfillRecordsForwarded, dto.SecurityBackfillRecordsDeduped).AppendLine();
		sb.AppendLine();

		sb.AppendLine("AuthAttemptFact counters");
		sb.AppendLine("------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Created (failed+succeeded):     {0}", dto.AuthAttemptFactCreated).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Failed:                         {0}", dto.AuthAttemptFactFailed).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Succeeded:                      {0}", dto.AuthAttemptFactSucceeded).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Last created (local):           {0}", FormatLocalWithUtc(dto.LastAuthAttemptFactCreatedUtc)).AppendLine();
		sb.AppendLine();

		sb.AppendLine("Database counts (EF Core / Microsoft.Data.Sqlite)");
		sb.AppendLine("-------------------------------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "RawEvents total:                {0}", dto.RawEventsTotal).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "AuthAttemptFacts total:         {0}", dto.AuthAttemptFactsTotal).AppendLine();
		sb.AppendLine();

		sb.AppendLine("RawEvents grouped by channel");
		sb.AppendLine("-----------------------------");
		if (dto.RawEventsByChannel.Count == 0)
		{
			sb.AppendLine("  (no rows)");
		}
		else
		{
			foreach (DiagnosticsChannelCount row in dto.RawEventsByChannel)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  {0,10}  {1}", row.Count, row.Channel).AppendLine();
			}
		}
		sb.AppendLine();

		sb.AppendLine("RawEvents grouped by event ID (top 30)");
		sb.AppendLine("---------------------------------------");
		if (dto.RawEventsByEventId.Count == 0)
		{
			sb.AppendLine("  (no rows)");
		}
		else
		{
			foreach (DiagnosticsEventIdCount row in dto.RawEventsByEventId)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  {0,10}  {1,6}  {2}", row.Count, row.EventId, row.Channel).AppendLine();
			}
		}
		sb.AppendLine();

		sb.AppendLine("AuthAttemptFacts grouped by EvidenceEventId / Outcome (top 30)");
		sb.AppendLine("---------------------------------------------------------------");
		if (dto.AuthAttemptFactsByOutcome.Count == 0)
		{
			sb.AppendLine("  (no rows)");
		}
		else
		{
			foreach (DiagnosticsFactOutcomeCount row in dto.AuthAttemptFactsByOutcome)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  {0,10}  {1,6}  {2}", row.Count, row.EvidenceEventId, row.Outcome).AppendLine();
			}
		}
		sb.AppendLine();

		sb.AppendLine("Recent pipeline errors");
		sb.AppendLine("----------------------");
		if (dto.RecentPipelineErrors.Count == 0)
		{
			sb.AppendLine("  (none)");
		}
		else
		{
			foreach (string err in dto.RecentPipelineErrors)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  - {0}", err).AppendLine();
			}
		}
		sb.AppendLine();

		sb.AppendLine("Recent operation log (newest first)");
		sb.AppendLine("-----------------------------------");
		if (dto.RecentOperationLog.Count == 0)
		{
			sb.AppendLine("  (no recent program-action log entries)");
		}
		else
		{
			foreach (DiagnosticsOperationLogLine line in dto.RecentOperationLog)
			{
				sb.AppendFormat(
					CultureInfo.InvariantCulture,
					"  {0:yyyy-MM-dd HH:mm:ss}Z  {1,-11}  {2}/{3}: {4}",
					line.TimeUtc,
					line.Severity,
					line.Source,
					line.Operation,
					line.Message).AppendLine();
			}
		}

		return sb.ToString();
	}

	/// <summary>Build an actionable structured failure report when GetDiagnostics did not return a clean
	/// snapshot. Never the bare "No diagnostics available": it states the command, outcome, duration,
	/// pipe/response state, exception type/message and, when the service was reachable, a tail of recent
	/// OperationLog entries so the operator has real context to act on. Always English; never throws.</summary>
	public static string FormatFailure(IpcCallResult<DiagnosticsSnapshotDto> call, IReadOnlyList<OperationLogDto> logTail)
	{
		ArgumentNullException.ThrowIfNull(call);
		StringBuilder sb = new();
		sb.AppendLine("RdpAudit diagnostics — could not build a full snapshot");
		sb.AppendLine("======================================================");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Command:               {0}", call.Command).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Outcome:               {0}", call.Outcome).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Headline:              {0}", call.Headline()).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Started (UTC):         {0:O}", call.StartUtc).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Duration / timeout:    {0} ms / {1} ms", call.DurationMs, call.TimeoutMs).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Pipe connected:        {0}", call.PipeConnected).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Response received:     {0}", call.ResponseReceived).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Exception type:        {0}", call.ErrorType ?? "(none)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Error message:         {0}", call.Error ?? "(none)").AppendLine();
		sb.AppendLine();

		sb.AppendLine("What this means");
		sb.AppendLine("---------------");
		sb.AppendLine(call.Outcome switch
		{
			IpcCallOutcome.ConnectFailed =>
				"The service named pipe did not accept a connection. The service is most likely stopped or not installed. Start the RdpAudit service (run the Configurator as administrator) and retry.",
			IpcCallOutcome.Timeout =>
				"The service is reachable but did not finish within the deadline. A long-running operation may be in progress; wait a moment and retry.",
			IpcCallOutcome.ServiceError =>
				"The service handled the request but reported an error. See the error message above and the recent operation log below.",
			IpcCallOutcome.TransportError =>
				"A transport / framing error occurred mid-stream after connecting. This usually indicates a version mismatch between the Configurator and the running service — re-publish and restart the service.",
			IpcCallOutcome.SuccessNoPayload =>
				"The service reported success but returned no diagnostics payload. This is unexpected; the recent operation log below may show why.",
			_ => "Unexpected outcome — see the trace line and recent operation log below.",
		});
		sb.AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Trace: {0}", call.TraceLine).AppendLine();
		sb.AppendLine();

		sb.AppendLine("Recent operation log (newest first)");
		sb.AppendLine("-----------------------------------");
		if (!call.ServiceLikelyReachable)
		{
			sb.AppendLine("  (service unreachable — operation log could not be queried)");
		}
		else if (logTail.Count == 0)
		{
			sb.AppendLine("  (no recent program-action log entries returned)");
		}
		else
		{
			foreach (OperationLogDto line in logTail)
			{
				sb.AppendFormat(
					CultureInfo.InvariantCulture,
					"  {0:yyyy-MM-dd HH:mm:ss}Z  {1,-11}  {2}/{3}: {4}",
					line.TimeUtc,
					line.Severity,
					line.Source,
					line.Operation,
					line.Message).AppendLine();
				if (!string.IsNullOrEmpty(line.ExceptionType))
				{
					sb.AppendFormat(CultureInfo.InvariantCulture, "      exception: {0}: {1}", line.ExceptionType, line.ExceptionMessage ?? "(no message)").AppendLine();
				}
			}
		}

		return sb.ToString();
	}

	/// <summary>v1.2.1: render a persisted UTC timestamp as "<local> | <UTC>Z" for the operator
	/// diagnostics panel. The deep-diagnostic dump keeps the UTC trace alongside the local form so
	/// support tickets pasted across timezones never lose evidence of the original wall clock.</summary>
	private static string FormatLocalWithUtc(DateTime? utc)
	{
		if (utc is not DateTime v)
		{
			return "(never)";
		}

		return LocalTimeFormatter.FormatBoth(v);
	}
}

/// <summary>Pure formatter that turns a <see cref="SecurityAuthProbeDto"/> into a flat,
/// monospace-friendly report. Pulled out of the TabPage so it can be unit-tested without
/// WinForms and so the same string can be piped to the clipboard or an exported .txt.</summary>
public static class SecurityAuthProbeReportFormatter
{
	/// <summary>Format the probe outcome for the Diagnostic tab. Always English; never throws.</summary>
	public static string Format(SecurityAuthProbeDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);
		StringBuilder sb = new();
		sb.AppendLine("RdpAudit Security auth probe");
		sb.AppendLine("============================");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Generated (UTC):       {0:O}", dto.GeneratedUtc).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Result status:         {0}", dto.Status).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Outcome:               {0}", dto.Outcome).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Identity:              {0}", dto.Identity ?? "(unknown)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Lookback (hours):      {0}", dto.LookbackHours).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Elapsed (ms):          {0}", dto.ElapsedMilliseconds).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Count returned:        {0}", dto.Count).AppendLine();
		if (!string.IsNullOrWhiteSpace(dto.Message))
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Message:               {0}", dto.Message).AppendLine();
		}
		if (!string.IsNullOrWhiteSpace(dto.Query))
		{
			sb.AppendLine();
			sb.AppendLine("XPath issued");
			sb.AppendLine("------------");
			sb.AppendLine(dto.Query);
		}

		if (!string.IsNullOrEmpty(dto.ExceptionType))
		{
			sb.AppendLine();
			sb.AppendLine("Exception detail");
			sb.AppendLine("----------------");
			sb.AppendFormat(CultureInfo.InvariantCulture, "Type:                  {0}", dto.ExceptionType).AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "HResult:               {0}", dto.ExceptionHResult ?? "(none)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "Message:               {0}", dto.ExceptionMessage ?? "(none)").AppendLine();
		}

		if (dto.FirstEvent is SecurityAuthProbeEvent first)
		{
			sb.AppendLine();
			sb.AppendLine("First parsed event");
			sb.AppendLine("------------------");
			sb.AppendFormat(CultureInfo.InvariantCulture, "EventId:               {0}", first.EventId).AppendLine();
			sb.AppendFormat(
				CultureInfo.InvariantCulture,
				"Time:                  {0}",
				first.TimeUtc is { } t ? LocalTimeFormatter.FormatBoth(t) : "(unknown)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "User:                  {0}", first.User ?? "(none)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "Domain:                {0}", first.Domain ?? "(none)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "Source IP:             {0}", first.Ip ?? "(none)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "LogonType:             {0}", first.LogonType?.ToString(CultureInfo.InvariantCulture) ?? "(none)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "Status:                {0}", first.Status ?? "(none)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "SubStatus:             {0}", first.SubStatus ?? "(none)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "SubStatus meaning:     {0}", first.SubStatusMeaning ?? "(none)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "AuthPackage:           {0}", first.AuthPackage ?? "(none)").AppendLine();
			sb.AppendFormat(CultureInfo.InvariantCulture, "Workstation:           {0}", first.WorkstationName ?? "(none)").AppendLine();
		}

		return sb.ToString();
	}
}

/// <summary>Renders a bounded, read-only preflight report describing whether the SQLite diagnostic
/// support bundle (Microsoft.Data.Sqlite + SQLitePCLRaw.* + native e_sqlite3.dll) is physically
/// present next to the running Configurator. External PowerShell diagnostics need these as loose
/// files; this section tells the operator the exact path of each required file and its on-disk
/// version. It performs at most one existence check and one metadata read per required file, never
/// loads a managed assembly, and never throws — a failure to read a version degrades to "(unknown)".</summary>
internal static class SqliteSupportBundleReportFormatter
{
	public static string Format(string configuratorDirectory)
	{
		StringBuilder sb = new();
		sb.AppendLine();
		sb.AppendLine("SQLite diagnostic support bundle (Configurator-local)");
		sb.AppendLine("=====================================================");

		if (string.IsNullOrWhiteSpace(configuratorDirectory))
		{
			sb.AppendLine("Configurator directory: (unknown)");
			sb.AppendLine("Bundle status:          cannot inspect — base directory is not resolvable.");
			return sb.ToString();
		}

		SqliteSupportBundleStatus status = SqliteSupportBundle.Verify(configuratorDirectory);
		sb.AppendFormat(CultureInfo.InvariantCulture, "Configurator directory: {0}", configuratorDirectory).AppendLine();
		sb.AppendFormat(
			CultureInfo.InvariantCulture,
			"Bundle complete:        {0} ({1}/{2} files present)",
			status.Complete ? "Yes" : "No",
			status.PresentFiles.Count,
			SqliteSupportBundle.RequiredFiles.Count).AppendLine();
		sb.AppendLine();
		sb.AppendLine("Required files");
		sb.AppendLine("--------------");

		foreach (string fileName in SqliteSupportBundle.RequiredFiles)
		{
			string fullPath = Path.Combine(configuratorDirectory, fileName);
			bool present = File.Exists(fullPath);
			string marker = present ? "[OK ]" : "[!! ]";
			sb.AppendFormat(CultureInfo.InvariantCulture, "{0} {1}", marker, fullPath).AppendLine();
			if (present)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "      version: {0}", TryReadFileVersion(fullPath)).AppendLine();
			}
		}

		if (!status.Complete)
		{
			sb.AppendLine();
			sb.AppendLine(SqliteSupportBundle.DescribeMissing(status));
		}

		return sb.ToString();
	}

	/// <summary>Reads file/product version strings without loading the assembly. Bounded and
	/// exception-safe: any IO or metadata failure degrades to "(unknown)".</summary>
	private static string TryReadFileVersion(string fullPath)
	{
		try
		{
			FileVersionInfo info = FileVersionInfo.GetVersionInfo(fullPath);
			string file = string.IsNullOrWhiteSpace(info.FileVersion) ? "(none)" : info.FileVersion!;
			string product = string.IsNullOrWhiteSpace(info.ProductVersion) ? "(none)" : info.ProductVersion!;
			return string.Format(CultureInfo.InvariantCulture, "file={0}, product={1}", file, product);
		}
		catch
		{
			return "(unknown)";
		}
	}
}
