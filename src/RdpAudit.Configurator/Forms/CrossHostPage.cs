/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrossHostPage.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Forms)
// Purpose: P4-18 Cross-Host tab. Renders the persisted cross-host attack chains over IPC:
//          a bounded newest-first chain list (rule / acknowledgment filters), a per-chain hop
//          (link) details pane populated on selection, and an Acknowledge action that flips the
//          chain flag and clears its linked CROSS_HOST_CHAIN alert server-side. Read-mostly;
//          the only mutation is the operator acknowledge.
// Depends: IpcClient, CrossHostChainDto/ListDto/DetailsDto/AckResultDto, DarkTheme
// Extends: Add host-availability indicators when a host-state list IPC command is introduced.

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Cross-host chain viewer tab.</summary>
[SupportedOSPlatform("windows")]
public sealed class CrossHostPage : TabPage
{
	private readonly IpcClient _ipc;

	private readonly TextBox _ruleFilter;
	private readonly CheckBox _includeAcknowledged;
	private readonly NumericUpDown _maxRows;
	private readonly Button _refresh;
	private readonly Button _acknowledge;
	private readonly Button _copy;
	private readonly Label _status;

	private readonly DataGridView _chainsGrid;
	private readonly DataGridView _linksGrid;
	private readonly Label _detailSummary;

	private readonly List<CrossHostChainDto> _chains = new();
	private long _selectedChainId = -1;
	private bool _selectedChainAcknowledged;
	private int _detailLoadToken;

	public CrossHostPage(IpcClient ipc)
	{
		_ipc = ipc;
		Text = "\U0001F310 Cross-Host";

		// --- Filter / action bar ----------------------------------------------------------------
		FlowLayoutPanel filters = new()
		{
			Dock = DockStyle.Top,
			Height = 44,
			Padding = new Padding(4),
			WrapContents = false,
			AutoScroll = true,
		};

		_ruleFilter = new TextBox { Width = 190, PlaceholderText = "RuleId filter (e.g. RDP_LATERAL_MOVEMENT)" };
		_includeAcknowledged = new CheckBox
		{
			Text = "Include acknowledged",
			AutoSize = true,
			Checked = true,
			Padding = new Padding(6, 8, 0, 0),
		};
		_maxRows = new NumericUpDown { Minimum = 1, Maximum = 1000, Value = 200, Width = 70 };

		_refresh = new Button { Text = "Refresh", Width = 90 };
		_refresh.Click += async (_, _) => await ReloadAsync().ConfigureAwait(true);

		_acknowledge = new Button { Text = "Acknowledge selected", Width = 150, Enabled = false };
		_acknowledge.Click += async (_, _) => await AcknowledgeSelectedAsync().ConfigureAwait(true);

		_copy = new Button { Text = "Copy page", Width = 90 };
		_copy.Click += (_, _) => CopyPageToClipboard();

		filters.Controls.Add(new Label { Text = "Rule:", AutoSize = true, Padding = new Padding(2, 8, 0, 0) });
		filters.Controls.Add(_ruleFilter);
		filters.Controls.Add(_includeAcknowledged);
		filters.Controls.Add(new Label { Text = "Max rows:", AutoSize = true, Padding = new Padding(6, 8, 0, 0) });
		filters.Controls.Add(_maxRows);
		filters.Controls.Add(_refresh);
		filters.Controls.Add(_acknowledge);
		filters.Controls.Add(_copy);

		// --- Chain list ---------------------------------------------------------------------------
		_chainsGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			ReadOnly = true,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
			RowHeadersVisible = false,
			AllowUserToResizeRows = false,
		};
		_chainsGrid.Columns.Add(NewColumn("Detected", "Last seen (UTC)", 90));
		_chainsGrid.Columns.Add(NewColumn("Path", "Host path", 170));
		_chainsGrid.Columns.Add(NewColumn("User", "User", 80));
		_chainsGrid.Columns.Add(NewColumn("Rule", "Rule", 110));
		_chainsGrid.Columns.Add(NewColumn("Score", "Score", 35));
		_chainsGrid.Columns.Add(NewColumn("Failed", "Failed", 40));
		_chainsGrid.Columns.Add(NewColumn("State", "State", 70));
		_chainsGrid.SelectionChanged += (_, _) => OnSelectedChainChanged();
		DataGridClipboardMenu.AttachWithExport(_chainsGrid, "Cross-host chains", ReportExportStatus);

		// --- Detail pane (selected chain hops) ---------------------------------------------------
		_detailSummary = new Label
		{
			Dock = DockStyle.Top,
			Height = 64,
			AutoSize = false,
			TextAlign = ContentAlignment.TopLeft,
			Padding = new Padding(6, 4, 4, 0),
			Text = "Select a chain to view its hops.",
		};

		_linksGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			ReadOnly = true,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
			RowHeadersVisible = false,
			AllowUserToResizeRows = false,
		};
		_linksGrid.Columns.Add(NewColumn("Ordinal", "Hop", 35));
		_linksGrid.Columns.Add(NewColumn("Host", "Host", 90));
		_linksGrid.Columns.Add(NewColumn("Kind", "Kind", 100));
		_linksGrid.Columns.Add(NewColumn("Event", "Event", 45));
		_linksGrid.Columns.Add(NewColumn("Time", "Time (UTC)", 90));
		_linksGrid.Columns.Add(NewColumn("SourceIp", "Source IP", 90));
		_linksGrid.Columns.Add(NewColumn("User", "User", 90));
		DataGridClipboardMenu.AttachWithExport(_linksGrid, "Cross-host chain hops", ReportExportStatus);

		Panel detailPanel = new() { Dock = DockStyle.Fill };
		detailPanel.Controls.Add(_linksGrid);
		detailPanel.Controls.Add(_detailSummary);

		SplitContainer split = new()
		{
			Dock = DockStyle.Fill,
			Orientation = Orientation.Vertical,
			SplitterDistance = 640,
		};
		split.Panel1.Controls.Add(_chainsGrid);
		split.Panel2.Controls.Add(detailPanel);

		_status = new Label
		{
			Dock = DockStyle.Bottom,
			Height = 24,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(6, 0, 0, 0),
			Text = "Ready",
		};

		Controls.Add(split);
		Controls.Add(_status);
		Controls.Add(filters);

		HandleCreated += async (_, _) => await ReloadAsync().ConfigureAwait(true);
	}

	/// <summary>Reports an export result through the page status label, using the same colour as the
	/// page's other informational messages.</summary>
	private void ReportExportStatus(string message)
	{
		_status.Text = message;
		_status.ForeColor = TextPrimary;
	}

	private static DataGridViewTextBoxColumn NewColumn(string name, string header, int fillWeight) => new()
	{
		Name = name,
		HeaderText = header,
		FillWeight = fillWeight,
		SortMode = DataGridViewColumnSortMode.NotSortable,
	};

	private async Task ReloadAsync()
	{
		_refresh.Enabled = false;
		_status.Text = "Loading chains…";
		_status.ForeColor = TextPrimary;
		try
		{
			CrossHostChainsRequest request = new()
			{
				MaxRows = (int)_maxRows.Value,
				RuleId = string.IsNullOrWhiteSpace(_ruleFilter.Text) ? null : _ruleFilter.Text.Trim(),
				IncludeAcknowledged = _includeAcknowledged.Checked,
			};

			IpcCallResult<CrossHostChainListDto> call =
				await _ipc.SendDetailedAsync<CrossHostChainListDto>(IpcCommand.ListCrossHostChains, request).ConfigureAwait(true);

			if (!call.IsSuccess || call.Value is not { } list)
			{
				_status.Text = "Cross-host chains unavailable: " + call.Headline();
				_status.ForeColor = StatusDanger;
				return;
			}

			if (list.Status != IpcResultStatus.Success)
			{
				_status.Text = "Chains query failed: " + (list.Message ?? list.Status.ToString());
				_status.ForeColor = StatusDanger;
				return;
			}

			_chains.Clear();
			_chains.AddRange(list.Chains);
			BindChainsGrid();
			ClearDetails();

			_status.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Showing {0} of {1} chains (server limit {2}).",
				list.Chains.Count,
				list.TotalMatching,
				list.AppliedLimit);
			_status.ForeColor = TextPrimary;
		}
		catch (Exception ex)
		{
			_status.Text = "Cross-host error: " + ex.GetType().Name;
			_status.ForeColor = StatusDanger;
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}

	private void BindChainsGrid()
	{
		_chainsGrid.Rows.Clear();
		foreach (CrossHostChainDto chain in _chains)
		{
			string path = chain.HostPath.Count > 0 ? string.Join(" → ", chain.HostPath) : "(no host path)";
			int idx = _chainsGrid.Rows.Add(
				chain.LastSeenUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
				path,
				chain.NormalizedUserName,
				chain.RuleId,
				chain.Score.ToString(CultureInfo.InvariantCulture),
				chain.FailedAttemptCount.ToString(CultureInfo.InvariantCulture),
				chain.IsAcknowledged ? "Acknowledged" : "Open");

			DataGridViewRow row = _chainsGrid.Rows[idx];
			row.Tag = chain.Id;
			row.DefaultCellStyle.ForeColor = chain.IsAcknowledged ? TextSecondary : TextPrimary;
		}
	}

	private void OnSelectedChainChanged()
	{
		if (_chainsGrid.CurrentRow is null || _chainsGrid.CurrentRow.Tag is not long chainId)
		{
			ClearDetails();
			return;
		}

		_selectedChainId = chainId;
		_selectedChainAcknowledged = _chains.Find(c => c.Id == chainId)?.IsAcknowledged ?? false;
		_acknowledge.Enabled = !_selectedChainAcknowledged;
		_ = LoadSelectedChainDetailsAsync(chainId);
	}

	private async Task LoadSelectedChainDetailsAsync(long chainId)
	{
		int generation = ++_detailLoadToken;
		_detailSummary.Text = "Loading details…";
		_linksGrid.Rows.Clear();
		try
		{
			IpcCallResult<CrossHostChainDetailsDto> call = await _ipc
				.SendDetailedAsync<CrossHostChainDetailsDto>(
					IpcCommand.GetCrossHostChainDetails,
					new CrossHostChainDetailsRequest { ChainId = chainId })
				.ConfigureAwait(true);

			if (generation != _detailLoadToken || _selectedChainId != chainId)
			{
				return;
			}

			if (!call.IsSuccess || call.Value is not { } details)
			{
				_detailSummary.Text = "Details unavailable: " + call.Headline();
				return;
			}

			if (details.Status != IpcResultStatus.Success)
			{
				_detailSummary.Text = "Details query failed: " + (details.Message ?? details.Status.ToString());
				return;
			}

			RenderDetails(details);
		}
		catch (Exception ex)
		{
			if (generation == _detailLoadToken)
			{
				_detailSummary.Text = "Details error: " + ex.GetType().Name;
			}
		}
	}

	private void RenderDetails(CrossHostChainDetailsDto details)
	{
		string path = details.Links.Count > 0
			? string.Join(" → ", details.Links.Select(l => l.HostName))
			: "(no host path)";

		_detailSummary.Text = string.Format(
			CultureInfo.InvariantCulture,
			"Path: {0}   |   User: {1}   |   Rule: {2}   |   Score: {3}\nFirst seen: {4}   |   Last seen: {5}{6}",
			path,
			details.NormalizedUserName,
			details.RuleId,
			details.Score,
			FormatUtc(details.FirstSeenUtc),
			FormatUtc(details.LastSeenUtc),
			details.IsAcknowledged ? "   |   ACKNOWLEDGED" : string.Empty);

		_linksGrid.Rows.Clear();
		foreach (CrossHostChainLinkDto link in details.Links)
		{
			_linksGrid.Rows.Add(
				link.Ordinal.ToString(CultureInfo.InvariantCulture),
				link.HostName,
				link.Kind.ToString(),
				link.EventId.ToString(CultureInfo.InvariantCulture),
				FormatUtc(link.TimeUtc),
				link.SourceIp ?? string.Empty,
				link.UserName ?? string.Empty);
		}
	}

	private static string FormatUtc(DateTime value)
		=> value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

	private void ClearDetails()
	{
		_detailLoadToken++;
		_selectedChainId = -1;
		_selectedChainAcknowledged = false;
		_acknowledge.Enabled = false;
		_detailSummary.Text = "Select a chain to view its hops.";
		_linksGrid.Rows.Clear();
	}

	private async Task AcknowledgeSelectedAsync()
	{
		if (_selectedChainId <= 0)
		{
			_status.Text = "Select a chain to acknowledge.";
			_status.ForeColor = StatusDanger;
			return;
		}

		_acknowledge.Enabled = false;
		_status.Text = "Acknowledging chain…";
		_status.ForeColor = TextPrimary;
		try
		{
			IpcCallResult<CrossHostChainAckResultDto> call = await _ipc
				.SendDetailedAsync<CrossHostChainAckResultDto>(
					IpcCommand.AcknowledgeCrossHostChain,
					new CrossHostChainAckRequest { ChainId = _selectedChainId })
				.ConfigureAwait(true);

			if (!call.IsSuccess || call.Value is not { } result)
			{
				_status.Text = "Acknowledge failed: " + call.Headline();
				_status.ForeColor = StatusDanger;
				return;
			}

			if (result.Status != IpcResultStatus.Success)
			{
				_status.Text = "Acknowledge failed: " + (result.Message ?? result.Status.ToString());
				_status.ForeColor = StatusDanger;
				return;
			}

			_selectedChainAcknowledged = true;
			_status.Text = "Chain acknowledged.";
			await ReloadAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			_status.Text = "Acknowledge error: " + ex.GetType().Name;
			_status.ForeColor = StatusDanger;
		}
		finally
		{
			_acknowledge.Enabled = !_selectedChainAcknowledged && _selectedChainId > 0;
		}
	}

	private void CopyPageToClipboard()
	{
		if (_chains.Count == 0)
		{
			_status.Text = "Nothing to copy.";
			return;
		}

		StringBuilder sb = new();
		sb.AppendLine("DetectedUtc\tHostPath\tUser\tRule\tScore\tFailed\tState");
		foreach (CrossHostChainDto row in _chains)
		{
			string path = row.HostPath.Count > 0 ? string.Join(" → ", row.HostPath) : string.Empty;
			sb.Append(row.LastSeenUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)).Append('\t')
				.Append(path).Append('\t')
				.Append(row.NormalizedUserName).Append('\t')
				.Append(row.RuleId).Append('\t')
				.Append(row.Score).Append('\t')
				.Append(row.FailedAttemptCount).Append('\t')
				.AppendLine(row.IsAcknowledged ? "Acknowledged" : "Open");
		}

		try
		{
			Clipboard.SetText(sb.ToString());
			_status.Text = string.Format(CultureInfo.InvariantCulture, "Copied {0} rows to clipboard.", _chains.Count);
		}
		catch (Exception ex)
		{
			_status.Text = "Copy failed: " + ex.GetType().Name;
			_status.ForeColor = StatusDanger;
		}
	}
}
