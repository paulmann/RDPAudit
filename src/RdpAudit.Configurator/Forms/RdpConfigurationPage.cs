// File:    src/RdpAudit.Configurator/Forms/RdpConfigurationPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Editable WinForms tab that surfaces the live Windows Terminal Services configuration
//          relevant to RDP — listener port, enabled state, NLA / SecurityLayer authentication mode,
//          Single Session per User, Hide Users on Logon Screen, Always-prompt-for-password, and the
//          Session Shadowing mode — plus TermService status and the termsrv.dll product version.
//          Every control carries a short description so the operator understands exactly what each
//          setting controls. Values are requested from RdpAudit.Service over IPC first; when the
//          service is not reachable (not installed, stopped, or pipe timeout) the page falls back to
//          an in-process direct registry / service inspection equivalent to the model used by
//          stascorp/rdpwrap's RDPConf.exe. The UI clearly indicates whether the displayed snapshot
//          came from the service or the local fallback. Mutating the registry flows through
//          <see cref="LocalRdpConfigurationWriter"/>, which captures a JSON backup of the affected
//          values before any write is committed and refuses to mutate the registry when that backup
//          step fails.
//
//          v2.0.0 — dark UI redesign. Absolute-position layout replaced with a TableLayoutPanel /
//          FlowLayoutPanel card composition styled to match MikroTikPage's dark palette. Adds a
//          StatusStrip status bar, an amber IPC-unreachable fallback banner, and a green Apply
//          accent when there are pending (dirty) edits. All persistence, validation, IPC and
//          fallback logic is preserved unchanged from v1.x.
// Extends: System.Windows.Forms.TabPage. To add a new RDP setting, add its control(s) to the
//          relevant card builder (BuildStatusCard / BuildListenerCard / BuildAuthCard /
//          BuildSessionPolicyCard / BuildShadowCard), wire the dirty-tracking handler through
//          OnEditChanged, and extend RdpConfigurationEditModel + RdpConfigurationDto accordingly.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 2.0.0

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

// v2.0.0 — dark UI redesign
/// <summary>Editable view of the live RDP configuration the Service reports over IPC, with an
/// in-process registry-based fallback when IPC is unavailable. Apply is guarded by a JSON
/// backup that is captured before any registry mutation lands. The page is rendered with the
/// shared dark palette so it matches the rest of the Configurator.</summary>
[SupportedOSPlatform("windows")]
public sealed class RdpConfigurationPage : TabPage
{
	// ── Dark palette (mirrors MikroTikPage benchmark) ────────────────────────────
	private static readonly Color BannerBack = Color.FromArgb(60, 50, 20);
	private static readonly Color BannerFore = Color.FromArgb(255, 200, 60);

	// ── Fields & DI ──────────────────────────────────────────────────────────────
	private readonly RdpConfigurationSnapshotService _snapshots;
	private readonly LocalRdpConfigurationWriter _writer;

	private readonly Panel _fallbackBanner;
	private readonly Label _serviceLine;
	private readonly Label _versionLine;
	private readonly Label _enabledDescription;
	private readonly CheckBox _enabledCheck;
	private readonly Label _portDescription;
	private readonly NumericUpDown _portInput;

	private readonly Label _authDescription;
	private readonly RadioButton _authNla;
	private readonly RadioButton _authNegotiate;
	private readonly RadioButton _authRdpSec;

	private readonly CheckBox _singleSession;
	private readonly Label _singleSessionDescription;
	private readonly CheckBox _hideUsers;
	private readonly Label _hideUsersDescription;
	private readonly CheckBox _alwaysPrompt;
	private readonly Label _alwaysPromptDescription;

	private readonly ComboBox _shadowMode;
	private readonly Label _shadowDescription;

	private readonly Button _refresh;
	private readonly Button _apply;
	private readonly Button _cancel;

	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;

	private RdpConfigurationDto? _baseline;
	private RdpConfigurationEditModel _edits = new();
	private bool _suppressDirtyEvents;
	private bool _dirty;

	// ── Construction ─────────────────────────────────────────────────────────────
	public RdpConfigurationPage(IpcClient ipc)
		: this(BuildSnapshotService(ipc, new LocalRdpConfigurationProvider()), new LocalRdpConfigurationWriter())
	{
	}

	public RdpConfigurationPage(RdpConfigurationSnapshotService snapshots, LocalRdpConfigurationWriter writer)
	{
		ArgumentNullException.ThrowIfNull(snapshots);
		ArgumentNullException.ThrowIfNull(writer);
		_snapshots = snapshots;
		_writer = writer;
		Text = "RDP Configuration";
		BackColor = PageBack;
		ForeColor = TextPrimary;
		Padding = new Padding(10);
		AutoScroll = true;

		// --- Service Status card controls -----------------------------------------------------
		_serviceLine = NewValueLine("TermService: probing...");
		_versionLine = NewValueLine("termsrv.dll: probing...");

		// --- Listener card controls -----------------------------------------------------------
		_enabledCheck = NewCheck("Enable Remote Desktop (fDenyTSConnections = 0)");
		_enabledCheck.CheckedChanged += (_, _) => OnEditChanged(() => _edits.RdpEnabled = _enabledCheck.Checked);
		_enabledDescription = NewDescription(RdpConfigurationModel.DescribeRdpEnabled);

		_portInput = new NumericUpDown
		{
			Minimum = RdpConfigurationModel.MinPort,
			Maximum = RdpConfigurationModel.MaxPort,
			Width = 140,
			BackColor = InputBack,
			ForeColor = TextPrimary,
			BorderStyle = BorderStyle.FixedSingle,
		};
		_portInput.ValueChanged += (_, _) => OnEditChanged(() => _edits.Port = (int)_portInput.Value);
		_portDescription = NewDescription(RdpConfigurationModel.DescribePortNumber);

		// --- Authentication card controls -----------------------------------------------------
		_authNla = NewRadio("Network Level Authentication required (UserAuthentication=1, SecurityLayer=2). Recommended.");
		_authNla.CheckedChanged += (_, _) => OnAuthModeChanged();
		_authNegotiate = NewRadio("Default RDP authentication — negotiate (UserAuthentication=0, SecurityLayer=1).");
		_authNegotiate.CheckedChanged += (_, _) => OnAuthModeChanged();
		_authRdpSec = NewRadio("RDP Security Layer — legacy (UserAuthentication=0, SecurityLayer=0). Not recommended.");
		_authRdpSec.CheckedChanged += (_, _) => OnAuthModeChanged();
		_authDescription = NewDescription(
			RdpConfigurationModel.DescribeAuthenticationMode(RdpUserAuthenticationMode.NlaRequired));

		// --- Session Policy card controls -----------------------------------------------------
		_singleSession = NewCheck("Single session per user");
		_singleSession.CheckedChanged += (_, _) => OnEditChanged(() => _edits.SingleSessionPerUser = _singleSession.Checked);
		_singleSessionDescription = NewDescription(RdpConfigurationModel.DescribeSingleSession);

		_hideUsers = NewCheck("Hide users on logon screen");
		_hideUsers.CheckedChanged += (_, _) => OnEditChanged(() => _edits.HideUsersOnLogon = _hideUsers.Checked);
		_hideUsersDescription = NewDescription(RdpConfigurationModel.DescribeHideUsersOnLogon);

		_alwaysPrompt = NewCheck("Always prompt for password upon connection (fPromptForPassword = 1)");
		_alwaysPrompt.CheckedChanged += (_, _) =>
			OnEditChanged(() => _edits.AlwaysPromptForPassword = _alwaysPrompt.Checked);
		_alwaysPromptDescription = NewDescription(RdpConfigurationModel.DescribePromptForPassword);

		// --- Session Shadowing card controls --------------------------------------------------
		_shadowMode = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Width = 460,
			FlatStyle = FlatStyle.Flat,
			BackColor = InputBack,
			ForeColor = TextPrimary,
		};
		_shadowMode.Items.AddRange(new object[]
		{
			"Not configured (Windows default)",
			"0 - No shadow allowed",
			"1 - Full control with user consent",
			"2 - Full control without user consent",
			"3 - View only with user consent",
			"4 - View only without user consent",
		});
		_shadowMode.SelectedIndex = 0;
		_shadowMode.SelectedIndexChanged += (_, _) => OnEditChanged(() => _edits.ShadowMode = ShadowFromComboIndex(_shadowMode.SelectedIndex));
		_shadowDescription = NewDescription(RdpConfigurationModel.DescribeShadowMode);

		// --- Action buttons -------------------------------------------------------------------
		_refresh = NewButton("Reload", ButtonNormal, ButtonHover);
		_refresh.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_apply = NewButton("Apply", ButtonNormal, ButtonHover);
		_apply.Enabled = false;
		_apply.Click += (_, _) => OnApply();

		_cancel = NewButton("Cancel", ButtonNormal, ButtonHover);
		_cancel.Enabled = false;
		_cancel.Click += (_, _) => OnCancel();

		// --- Fallback banner (hidden unless the snapshot came from the local registry) ---------
		_fallbackBanner = new Panel
		{
			Dock = DockStyle.Top,
			Height = 30,
			BackColor = BannerBack,
			Padding = new Padding(8, 0, 8, 0),
			Visible = false,
		};
		_fallbackBanner.Controls.Add(new Label
		{
			Dock = DockStyle.Fill,
			TextAlign = ContentAlignment.MiddleLeft,
			ForeColor = BannerFore,
			BackColor = BannerBack,
			Text = "\u26A0 IPC unreachable — showing local registry fallback. Changes will be applied locally.",
		});

		// --- Status bar -----------------------------------------------------------------------
		_statusStrip = new StatusStrip
		{
			SizingGrip = false,
			BackColor = StatusBack,
			ForeColor = StatusFore,
		};
		_statusLabel = new ToolStripStatusLabel("Ready.")
		{
			Spring = true,
			TextAlign = ContentAlignment.MiddleLeft,
			ForeColor = StatusFore,
		};
		_statusStrip.Items.Add(_statusLabel);

		// --- Compose: a single-column scrollable stack of dark cards ---------------------------
		TableLayoutPanel root = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 1,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			BackColor = PageBack,
		};
		root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

		root.Controls.Add(BuildStatusCard());
		root.Controls.Add(BuildListenerCard());
		root.Controls.Add(BuildAuthCard());
		root.Controls.Add(BuildSessionPolicyCard());
		root.Controls.Add(BuildShadowCard());
		root.Controls.Add(BuildButtonsRow());

		// Order matters: docked controls added later sit closer to the top edge.
		Controls.Add(root);
		Controls.Add(_statusStrip);
		Controls.Add(_fallbackBanner);

		SetEditControlsEnabled(false);
		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	private static RdpConfigurationSnapshotService BuildSnapshotService(
		IpcClient ipc,
		LocalRdpConfigurationProvider local)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		ArgumentNullException.ThrowIfNull(local);
		return new RdpConfigurationSnapshotService(
			ipcFetch: ct => ipc.SendAsync<RdpConfigurationDto>(IpcCommand.GetRdpConfiguration, null, ct),
			localFetch: local.Read);
	}

	// ── Card builders ────────────────────────────────────────────────────────────
	private Panel BuildStatusCard()
	{
		TableLayoutPanel body = NewCardBody(2);
		body.Controls.Add(_serviceLine, 0, 0);
		body.Controls.Add(_versionLine, 0, 1);
		return WrapCard("Service Status", body);
	}

	private Panel BuildListenerCard()
	{
		TableLayoutPanel body = NewCardBody(4);
		body.Controls.Add(_enabledCheck, 0, 0);
		body.Controls.Add(_enabledDescription, 0, 1);

		FlowLayoutPanel portRow = new()
		{
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			FlowDirection = FlowDirection.LeftToRight,
			WrapContents = false,
			BackColor = CardBack,
			Margin = new Padding(0, 6, 0, 0),
		};
		portRow.Controls.Add(new Label
		{
			Text = "Listener port:",
			AutoSize = true,
			ForeColor = TextPrimary,
			BackColor = CardBack,
			TextAlign = ContentAlignment.MiddleLeft,
			Margin = new Padding(0, 6, 8, 0),
		});
		portRow.Controls.Add(_portInput);
		body.Controls.Add(portRow, 0, 2);
		body.Controls.Add(_portDescription, 0, 3);
		return WrapCard("Listener", body);
	}

	private Panel BuildAuthCard()
	{
		TableLayoutPanel body = NewCardBody(4);
		body.Controls.Add(_authNla, 0, 0);
		body.Controls.Add(_authNegotiate, 0, 1);
		body.Controls.Add(_authRdpSec, 0, 2);
		body.Controls.Add(_authDescription, 0, 3);
		return WrapCard("Authentication", body);
	}

	private Panel BuildSessionPolicyCard()
	{
		TableLayoutPanel body = NewCardBody(6);
		body.Controls.Add(_singleSession, 0, 0);
		body.Controls.Add(_singleSessionDescription, 0, 1);
		body.Controls.Add(_hideUsers, 0, 2);
		body.Controls.Add(_hideUsersDescription, 0, 3);
		body.Controls.Add(_alwaysPrompt, 0, 4);
		body.Controls.Add(_alwaysPromptDescription, 0, 5);
		return WrapCard("Session Policy", body);
	}

	private Panel BuildShadowCard()
	{
		TableLayoutPanel body = NewCardBody(2);
		body.Controls.Add(_shadowMode, 0, 0);
		body.Controls.Add(_shadowDescription, 0, 1);
		return WrapCard("Session Shadowing", body);
	}

	private FlowLayoutPanel BuildButtonsRow()
	{
		FlowLayoutPanel buttons = new()
		{
			Dock = DockStyle.Top,
			FlowDirection = FlowDirection.RightToLeft,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			Padding = new Padding(0, 6, 0, 6),
			BackColor = PageBack,
			WrapContents = false,
		};
		// RightToLeft flow: first added sits rightmost.
		buttons.Controls.Add(_apply);
		buttons.Controls.Add(_cancel);
		buttons.Controls.Add(_refresh);
		return buttons;
	}

	// ── Dark control factories ───────────────────────────────────────────────────
	private static Label NewValueLine(string text) => new()
	{
		Text = text,
		AutoSize = false,
		Dock = DockStyle.Fill,
		Height = 22,
		ForeColor = TextPrimary,
		BackColor = CardBack,
		TextAlign = ContentAlignment.MiddleLeft,
		Margin = new Padding(0, 1, 0, 1),
	};

	private static Label NewDescription(string text) => new()
	{
		Text = text,
		AutoSize = false,
		Dock = DockStyle.Fill,
		Height = 40,
		Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 8f, FontStyle.Regular),
		ForeColor = TextSecondary,
		BackColor = CardBack,
		Margin = new Padding(0, 0, 0, 4),
	};

	private static CheckBox NewCheck(string text) => new()
	{
		Text = text,
		AutoSize = true,
		FlatStyle = FlatStyle.Flat,
		ForeColor = TextPrimary,
		BackColor = CardBack,
		Margin = new Padding(0, 2, 0, 0),
	};

	private static RadioButton NewRadio(string text) => new()
	{
		Text = text,
		AutoSize = true,
		FlatStyle = FlatStyle.Flat,
		ForeColor = TextPrimary,
		BackColor = CardBack,
		Margin = new Padding(0, 2, 0, 0),
	};

	private static Button NewButton(string text, Color normal, Color hover)
	{
		Button b = new()
		{
			Text = text,
			Height = 30,
			MinimumSize = new Size(150, 30),
			AutoSize = false,
			FlatStyle = FlatStyle.Flat,
			BackColor = normal,
			ForeColor = Color.White,
			Margin = new Padding(4, 0, 4, 0),
			Padding = new Padding(4, 0, 4, 0),
			UseVisualStyleBackColor = false,
		};
		b.FlatAppearance.BorderColor = hover;
		b.FlatAppearance.BorderSize = 1;
		b.FlatAppearance.MouseOverBackColor = hover;
		return b;
	}

	private static TableLayoutPanel NewCardBody(int rows)
	{
		TableLayoutPanel body = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 1,
			RowCount = rows,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			BackColor = CardBack,
			Padding = new Padding(2),
		};
		body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
		for (int i = 0; i < rows; i++)
		{
			body.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		}

		return body;
	}

	/// <summary>Wraps a card body in a bordered dark panel with a bold accent-color section
	/// header, simulating a GroupBox in the dark palette.</summary>
	private static Panel WrapCard(string title, Control body)
	{
		Panel card = new()
		{
			Dock = DockStyle.Top,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			BackColor = CardBack,
			Padding = new Padding(10, 30, 10, 10),
			Margin = new Padding(0, 0, 0, 8),
		};
		card.Paint += (_, e) =>
		{
			using Pen pen = new(CardBorder, 1);
			e.Graphics.DrawRectangle(pen, 0, 0, card.Width - 1, card.Height - 1);
		};

		Label header = new()
		{
			Text = title,
			AutoSize = true,
			Location = new Point(10, 8),
			Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 9.5f, FontStyle.Bold),
			ForeColor = AccentHeader,
			BackColor = CardBack,
		};

		body.Dock = DockStyle.Top;
		card.Controls.Add(body);
		card.Controls.Add(header);
		return card;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────
	private async Task RefreshAsync()
	{
		_refresh.Enabled = false;
		_apply.Enabled = false;
		_cancel.Enabled = false;
		SetStatus("Reading live configuration...");
		try
		{
			RdpConfigurationSnapshotResult result = await _snapshots.CaptureAsync().ConfigureAwait(true);
			if (!result.HasSnapshot || result.Snapshot is null)
			{
				ApplyUnreadableSnapshot();
				SetStatus(result.Error is null
					? "Could not read RDP configuration from the service or the local registry."
					: "Reload failed: " + result.Error);
				return;
			}

			_baseline = result.Snapshot;
			SetFallbackBannerVisible(result.Source == RdpConfigurationSnapshotSource.LocalFallback);
			LoadEditsFromSnapshot(_baseline);
			SetEditControlsEnabled(true);
			SetDirty(false);
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Source: {0}. Snapshot captured {1:yyyy-MM-dd HH:mm:ss} UTC.",
				DescribeSource(result.Source),
				_baseline.CapturedUtc));
		}
		catch (Exception ex)
		{
			ApplyUnreadableSnapshot();
			SetStatus("Reload failed: " + ex.GetType().Name + ": " + ex.Message);
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}

	private static string DescribeSource(RdpConfigurationSnapshotSource source) => source switch
	{
		RdpConfigurationSnapshotSource.ServiceIpc => "RdpAudit service (IPC)",
		RdpConfigurationSnapshotSource.LocalFallback => "local machine fallback",
		_ => "unknown",
	};

	private void SetFallbackBannerVisible(bool visible)
	{
		if (_fallbackBanner.Visible != visible)
		{
			_fallbackBanner.Visible = visible;
		}
	}

	private void ApplyUnreadableSnapshot()
	{
		_baseline = null;
		_serviceLine.Text = "TermService: unknown";
		_versionLine.Text = "OS: unknown    termsrv.dll: unknown";
		_suppressDirtyEvents = true;
		try
		{
			_enabledCheck.Checked = false;
			_portInput.Value = RdpConfigurationModel.DefaultRdpPort;
			_authNla.Checked = true;
			_singleSession.Checked = false;
			_hideUsers.Checked = false;
			_shadowMode.SelectedIndex = 0;
			_alwaysPrompt.Checked = false;
		}
		finally
		{
			_suppressDirtyEvents = false;
		}

		SetEditControlsEnabled(false);
	}

	private void LoadEditsFromSnapshot(RdpConfigurationDto dto)
	{
		_serviceLine.Text = string.Format(CultureInfo.InvariantCulture,
			"TermService: {0}{1}",
			dto.TermServiceInstalled ? "installed" : "not installed",
			dto.TermServiceInstalled ? (dto.TermServiceRunning ? " (running)" : " (stopped)") : string.Empty);

		StringBuilder version = new();
		version.Append("OS: ").Append(string.IsNullOrWhiteSpace(dto.OsVersion) ? "unknown" : dto.OsVersion);
		if (!string.IsNullOrWhiteSpace(dto.TermServiceVersion))
		{
			version.Append("    termsrv.dll: ").Append(dto.TermServiceVersion);
		}

		_versionLine.Text = version.ToString();

		_edits = RdpConfigurationEditModel.FromSnapshot(dto);

		_suppressDirtyEvents = true;
		try
		{
			_enabledCheck.Checked = _edits.RdpEnabled;
			_portInput.Value = Math.Clamp(_edits.Port, (int)_portInput.Minimum, (int)_portInput.Maximum);
			_singleSession.Checked = _edits.SingleSessionPerUser;
			_hideUsers.Checked = _edits.HideUsersOnLogon;
			SelectAuthMode(_edits.AuthenticationMode);
			_shadowMode.SelectedIndex = ComboIndexFromShadow(_edits.ShadowMode);
			_alwaysPrompt.Checked = _edits.AlwaysPromptForPassword;
		}
		finally
		{
			_suppressDirtyEvents = false;
		}

		_authDescription.Text = DescribeAuthMode(_edits.AuthenticationMode);

		string hideDetail = string.Format(CultureInfo.InvariantCulture,
			" Current values: dontdisplaylastusername={0}, DontEnumerateConnectedUsers={1}.",
			dto.DontDisplayLastUserNameRaw?.ToString(CultureInfo.InvariantCulture) ?? "missing",
			dto.DontEnumerateConnectedUsersRaw?.ToString(CultureInfo.InvariantCulture) ?? "missing");
		_hideUsersDescription.Text = RdpConfigurationModel.DescribeHideUsersOnLogon + hideDetail;
		_singleSessionDescription.Text = RdpConfigurationModel.DescribeSingleSession
			+ (dto.SingleSessionPerUserRaw is null ? " (value is currently absent)" : string.Empty);

		string promptDetail = string.Format(CultureInfo.InvariantCulture,
			" Current values: policy={0}, listener={1}.",
			dto.PromptForPasswordPolicyRaw?.ToString(CultureInfo.InvariantCulture) ?? "missing",
			dto.PromptForPasswordListenerRaw?.ToString(CultureInfo.InvariantCulture) ?? "missing");
		_alwaysPromptDescription.Text = RdpConfigurationModel.DescribePromptForPassword + promptDetail;
	}

	private void SelectAuthMode(RdpAuthenticationMode mode)
	{
		_authNla.Checked = mode == RdpAuthenticationMode.NetworkLevelAuth;
		_authNegotiate.Checked = mode == RdpAuthenticationMode.NegotiateNoNla;
		_authRdpSec.Checked = mode == RdpAuthenticationMode.RdpSecurityLayer;
	}

	private void OnAuthModeChanged()
	{
		if (_suppressDirtyEvents)
		{
			return;
		}

		RdpAuthenticationMode mode = _authNla.Checked ? RdpAuthenticationMode.NetworkLevelAuth
			: _authNegotiate.Checked ? RdpAuthenticationMode.NegotiateNoNla
			: _authRdpSec.Checked ? RdpAuthenticationMode.RdpSecurityLayer
			: RdpAuthenticationMode.NetworkLevelAuth;
		_edits.AuthenticationMode = mode;
		_authDescription.Text = DescribeAuthMode(mode);
		SetDirty(true);
	}

	private static string DescribeAuthMode(RdpAuthenticationMode mode) => mode switch
	{
		RdpAuthenticationMode.NetworkLevelAuth =>
			RdpConfigurationModel.DescribeAuthenticationMode(RdpUserAuthenticationMode.NlaRequired)
			+ "  /  "
			+ RdpConfigurationModel.DescribeSecurityLayer(RdpSecurityLayerMode.SslTls),
		RdpAuthenticationMode.NegotiateNoNla =>
			RdpConfigurationModel.DescribeAuthenticationMode(RdpUserAuthenticationMode.NlaNotRequired)
			+ "  /  "
			+ RdpConfigurationModel.DescribeSecurityLayer(RdpSecurityLayerMode.Negotiate),
		RdpAuthenticationMode.RdpSecurityLayer =>
			RdpConfigurationModel.DescribeAuthenticationMode(RdpUserAuthenticationMode.NlaNotRequired)
			+ "  /  "
			+ RdpConfigurationModel.DescribeSecurityLayer(RdpSecurityLayerMode.RdpSecurity),
		_ => string.Empty,
	};

	private void OnEditChanged(Action mutate)
	{
		if (_suppressDirtyEvents)
		{
			return;
		}

		mutate();
		SetDirty(true);
	}

	private void SetDirty(bool dirty)
	{
		_dirty = dirty;
		_cancel.Enabled = dirty && _baseline is not null;
		bool applyEnabled = dirty && _baseline is not null && _edits.Validate().IsValid;
		_apply.Enabled = applyEnabled;

		// v2.0.0 — signal pending changes visually by switching Apply to the success accent.
		if (_dirty && applyEnabled)
		{
			_apply.BackColor = SuccessAccent;
			_apply.FlatAppearance.BorderColor = SuccessHover;
			_apply.FlatAppearance.MouseOverBackColor = SuccessHover;
		}
		else
		{
			_apply.BackColor = ButtonNormal;
			_apply.FlatAppearance.BorderColor = ButtonHover;
			_apply.FlatAppearance.MouseOverBackColor = ButtonHover;
		}
	}

	private void SetEditControlsEnabled(bool enabled)
	{
		_enabledCheck.Enabled = enabled;
		_portInput.Enabled = enabled;
		_authNla.Enabled = enabled;
		_authNegotiate.Enabled = enabled;
		_authRdpSec.Enabled = enabled;
		_singleSession.Enabled = enabled;
		_hideUsers.Enabled = enabled;
		_shadowMode.Enabled = enabled;
		_alwaysPrompt.Enabled = enabled;
	}

	private void OnCancel()
	{
		if (_baseline is null)
		{
			return;
		}

		LoadEditsFromSnapshot(_baseline);
		SetDirty(false);
		SetStatus("Reverted edits to last loaded snapshot.");
	}

	private void OnApply()
	{
		if (_baseline is null)
		{
			SetStatus("Apply blocked: no baseline snapshot loaded.");
			return;
		}

		RdpConfigurationValidationResult validation = _edits.Validate();
		if (!validation.IsValid)
		{
			SetStatus("Apply blocked: " + string.Join("  |  ", validation.Errors));
			return;
		}

		RdpConfigurationChangeSet changes = _edits.ComputeChanges(_baseline);
		if (!changes.HasChanges)
		{
			SetStatus("Nothing to apply — no fields diverged from the loaded snapshot.");
			SetDirty(false);
			return;
		}

		string confirmation = string.Format(CultureInfo.InvariantCulture,
			"Apply {0} RDP configuration change(s)?\n\nA JSON backup of every affected value is "
			+ "captured first under %ProgramData%\\RdpAudit\\Backups so the change is reversible.",
			changes.Writes.Count);
		if (MessageBox.Show(confirmation, "Confirm Apply", MessageBoxButtons.YesNo,
			MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
		{
			SetStatus("Apply cancelled by operator.");
			return;
		}

		_apply.Enabled = false;
		_cancel.Enabled = false;
		SetStatus("Applying configuration...");
		LocalRdpConfigurationApplyResult result;
		try
		{
			result = _writer.Apply(changes);
		}
		catch (Exception ex)
		{
			SetStatus("Apply failed: " + ex.GetType().Name + " — " + ex.Message);
			return;
		}

		if (!result.Success)
		{
			SetStatus("Apply failed: " + (result.Error ?? "(unknown)"));
			return;
		}

		StringBuilder summary = new();
		summary.Append(string.Format(CultureInfo.InvariantCulture,
			"Applied {0} change(s). Backup: {1}.",
			result.WrittenValueLabels.Count,
			result.BackupFilePath ?? "(none)"));
		if (PortMutationRequiresRestart(changes))
		{
			summary.Append(" Listener port change requires TermService restart or reboot to take effect.");
		}

		SetStatus(summary.ToString());
		_ = RefreshAsync();
	}

	private static bool PortMutationRequiresRestart(RdpConfigurationChangeSet changes)
	{
		foreach (RdpRegistryWrite write in changes.Writes)
		{
			if (string.Equals(write.KeyPath, RdpConfigurationModel.RdpTcpListenerKey, StringComparison.OrdinalIgnoreCase)
				&& string.Equals(write.ValueName, RdpConfigurationModel.PortNumberValueName, StringComparison.Ordinal))
			{
				return true;
			}
		}

		return false;
	}

	private static int ComboIndexFromShadow(ShadowPolicyMode mode) => mode switch
	{
		ShadowPolicyMode.NoShadow => 1,
		ShadowPolicyMode.FullControlWithConsent => 2,
		ShadowPolicyMode.FullControlNoConsent => 3,
		ShadowPolicyMode.ViewWithConsent => 4,
		ShadowPolicyMode.ViewNoConsent => 5,
		_ => 0,
	};

	private static ShadowPolicyMode ShadowFromComboIndex(int index) => index switch
	{
		1 => ShadowPolicyMode.NoShadow,
		2 => ShadowPolicyMode.FullControlWithConsent,
		3 => ShadowPolicyMode.FullControlNoConsent,
		4 => ShadowPolicyMode.ViewWithConsent,
		5 => ShadowPolicyMode.ViewNoConsent,
		_ => ShadowPolicyMode.NotConfigured,
	};

	// ── Status bar ───────────────────────────────────────────────────────────────
	private void SetStatus(string message)
	{
		string stamped = string.Format(CultureInfo.InvariantCulture,
			"[{0:HH:mm:ss}Z] {1}",
			DateTime.UtcNow, message);
		if (_statusStrip.InvokeRequired)
		{
			_statusStrip.BeginInvoke(new Action(() => _statusLabel.Text = stamped));
		}
		else
		{
			_statusLabel.Text = stamped;
		}
	}
}
