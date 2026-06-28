// File:    src/RdpAudit.Configurator/Forms/MikroTikPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Stage 9 MikroTik Configurator tab. Lets the operator configure the RouterOS v7 REST
//          endpoint (scheme/host/port, username, password with show toggle), the firewall filter
//          chain/action, the block duration (days/hours/minutes), the TLS certificate validation
//          flag, the AddAttackerRules toggle, and persist them via the service IPC (which DPAPI-
//          protects the password before persistence). Buttons: Save settings, Test connection,
//          Refresh status. The status panel surfaces configuration/enabled state, the resolved
//          endpoint, active MikroTik block count, last probe result, and any controlled error.
//          The page never displays the plaintext password — only a "configured / not configured"
//          state. All UI strings are English-only.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json.Nodes;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Stage 9 MikroTik Configurator tab.</summary>
[SupportedOSPlatform("windows")]
public sealed class MikroTikPage : TabPage
{
	private const string MaskedPlaceholder = "***configured***";

	private const string IntroText =
		"MikroTik RouterOS v7 REST API integration. When enabled, the RdpAudit service inserts and "
		+ "removes firewall filter rules on the router for attacker IPs, with a comment that starts "
		+ "with the configured CommentPrefix so removal is restricted to RdpAudit-owned rules.\r\n\r\n"
		+ "Security:\r\n"
		+ "  • The password is encrypted at rest via Windows DPAPI before persistence.\r\n"
		+ "  • Only firewall rules whose comment starts with the configured CommentPrefix are ever deleted.\r\n"
		+ "  • Existing matching rules are reused (idempotent), never duplicated.\r\n"
		+ "  • TLS certificate validation is on by default — disable only for lab use.";

	/// <summary>Copy-paste-ready RouterOS v7 shell command bundle used by the Stage A
	/// <c>Copy commands</c> button. Sourced from <see cref="MikroTikSetupCommands"/> so the bundle
	/// is unit-tested in <c>RdpAudit.Core.Tests</c> for placeholder presence and absence of any
	/// embedded secret values.</summary>
	internal static readonly string RouterOsSetupCommands = MikroTikSetupCommands.BuildAll();

	private readonly IpcClient _ipc;

	private readonly TextBox _intro;
	private readonly TextBox _setupCommands;
	private readonly Button _copyCommandsButton;
	private readonly TextBox _hostInput;
	private readonly NumericUpDown _portInput;
	private readonly CheckBox _useHttpsInput;
	private readonly CheckBox _validateCertInput;
	private readonly TextBox _userNameInput;
	private readonly TextBox _passwordInput;
	private readonly CheckBox _showPasswordInput;
	private readonly TextBox _chainInput;
	private readonly TextBox _actionInput;
	private readonly TextBox _commentPrefixInput;
	private readonly NumericUpDown _durationDaysInput;
	private readonly NumericUpDown _durationHoursInput;
	private readonly NumericUpDown _durationMinutesInput;
	private readonly CheckBox _addRulesInput;
	private readonly CheckBox _enabledInput;
	private readonly Button _saveButton;
	private readonly Button _testButton;
	private readonly Button _refreshButton;
	private readonly Label _statusLabel;
	private readonly Label _configuredLabel;
	private readonly Label _endpointLabel;
	private readonly Label _providerStatusLabel;
	private readonly Label _activeBlocksLabel;
	private readonly Label _lastResultLabel;

	private bool _credentialPresentOnService;
	private bool _configuredOnService;

	public MikroTikPage(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		Text = "MikroTik";

		_intro = new TextBox
		{
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Vertical,
			Dock = DockStyle.Top,
			Height = 120,
			Text = IntroText,
			WordWrap = true,
			BackColor = SystemColors.Info,
		};

		_setupCommands = new TextBox
		{
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Both,
			Dock = DockStyle.Top,
			Height = 220,
			Text = RouterOsSetupCommands,
			WordWrap = false,
			Font = new Font(FontFamily.GenericMonospace, 9.5f),
			BackColor = SystemColors.Window,
		};

		_copyCommandsButton = new Button
		{
			Text = "Copy commands",
			Dock = DockStyle.Top,
			Height = 30,
		};
		_copyCommandsButton.Click += (_, _) => OnCopyCommands();

		_hostInput = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "router host name or IP literal" };
		_portInput = new NumericUpDown { Dock = DockStyle.Fill, Minimum = 0, Maximum = 65535, Value = 0 };
		_useHttpsInput = new CheckBox { Text = "Use HTTPS", AutoSize = true, Checked = true };
		_validateCertInput = new CheckBox { Text = "Validate TLS certificate", AutoSize = true, Checked = true };
		_userNameInput = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "router user name" };
		_passwordInput = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true, PlaceholderText = "router password" };
		_showPasswordInput = new CheckBox { Text = "Show password", AutoSize = true };
		_showPasswordInput.CheckedChanged += (_, _) => _passwordInput.UseSystemPasswordChar = !_showPasswordInput.Checked;
		_chainInput = new TextBox { Dock = DockStyle.Fill, Text = "input" };
		_actionInput = new TextBox { Dock = DockStyle.Fill, Text = "drop" };
		_commentPrefixInput = new TextBox { Dock = DockStyle.Fill, Text = "RdpAudit" };

		_durationDaysInput = new NumericUpDown { Dock = DockStyle.Fill, Minimum = 0, Maximum = 365, Value = 0 };
		_durationHoursInput = new NumericUpDown { Dock = DockStyle.Fill, Minimum = 0, Maximum = 24, Value = 1 };
		_durationMinutesInput = new NumericUpDown { Dock = DockStyle.Fill, Minimum = 0, Maximum = 59, Value = 0 };

		_addRulesInput = new CheckBox
		{
			Text = "Add attacker IP block rules to MikroTik Firewall",
			AutoSize = true,
			Enabled = false,
		};
		_enabledInput = new CheckBox
		{
			Text = "Enable MikroTik integration",
			AutoSize = true,
			Enabled = false,
		};

		_saveButton = new Button { Text = "Save settings", Width = 140 };
		_saveButton.Click += async (_, _) => await OnSaveAsync().ConfigureAwait(true);
		_testButton = new Button { Text = "Test connection", Width = 140, Enabled = false };
		_testButton.Click += async (_, _) => await OnTestAsync().ConfigureAwait(true);
		_refreshButton = new Button { Text = "Refresh status", Width = 140 };
		_refreshButton.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_statusLabel = new Label { Text = "Loading…", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_configuredLabel = new Label { Text = "Configuration: ?", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_endpointLabel = new Label { Text = "Endpoint: ?", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_providerStatusLabel = new Label { Text = "Provider: ?", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_activeBlocksLabel = new Label { Text = "Active MikroTik blocks: 0", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_lastResultLabel = new Label { Text = "Last result: (none)", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };

		Panel statusPanel = BuildStatusPanel();
		Panel formPanel = BuildFormPanel();

		// Docked panels: last-added control sits closest to the top edge.
		Controls.Add(formPanel);
		Controls.Add(statusPanel);
		Controls.Add(_copyCommandsButton);
		Controls.Add(_setupCommands);
		Controls.Add(_intro);

		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	private void OnCopyCommands()
	{
		try
		{
			Clipboard.SetText(RouterOsSetupCommands);
			_statusLabel.Text = string.Format(CultureInfo.InvariantCulture,
				"[{0:HH:mm:ss}Z] Copied RouterOS setup commands to clipboard ({1} chars).",
				DateTime.UtcNow, RouterOsSetupCommands.Length);
		}
		catch (Exception ex)
		{
			_statusLabel.Text = "Copy commands FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
	}

	private Panel BuildFormPanel()
	{
		Panel panel = new() { Dock = DockStyle.Top, Height = 380, Padding = new Padding(8) };

		TableLayoutPanel layout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 4,
			RowCount = 11,
		};
		layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
		layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
		layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
		layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
		for (int i = 0; i < 11; i++)
		{
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
		}

		layout.Controls.Add(LabelFor("Host / IP:"), 0, 0);
		layout.Controls.Add(_hostInput, 1, 0);
		layout.Controls.Add(LabelFor("Port (0 = default):"), 2, 0);
		layout.Controls.Add(_portInput, 3, 0);

		layout.Controls.Add(LabelFor("Scheme:"), 0, 1);
		layout.Controls.Add(_useHttpsInput, 1, 1);
		layout.Controls.Add(LabelFor("TLS:"), 2, 1);
		layout.Controls.Add(_validateCertInput, 3, 1);

		layout.Controls.Add(LabelFor("Username:"), 0, 2);
		layout.Controls.Add(_userNameInput, 1, 2);

		layout.Controls.Add(LabelFor("Password:"), 0, 3);
		layout.Controls.Add(_passwordInput, 1, 3);
		layout.Controls.Add(_showPasswordInput, 2, 3);

		layout.Controls.Add(LabelFor("Filter chain:"), 0, 4);
		layout.Controls.Add(_chainInput, 1, 4);
		layout.Controls.Add(LabelFor("Action:"), 2, 4);
		layout.Controls.Add(_actionInput, 3, 4);

		layout.Controls.Add(LabelFor("Comment prefix:"), 0, 5);
		layout.Controls.Add(_commentPrefixInput, 1, 5);

		layout.Controls.Add(LabelFor("Block duration days:"), 0, 6);
		layout.Controls.Add(_durationDaysInput, 1, 6);
		layout.Controls.Add(LabelFor("hours:"), 2, 6);
		layout.Controls.Add(_durationHoursInput, 3, 6);

		layout.Controls.Add(LabelFor("Block duration minutes:"), 0, 7);
		layout.Controls.Add(_durationMinutesInput, 1, 7);

		layout.Controls.Add(_addRulesInput, 1, 8);
		layout.SetColumnSpan(_addRulesInput, 3);

		layout.Controls.Add(_enabledInput, 1, 9);
		layout.SetColumnSpan(_enabledInput, 3);

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight };
		buttons.Controls.Add(_saveButton);
		buttons.Controls.Add(_testButton);
		buttons.Controls.Add(_refreshButton);
		layout.Controls.Add(buttons, 1, 10);
		layout.SetColumnSpan(buttons, 3);

		panel.Controls.Add(layout);
		return panel;
	}

	private Panel BuildStatusPanel()
	{
		Panel panel = new() { Dock = DockStyle.Top, Height = 150, Padding = new Padding(8) };

		TableLayoutPanel layout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 1,
			RowCount = 6,
		};
		for (int i = 0; i < 6; i++)
		{
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
		}

		layout.Controls.Add(_configuredLabel, 0, 0);
		layout.Controls.Add(_endpointLabel, 0, 1);
		layout.Controls.Add(_providerStatusLabel, 0, 2);
		layout.Controls.Add(_activeBlocksLabel, 0, 3);
		layout.Controls.Add(_lastResultLabel, 0, 4);
		layout.Controls.Add(_statusLabel, 0, 5);

		panel.Controls.Add(layout);
		return panel;
	}

	private static Label LabelFor(string text) => new()
	{
		Text = text,
		Dock = DockStyle.Fill,
		TextAlign = ContentAlignment.MiddleLeft,
	};

	private async Task RefreshAsync()
	{
		_refreshButton.Enabled = false;
		try
		{
			MikroTikStatusDto? status = await _ipc
				.SendAsync<MikroTikStatusDto>(IpcCommand.GetMikroTikStatus)
				.ConfigureAwait(true);

			if (status is null)
			{
				_statusLabel.Text = "Service unreachable.";
				_configuredLabel.Text = "Configuration: ?";
				_endpointLabel.Text = "Endpoint: ?";
				_providerStatusLabel.Text = "Provider: ?";
				_activeBlocksLabel.Text = "Active MikroTik blocks: ?";
				_lastResultLabel.Text = "Last result: ?";
				_enabledInput.Enabled = false;
				_addRulesInput.Enabled = false;
				_testButton.Enabled = false;
				return;
			}

			_configuredOnService = status.Configured;
			_credentialPresentOnService = status.CredentialPresent;

			_configuredLabel.Text = string.Format(CultureInfo.InvariantCulture,
				"Configuration: {0} | Credential: {1} | Enabled: {2} | AddRules: {3}",
				status.Configured ? "Configured" : "Not configured",
				status.CredentialPresent ? "Configured (encrypted at rest)" : "Not configured",
				status.Enabled ? "yes" : "no",
				status.AddAttackerRules ? "yes" : "no");
			_endpointLabel.Text = "Endpoint: " + (string.IsNullOrEmpty(status.Endpoint) ? "(unset)" : status.Endpoint);
			_providerStatusLabel.Text = "Provider: " + status.ProviderStatus
				+ (string.IsNullOrEmpty(status.LastError) ? string.Empty : " | last error: " + status.LastError);
			_activeBlocksLabel.Text = string.Format(CultureInfo.InvariantCulture,
				"Active MikroTik blocks: {0} | chain={1} action={2} duration={3}s prefix='{4}' validateTls={5}",
				status.ActiveBlockCount,
				status.FilterChain,
				status.FilterAction,
				status.BlockDurationSeconds,
				status.CommentPrefix,
				status.ValidateServerCertificate ? "yes" : "no");
			_lastResultLabel.Text = string.IsNullOrEmpty(status.Message) ? "Last result: (none)" : "Last result: " + status.Message;

			// Populate inputs that don't carry secrets from the latest service-side state.
			if (!string.IsNullOrEmpty(status.Host))
			{
				_hostInput.Text = status.Host;
			}
			if (status.Port >= 0 && status.Port <= 65535)
			{
				_portInput.Value = status.Port;
			}
			_useHttpsInput.Checked = string.IsNullOrEmpty(status.Scheme)
				? _useHttpsInput.Checked
				: string.Equals(status.Scheme, "https", StringComparison.OrdinalIgnoreCase);
			_validateCertInput.Checked = status.ValidateServerCertificate;
			if (!string.IsNullOrEmpty(status.FilterChain))
			{
				_chainInput.Text = status.FilterChain;
			}
			if (!string.IsNullOrEmpty(status.FilterAction))
			{
				_actionInput.Text = status.FilterAction;
			}
			if (!string.IsNullOrEmpty(status.CommentPrefix))
			{
				_commentPrefixInput.Text = status.CommentPrefix;
			}

			// Test and Enabled toggles are only meaningful once host+credentials are present.
			_testButton.Enabled = status.Configured;
			_addRulesInput.Enabled = status.Configured;
			_addRulesInput.Checked = status.AddAttackerRules;
			_enabledInput.Enabled = status.Configured;
			_enabledInput.Checked = status.Enabled;

			_statusLabel.Text = "Status loaded.";
		}
		catch (Exception ex)
		{
			_statusLabel.Text = "Refresh FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
		finally
		{
			_refreshButton.Enabled = true;
		}
	}

	private async Task OnSaveAsync()
	{
		_saveButton.Enabled = false;
		_statusLabel.Text = "Saving settings…";

		try
		{
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			JsonObject root;
			JsonObject section;
			if (settings is JsonObject obj)
			{
				section = obj;
				root = new JsonObject { [Core.Config.RdpAuditOptions.SectionName] = section.DeepClone() };
				section = (JsonObject)root[Core.Config.RdpAuditOptions.SectionName]!;
			}
			else
			{
				root = new JsonObject { [Core.Config.RdpAuditOptions.SectionName] = new JsonObject() };
				section = (JsonObject)root[Core.Config.RdpAuditOptions.SectionName]!;
			}

			if (section["MikroTik"] is not JsonObject mt)
			{
				mt = new JsonObject();
				section["MikroTik"] = mt;
			}

			mt["Host"] = _hostInput.Text?.Trim() ?? string.Empty;
			mt["Port"] = (int)_portInput.Value;
			mt["UseHttps"] = _useHttpsInput.Checked;
			mt["ValidateServerCertificate"] = _validateCertInput.Checked;
			mt["UserName"] = _userNameInput.Text?.Trim() ?? string.Empty;
			mt["FilterChain"] = string.IsNullOrWhiteSpace(_chainInput.Text) ? "input" : _chainInput.Text.Trim();
			mt["FilterAction"] = string.IsNullOrWhiteSpace(_actionInput.Text) ? "drop" : _actionInput.Text.Trim();
			mt["CommentPrefix"] = string.IsNullOrWhiteSpace(_commentPrefixInput.Text) ? "RdpAudit" : _commentPrefixInput.Text.Trim();
			mt["BlockDurationDays"] = (int)_durationDaysInput.Value;
			mt["BlockDurationHours"] = (int)_durationHoursInput.Value;
			mt["BlockDurationMinutes"] = (int)_durationMinutesInput.Value;
			mt["AddAttackerRules"] = _addRulesInput.Checked;
			mt["Enabled"] = _enabledInput.Checked;

			string newPassword = _passwordInput.Text ?? string.Empty;
			if (newPassword.Length > 0 && !string.Equals(newPassword, MaskedPlaceholder, StringComparison.Ordinal))
			{
				mt["Password"] = newPassword;
			}

			object? response = await _ipc
				.SendAsync<object>(IpcCommand.SaveSettings, root.ToJsonString(JsonOptions.Default))
				.ConfigureAwait(true);

			if (response is null)
			{
				_statusLabel.Text = "Save FAILED: service unreachable.";
				return;
			}

			_passwordInput.Clear();
			_statusLabel.Text = "Settings saved. The router password is encrypted at rest via DPAPI.";
			await RefreshAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			_statusLabel.Text = "Save FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
		finally
		{
			_saveButton.Enabled = true;
		}
	}

	private async Task OnTestAsync()
	{
		_testButton.Enabled = false;
		_statusLabel.Text = "Testing MikroTik connection…";
		try
		{
			MikroTikTestResult? result = await _ipc
				.SendAsync<MikroTikTestResult>(IpcCommand.TestMikroTik)
				.ConfigureAwait(true);
			if (result is null)
			{
				_statusLabel.Text = "Test FAILED: service unreachable.";
				return;
			}

			StringBuilder sb = new();
			sb.Append("Test status=").Append(result.Status).Append(". ");
			sb.Append("Credential format ").Append(result.CredentialFormatValid ? "OK" : "FAILED").Append(". ");
			if (result.ResponseCode > 0)
			{
				sb.Append("HTTP ").Append(result.ResponseCode.ToString(CultureInfo.InvariantCulture)).Append(". ");
			}
			sb.Append("Remote verified: ").Append(result.RemoteVerified ? "yes" : "no").Append(". ");
			if (!string.IsNullOrEmpty(result.Endpoint))
			{
				sb.Append("Endpoint=").Append(result.Endpoint).Append(". ");
			}
			sb.Append(result.Message);
			_statusLabel.Text = sb.ToString();
		}
		catch (Exception ex)
		{
			_statusLabel.Text = "Test FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
		finally
		{
			_testButton.Enabled = _configuredOnService && _credentialPresentOnService;
		}
	}
}
