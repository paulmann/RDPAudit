/*
 * File   : ConnectionPanel.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Top connection bar of the wizard: router IP (pre-filled from GatewayDetector), SSH and
 *          api-ssl ports, the bootstrap admin credentials, and Probe / status controls. It owns no
 *          router logic — it raises ProbeRequested with the entered endpoint and renders the summary
 *          handed back by the host form.
 * Depends: System.Windows.Forms, DarkTheme, GatewayDetector, ConnectionProbeSummary
 * Extends: To capture another connection parameter, add a labelled input here and expose it through a
 *          property; surface it in the ConnectionEndpoint record consumed by the host form.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.1
 */

using System.Drawing;
using System.Globalization;
using System.Windows.Forms;
using RdpAudit.Mikrotik.Core;
using RdpAudit.Mikrotik.Helpers;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>The endpoint and bootstrap credentials entered by the operator.</summary>
/// <param name="RouterIp">Router management IP.</param>
/// <param name="SshPort">SSH port for bootstrap.</param>
/// <param name="ApiSslPort">api-ssl port for production.</param>
/// <param name="AdminUsername">Bootstrap admin user.</param>
/// <param name="AdminPassword">Bootstrap admin password.</param>
public sealed record ConnectionEndpoint(string RouterIp, int SshPort, int ApiSslPort, string AdminUsername, string AdminPassword);

/// <summary>Top connection bar with endpoint inputs and a probe action.</summary>
public sealed class ConnectionPanel : Panel
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly TextBox _ipBox = new();
	private readonly TextBox _sshPortBox = new() { Text = "22" };
	private readonly TextBox _apiSslPortBox = new() { Text = "8729" };
	private readonly TextBox _userBox = new() { Text = "admin" };
	private readonly TextBox _passwordBox = new() { UseSystemPasswordChar = true };
	private readonly Button _probeButton = new() { Text = "Probe" };
	private readonly Label _statusLabel = new() { Text = "Enter the router IP and probe to begin." };

	// ── Construction ─────────────────────────────────────────────────────────────

	public ConnectionPanel()
	{
		Dock = DockStyle.Top;
		Height = 96;
		DarkTheme.ApplyContainer(this);
		BackColor = DarkTheme.SurfaceRaised;
		Padding = new Padding(16, 10, 16, 10);
		BuildLayout();
		PrefillGateway();
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Raised when the operator clicks Probe with a valid endpoint.</summary>
	public event EventHandler<ProbeRequestedEventArgs>? ProbeRequested;

	/// <summary>Returns the currently entered endpoint, or null when the input is invalid.</summary>
	public ConnectionEndpoint? CurrentEndpoint => TryReadEndpoint(out ConnectionEndpoint? ep) ? ep : null;

	/// <summary>Renders a probe summary line in the status label.</summary>
	public void ShowProbeSummary(ConnectionProbeSummary summary)
	{
		ArgumentNullException.ThrowIfNull(summary);
		_statusLabel.ForeColor = summary.ApiSslAvailable || summary.SshAvailable ? DarkTheme.Success : DarkTheme.Danger;
		_statusLabel.Text = summary.Recommendation;
	}

	/// <summary>Shows a plain status message.</summary>
	public void ShowStatus(string message, bool isError = false)
	{
		_statusLabel.ForeColor = isError ? DarkTheme.Danger : DarkTheme.SubtleText;
		_statusLabel.Text = message;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private void BuildLayout()
	{
		TableLayoutPanel grid = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 6,
			RowCount = 2,
			BackColor = DarkTheme.SurfaceRaised,
		};
		grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 200));
		grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
		grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
		grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
		grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
		grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

		foreach (TextBox box in new[] { _ipBox, _sshPortBox, _apiSslPortBox, _userBox, _passwordBox })
		{
			DarkTheme.StyleTextBox(box);
			box.Dock = DockStyle.Fill;
			box.Margin = new Padding(3, 2, 3, 2);
		}

		DarkTheme.StyleAccentButton(_probeButton);
		_probeButton.Dock = DockStyle.Fill;
		_probeButton.Margin = new Padding(3, 2, 3, 2);
		_probeButton.Click += OnProbeClicked;

		grid.Controls.Add(MakeLabel("Router IP"), 0, 0);
		grid.Controls.Add(MakeLabel("SSH port"), 1, 0);
		grid.Controls.Add(MakeLabel("api-ssl port"), 2, 0);
		grid.Controls.Add(MakeLabel("Admin user"), 3, 0);
		grid.Controls.Add(MakeLabel("Admin password"), 4, 0);

		grid.Controls.Add(_ipBox, 0, 1);
		grid.Controls.Add(_sshPortBox, 1, 1);
		grid.Controls.Add(_apiSslPortBox, 2, 1);
		grid.Controls.Add(_userBox, 3, 1);
		grid.Controls.Add(_passwordBox, 4, 1);
		grid.Controls.Add(_probeButton, 5, 1);

		_statusLabel.ForeColor = DarkTheme.SubtleText;
		_statusLabel.Dock = DockStyle.Fill;
		_statusLabel.TextAlign = ContentAlignment.MiddleLeft;
		grid.Controls.Add(_statusLabel, 5, 0);

		Controls.Add(grid);
	}

	private static Label MakeLabel(string text) => new()
	{
		Text = text,
		ForeColor = DarkTheme.SubtleText,
		Dock = DockStyle.Fill,
		TextAlign = ContentAlignment.MiddleLeft,
		Font = DarkTheme.BaseFont,
	};

	private void PrefillGateway()
	{
		string? gateway = new GatewayDetector().DetectPrimaryGatewayIp();
		if (!string.IsNullOrWhiteSpace(gateway))
		{
			_ipBox.Text = gateway;
		}
	}

	private void OnProbeClicked(object? sender, EventArgs e)
	{
		if (TryReadEndpoint(out ConnectionEndpoint? endpoint) && endpoint is not null)
		{
			ProbeRequested?.Invoke(this, new ProbeRequestedEventArgs(endpoint));
		}
		else
		{
			ShowStatus("Enter a valid router IP and numeric ports.", isError: true);
		}
	}

	private bool TryReadEndpoint(out ConnectionEndpoint? endpoint)
	{
		endpoint = null;
		string ip = _ipBox.Text.Trim();
		if (string.IsNullOrWhiteSpace(ip))
		{
			return false;
		}
		if (!int.TryParse(_sshPortBox.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int sshPort) || sshPort <= 0)
		{
			return false;
		}
		if (!int.TryParse(_apiSslPortBox.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int apiPort) || apiPort <= 0)
		{
			return false;
		}

		endpoint = new ConnectionEndpoint(ip, sshPort, apiPort, _userBox.Text.Trim(), _passwordBox.Text);
		return true;
	}
}
