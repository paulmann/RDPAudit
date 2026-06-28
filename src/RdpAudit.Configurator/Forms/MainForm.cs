// File:    src/RdpAudit.Configurator/Forms/MainForm.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Top-level WinForms shell with tab navigation across all configuration pages.
//          Async event handlers use ConfigureAwait(true) so continuations stay on the UI thread.
//
//          v2.0.0 — dark UI redesign. The shell, the owner-drawn tab strip and the status bar are
//          restyled with the shared DarkTheme palette, and every page has DarkTheme.Apply invoked on
//          it after construction so the whole Configurator matches the MikroTik tab's styling.
//          v2.2.0 — the outer tab strip uses the classic (Normal) appearance with an explicit dark
//          band paint so the light system band no longer shows behind / under the tab row.
//          v2.3.0 — version aligned with DarkTheme v2.3.0 (shared tab-strip band paint behaviour).
//          v2.4.0 — the outer tab strip is themed via DarkTabStripPainter (Win32 subclass) so the light
//                   band right of Settings / above Firewall and the wrapped-row tail are painted dark.
// Extends: System.Windows.Forms.Form
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 2.4.0

using System.Globalization;
using System.Reflection;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.Ipc;

namespace RdpAudit.Configurator.Forms;

/// <summary>Top-level WinForms shell.</summary>
[SupportedOSPlatform("windows")]
public sealed class MainForm : Form
{
	private readonly TabControl _tabs;
	private readonly IpcClient _ipc = new();
	private readonly System.Windows.Forms.Timer _statusTimer;
	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;

	public MainForm()
	{
		Text = "RdpAudit Configurator";
		Width = 1200;
		Height = 820;
		StartPosition = FormStartPosition.CenterScreen;
		BackColor = DarkTheme.PageBack;
		ForeColor = DarkTheme.TextPrimary;

		// Owner-drawn tabs: each page label is prefixed with a glyph for fast visual scanning, and the
		// selected tab is rendered bold on a highlighted background with an accent bar so the active page
		// is obvious at a glance. DrawMode=OwnerDrawFixed keeps tab sizing native (no layout shift /
		// flicker); only the per-tab paint is customized. SizeMode=Fixed gives every tab a stable width so
		// the bold selected label does not reflow neighbours. Multiline=true lets the full row of tabs wrap
		// onto additional rows instead of clipping behind scroll arrows when the window is narrow or DPI is
		// high — every page stays reachable without horizontal scrolling.
		_tabs = new TabControl
		{
			Dock = DockStyle.Fill,
			DrawMode = TabDrawMode.OwnerDrawFixed,
			// Classic (Normal) appearance: FlatButtons fills the whole tab-strip band with the light system
			// colour (the grey band reported by the user behind / under the tab row). In Normal mode the band
			// takes the control BackColor and DarkTabStripPainter (attached below) repaints the strip dark
			// so no light system band remains.
			Appearance = TabAppearance.Normal,
			SizeMode = TabSizeMode.Fixed,
			Multiline = true,
			ItemSize = new Size(160, 30),
			Padding = new Point(10, 4),
		};
		// Tab order is FIXED and MUST stay stable across releases: Overview is always first and Settings
		// is always last, with the operational pages in between in a deterministic sequence. The order is
		// built from a single explicit list (see BuildOrderedPages) so it cannot drift accidentally and is
		// covered by a unit test. The tab strip may *wrap* onto multiple rows when narrow (Multiline=true)
		// but the page sequence never changes.
		_tabs.BackColor = DarkTheme.PageBack;
		_tabs.ForeColor = DarkTheme.TextPrimary;
		foreach (TabPage page in BuildOrderedPages())
		{
			// Theme each page's full control tree once, after it is fully constructed.
			DarkTheme.Apply(page);
			_tabs.TabPages.Add(page);
		}

		_tabs.DrawItem += OnDrawTab;
		// The tab-strip header band (and its empty tail right of the last tab / wrapped-row gaps) is drawn
		// by WinForms in the light system colour and never raises a managed Paint event, so a Win32
		// subclass repaints it dark while leaving the owner-drawn tab glyphs intact.
		DarkTabStripPainter.AttachTo(_tabs, DarkTheme.PageBack);

		Controls.Add(_tabs);

		_statusStrip = new StatusStrip
		{
			BackColor = DarkTheme.StatusBack,
			ForeColor = DarkTheme.StatusFore,
		};
		_statusLabel = new ToolStripStatusLabel("Initializing...") { ForeColor = DarkTheme.StatusFore };
		_statusStrip.Items.Add(_statusLabel);
		Controls.Add(_statusStrip);

		_statusTimer = new System.Windows.Forms.Timer { Interval = 5_000 };
		_statusTimer.Tick += async (_, _) => await RefreshServiceStatusAsync().ConfigureAwait(true);
		Load += async (_, _) =>
		{
			_statusTimer.Start();
			await RefreshServiceStatusAsync().ConfigureAwait(true);
		};
		FormClosing += (_, _) => _statusTimer.Stop();
	}

	/// <summary>Builds the tab pages in their FIXED display order. Overview is always first and Settings is
	/// always last; the operational pages sit in between in a deterministic sequence. Keep this list and
	/// <see cref="OrderedPageTitles"/> in lock-step — the stable-order unit test asserts the rendered tab
	/// titles match <see cref="OrderedPageTitles"/> exactly.</summary>
	private TabPage[] BuildOrderedPages() => new TabPage[]
	{
		new OverviewPage(_ipc) { Text = "\U0001F4CA Overview" },
		new PrerequisitesPage { Text = "✅ Prerequisites" },
		new AuditPolicyPage { Text = "\U0001F4DC Audit Policy" },
		new ServicePage(_ipc) { Text = "⚙️ Service" },
		new RdpConfigurationPage(_ipc) { Text = "\U0001F5A5️ RDP Configuration" },
		new LiveEventsPage(_ipc) { Text = "\U0001F4E1 Live Events" },
		new LogsPage(_ipc) { Text = "\U0001F4DC Logs" },
		new FirewallPage(_ipc) { Text = "\U0001F6E1️ Firewall" },
		new AttackStatisticsPage(_ipc) { Text = "\U0001F4C8 RDP Activity" },
		new RemoteRdpClientsPage(_ipc) { Text = "\U0001F310 RDP Clients" },
		new AbuseIpDbPage(_ipc) { Text = "\U0001F9FE AbuseIPDB" },
		new MikroTikPage(_ipc) { Text = "\U0001F4F6 MikroTik" },
		new DiagnosticsPage(_ipc) { Text = "\U0001FA7A Diagnostic" },
		new ToolsDiagPage(_ipc) { Text = "\U0001F9EA Tools Diag" },
		new SettingsPage(_ipc) { Text = "\U0001F527 Settings" },
	};

	/// <summary>The FIXED tab titles in display order, mirroring <see cref="BuildOrderedPages"/>. Exposed so
	/// the stable-order unit test can assert the order without instantiating the live IPC-backed pages.
	/// Overview MUST be first and Settings MUST be last.</summary>
	public static IReadOnlyList<string> OrderedPageTitles { get; } = new[]
	{
		"\U0001F4CA Overview",
		"✅ Prerequisites",
		"\U0001F4DC Audit Policy",
		"⚙️ Service",
		"\U0001F5A5️ RDP Configuration",
		"\U0001F4E1 Live Events",
		"\U0001F4DC Logs",
		"\U0001F6E1️ Firewall",
		"\U0001F4C8 RDP Activity",
		"\U0001F310 RDP Clients",
		"\U0001F9FE AbuseIPDB",
		"\U0001F4F6 MikroTik",
		"\U0001FA7A Diagnostic",
		"\U0001F9EA Tools Diag",
		"\U0001F527 Settings",
	};

	/// <summary>Owner-draws a single tab header: emoji-prefixed label, with the selected tab rendered
	/// bold on a highlighted background so the active page stands out. Falls back gracefully if the
	/// index is out of range (can happen transiently during tab mutation).</summary>
	private void OnDrawTab(object? sender, DrawItemEventArgs e)
	{
		if (e.Index < 0 || e.Index >= _tabs.TabPages.Count)
		{
			return;
		}

		TabPage page = _tabs.TabPages[e.Index];
		bool selected = e.Index == _tabs.SelectedIndex;
		Rectangle bounds = e.Bounds;

		// v2.0.0 — dark tab strip: unselected tabs sit on the page background, the selected tab is
		// raised onto a lighter surface with a bright accent bar so the active page is obvious.
		Color back = selected ? DarkTheme.TabSelectedBack : DarkTheme.TabBack;
		Color fore = selected ? DarkTheme.AccentHeader : DarkTheme.TextPrimary;

		using (SolidBrush backBrush = new(back))
		{
			e.Graphics.FillRectangle(backBrush, bounds);
		}

		// A thick accent bar along the top edge of the selected tab gives the active page a strong,
		// glanceable cue on the dark surface.
		if (selected)
		{
			using SolidBrush accentBrush = new(DarkTheme.TabAccent);
			e.Graphics.FillRectangle(accentBrush, bounds.Left, bounds.Top, bounds.Width, 4);
		}

		using Font font = new(Font, selected ? FontStyle.Bold : FontStyle.Regular);
		TextRenderer.DrawText(
			e.Graphics,
			page.Text,
			font,
			bounds,
			fore,
			TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
	}

	private async Task RefreshServiceStatusAsync()
	{
		try
		{
			IpcCallResult<ServiceStatus> call =
				await _ipc.SendDetailedAsync<ServiceStatus>(IpcCommand.GetStatus).ConfigureAwait(true);

			if (call.IsSuccess && call.Value is { } status)
			{
				string baseLine = string.Format(CultureInfo.InvariantCulture,
					"Service v{0} | uptime {1:hh\\:mm\\:ss} | events {2} (dropped {3}) | alerts {4}",
					status.Version, status.Uptime, status.EventsCaptured, status.EventsDropped, status.AlertsRaised);

				// Warn prominently when the running service was built from a different version than this
				// Configurator — the most common cause of "I fixed it but nothing changed" is launching a
				// freshly built Configurator against a stale installed service that was never re-published.
				string mismatch = DescribeVersionMismatch(status.Version);
				_statusLabel.Text = mismatch.Length == 0 ? baseLine : baseLine + "  ⚠ " + mismatch;
				_statusLabel.ForeColor = mismatch.Length == 0 ? DarkTheme.StatusFore : DarkTheme.StatusDanger;
			}
			else
			{
				// Distinguish a stopped service from a busy one rather than the blanket "not reachable".
				_statusLabel.Text = "Service: " + call.Headline();
				_statusLabel.ForeColor = call.ServiceLikelyReachable ? DarkTheme.StatusFore : DarkTheme.StatusDanger;
			}
		}
		catch (Exception ex)
		{
			_statusLabel.Text = $"Service: error — {ex.GetType().Name}";
			_statusLabel.ForeColor = DarkTheme.StatusDanger;
		}
	}

	/// <summary>Returns a short warning when the running service's version differs from this Configurator's
	/// own version, else an empty string. Compares the bare SemVer (build-metadata "+sha" suffix trimmed),
	/// so a SHA difference on the same version is not flagged here — the Service tab diagnostics report
	/// performs the deeper SHA / fingerprint comparison.</summary>
	private static string DescribeVersionMismatch(string? serviceVersion)
	{
		if (string.IsNullOrWhiteSpace(serviceVersion))
		{
			return string.Empty;
		}

		string configurator = ResolveConfiguratorVersion();
		string serviceSemVer = TrimBuildMetadata(serviceVersion);
		if (string.Equals(configurator, serviceSemVer, StringComparison.OrdinalIgnoreCase))
		{
			return string.Empty;
		}

		return string.Format(CultureInfo.InvariantCulture,
			"VERSION MISMATCH: Configurator {0} vs Service {1} — the running service is likely a stale build. Re-publish & restart the service.",
			configurator, serviceSemVer);
	}

	private static string ResolveConfiguratorVersion()
	{
		System.Reflection.Assembly asm = typeof(MainForm).Assembly;
		string? info = asm
			.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		if (!string.IsNullOrWhiteSpace(info))
		{
			return TrimBuildMetadata(info);
		}

		return asm.GetName().Version?.ToString() ?? "0.0.0";
	}

	private static string TrimBuildMetadata(string version)
	{
		int plus = version.IndexOf('+', StringComparison.Ordinal);
		return plus > 0 ? version[..plus] : version;
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_statusTimer.Dispose();
		}

		base.Dispose(disposing);
	}
}
