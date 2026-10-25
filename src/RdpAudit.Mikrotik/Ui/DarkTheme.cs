/*
 * File   : DarkTheme.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Centralised dark-theme palette and styling helpers for the MikroTik wizard. Every panel
 *          and control pulls its colours and fonts from here so the UI stays consistent and a future
 *          theme change is a single-file edit. Palette: Catppuccin-inspired (bg #1E1E2E, text
 *          #CDD6F4, accent #89B4FA) at Segoe UI 9pt.
 * Depends: System.Drawing.Color, System.Windows.Forms.Control
 * Extends: To add a new semantic colour (e.g. a distinct disabled tint), add a static Color here and
 *          a styling helper; never hard-code a Color literal inside a panel.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Drawing;
using System.Windows.Forms;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>Centralised dark-theme palette and styling helpers.</summary>
public static class DarkTheme
{
	// ── Public API ───────────────────────────────────────────────────────────────

	public static readonly Color Background = Color.FromArgb(0x1E, 0x1E, 0x2E);
	public static readonly Color Surface = Color.FromArgb(0x28, 0x28, 0x3C);
	public static readonly Color SurfaceRaised = Color.FromArgb(0x31, 0x32, 0x44);
	public static readonly Color Text = Color.FromArgb(0xCD, 0xD6, 0xF4);
	public static readonly Color SubtleText = Color.FromArgb(0x93, 0x99, 0xB2);
	public static readonly Color Accent = Color.FromArgb(0x89, 0xB4, 0xFA);
	public static readonly Color Success = Color.FromArgb(0xA6, 0xE3, 0xA1);
	public static readonly Color Warning = Color.FromArgb(0xF9, 0xE2, 0xAF);
	public static readonly Color Danger = Color.FromArgb(0xF3, 0x8B, 0xA8);
	public static readonly Color Border = Color.FromArgb(0x45, 0x47, 0x5A);

	// Availability colours — the same contract as the Configurator palette so both surfaces of the
	// product read identically: an available command button carries a sober green, an unavailable one
	// a sober dark red. Desaturated on purpose, so they state availability rather than alarm.
	public static readonly Color ButtonAvailable = Color.FromArgb(0x2F, 0x6F, 0x4F);
	public static readonly Color ButtonAvailableHover = Color.FromArgb(0x3D, 0x8A, 0x63);
	public static readonly Color ButtonUnavailable = Color.FromArgb(0x7A, 0x2A, 0x2A);
	public static readonly Color ButtonUnavailableBorder = Color.FromArgb(0x8F, 0x3A, 0x3A);

	/// <summary>Marker stored in a button's Tag recording that availability tracking is installed, so a
	/// re-style never double-subscribes.</summary>
	private const string ButtonStateTag = "Mikrotik.DarkTheme.Button";

	public static Font BaseFont { get; } = new("Segoe UI", 9f, FontStyle.Regular);
	public static Font HeadingFont { get; } = new("Segoe UI Semibold", 12f, FontStyle.Bold);
	public static Font SubheadingFont { get; } = new("Segoe UI Semibold", 10f, FontStyle.Bold);
	public static Font MonoFont { get; } = new("Cascadia Mono", 9f, FontStyle.Regular);

	/// <summary>Applies the base background/foreground/font to a form or container control.</summary>
	public static void ApplyContainer(Control control)
	{
		ArgumentNullException.ThrowIfNull(control);
		control.BackColor = Background;
		control.ForeColor = Text;
		control.Font = BaseFont;
	}

	/// <summary>Styles a primary action button and paints its face for the CURRENT availability: a sober
	/// green while the action can be used, a sober dark red while it cannot. Availability changes repaint
	/// the button automatically (including a parent panel being disabled), so a panel only flips
	/// <c>Enabled</c> and never touches colours.</summary>
	public static void StyleAccentButton(Button button)
	{
		ArgumentNullException.ThrowIfNull(button);
		button.FlatStyle = FlatStyle.Flat;
		button.FlatAppearance.BorderSize = 1;
		button.Font = SubheadingFont;
		button.Cursor = Cursors.Hand;
		button.Height = 34;

		button.Tag = ButtonStateTag;
		button.EnabledChanged -= OnButtonEnabledChanged;
		button.EnabledChanged += OnButtonEnabledChanged;
		ApplyButtonAvailability(button);
	}

	/// <summary>The face a command button paints for the given availability. Pure function so the contract
	/// is pinnable by a test without constructing a form.</summary>
	internal static Color ButtonBackFor(bool available) => available ? ButtonAvailable : ButtonUnavailable;

	/// <summary>Paints the availability face, border accent and text colour of a command button. An
	/// unavailable button never lights up under the pointer.</summary>
	internal static void ApplyButtonAvailability(Button button)
	{
		ArgumentNullException.ThrowIfNull(button);
		bool available = button.Enabled;
		Color face = ButtonBackFor(available);
		Color accent = available ? ButtonAvailableHover : ButtonUnavailableBorder;

		button.BackColor = face;
		button.ForeColor = available ? Background : Text;
		button.FlatAppearance.BorderColor = accent;
		button.FlatAppearance.MouseOverBackColor = accent;
		button.FlatAppearance.MouseDownBackColor = accent;
	}

	private static void OnButtonEnabledChanged(object? sender, EventArgs e)
	{
		if (sender is Button button && button.Tag as string == ButtonStateTag)
		{
			ApplyButtonAvailability(button);
		}
	}

	/// <summary>Styles a text input with the surface colour and subtle border.</summary>
	public static void StyleTextBox(TextBox textBox)
	{
		ArgumentNullException.ThrowIfNull(textBox);
		textBox.BackColor = Surface;
		textBox.ForeColor = Text;
		textBox.BorderStyle = BorderStyle.FixedSingle;
		textBox.Font = BaseFont;
	}

	/// <summary>Styles a label as a section heading.</summary>
	public static void StyleHeading(Label label)
	{
		ArgumentNullException.ThrowIfNull(label);
		label.ForeColor = Text;
		label.Font = HeadingFont;
		label.AutoSize = true;
	}
}
