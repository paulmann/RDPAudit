// File:    src/RdpAudit.Configurator/Theming/DarkTheme.cs
// Module:  RdpAudit.Configurator.Theming
// Purpose: Single source of truth for the Configurator's dark-blue visual language. Holds the shared
//          colour palette (Catppuccin Mocha) and exposes a recursive Apply(Control) that themes any
//          WinForms control tree — Panels, Labels, LinkLabels, Buttons, TextBoxes, ComboBoxes,
//          CheckBoxes, RadioButtons, NumericUpDowns, GroupBoxes, DataGridViews, ListViews, TreeViews,
//          TabControls, StatusStrips, ToolStrips and the ContextMenuStrips attached to controls — so
//          every tab inherits the same look without per-page rewrites. Also provides StyleGrid /
//          StyleButton / StyleMenu helpers, owner-draw for check/radio indicators (bright-green so the
//          checked state is unmistakable on the dark surface), a dark ToolStrip/menu renderer, and
//          semantic status colours that stay legible on the dark background.
//
//          v2.0.0 — introduced as part of the full-Configurator dark redesign.
//          v2.1.0 — repalette to Catppuccin Mocha (dark blue) matching the MikroTik setup module.
//          v2.2.0 — square accent buttons (no rounded region); every button that is not a recognised
//                   Danger/Success face is forced to the single accent blue from one place; check boxes
//                   and radio buttons are owner-drawn with a bright-green indicator so the selected
//                   state reads on the dark surface; every control's ContextMenuStrip is themed by the
//                   recursive Apply (fixes the grey right-click menus on Service / Live Events / Firewall
//                   / RDP Activity); nested TabControls size tabs to their text (fixes the truncated
//                   "Whitel.." Firewall sub-tab) and drop the grey strip band.
//          v2.3.0 — nested TabControls use the classic (Normal) appearance and paint their strip band /
//                   page-area edge dark via OnPaintTabStripBand, so no light system band remains behind or
//                   under the Blocklist / Whitelist sub-tab row.
//          v2.4.0 — the managed Paint approach could not reach the tab-strip header band, so strip
//                   theming now goes through DarkTabStripPainter (a Win32 NativeWindow subclass) which
//                   fills every non-tab region of the strip dark, finally removing the light tail right of
//                   the last tab and the band under the Blocklist / Whitelist rows.
// Depends: System.Windows.Forms, System.Drawing
// Extends: To add a new themed control type, add a branch in ApplyToControl. To tweak the palette,
//          change the static Color fields here — every tab picks the change up automatically. To add a
//          new semantic status colour, add a static field and use it from page CellFormatting code.
//
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 2.4.0

using System.Runtime.Versioning;

namespace RdpAudit.Configurator.Theming;

/// <summary>Centralised dark-blue theme: palette, recursive control theming, grid/button/menu helpers,
/// owner-drawn check/radio indicators, a dark ToolStrip renderer, and semantic status colours. All
/// members are static — the theme is stateless.</summary>
[SupportedOSPlatform("windows")]
public static class DarkTheme
{
	// ── Constants ────────────────────────────────────────────────────────────────
	// Markers stored in a control's Tag so owner-draw / event wiring runs exactly once per control.
	private const string ThemedTag = "DarkTheme.ListView";
	private const string TabbedTag = "DarkTheme.TabControl";
	private const string CheckTag = "DarkTheme.CheckBox";
	private const string RadioTag = "DarkTheme.RadioButton";
	private const string MenuTag = "DarkTheme.Menu";

	// ── Palette — Catppuccin Mocha (dark blue) ──────────────────────────────────────────────────────────────────
	public static readonly Color PageBack = Color.FromArgb(30, 30, 46);
	public static readonly Color PanelBack = Color.FromArgb(40, 40, 60);
	public static readonly Color CardBack = Color.FromArgb(49, 50, 68);
	public static readonly Color CardBorder = Color.FromArgb(69, 71, 90);
	public static readonly Color TextPrimary = Color.FromArgb(205, 214, 244);
	public static readonly Color TextSecondary = Color.FromArgb(166, 173, 200);
	public static readonly Color InputBack = Color.FromArgb(49, 50, 68);
	public static readonly Color InputBorder = Color.FromArgb(88, 91, 112);
	public static readonly Color AccentHeader = Color.FromArgb(137, 180, 250);
	public static readonly Color ButtonNormal = Color.FromArgb(137, 180, 250);
	public static readonly Color ButtonHover = Color.FromArgb(180, 190, 254);
	public static readonly Color DangerButton = Color.FromArgb(243, 139, 168);
	public static readonly Color DangerHover = Color.FromArgb(235, 160, 185);
	public static readonly Color SuccessAccent = Color.FromArgb(166, 227, 161);
	public static readonly Color SuccessHover = Color.FromArgb(190, 235, 185);
	public static readonly Color StatusBack = Color.FromArgb(24, 24, 37);
	public static readonly Color StatusFore = Color.FromArgb(166, 173, 200);
	public static readonly Color ToolbarBack = Color.FromArgb(24, 24, 37);
	public static readonly Color ButtonFore = Color.FromArgb(30, 30, 46);

	// Bright-green indicator used for the checked state of CheckBoxes and RadioButtons so the selection
	// is unmistakable on the dark surface (the native glyph rendered light-on-light and was unreadable).
	public static readonly Color IndicatorOn = Color.FromArgb(166, 227, 161);
	public static readonly Color IndicatorBox = Color.FromArgb(49, 50, 68);
	public static readonly Color IndicatorBorder = Color.FromArgb(137, 180, 250);

	// Grid colours.
	public static readonly Color GridBack = Color.FromArgb(17, 17, 27);
	public static readonly Color GridLines = Color.FromArgb(69, 71, 90);
	public static readonly Color CellBack = Color.FromArgb(30, 30, 46);
	public static readonly Color AltRowBack = Color.FromArgb(36, 37, 56);
	public static readonly Color SelectionBack = Color.FromArgb(137, 180, 250);
	public static readonly Color SelectionFore = Color.FromArgb(30, 30, 46);
	public static readonly Color HeaderBack = Color.FromArgb(49, 50, 68);
	public static readonly Color HeaderFore = Color.FromArgb(137, 180, 250);

	// Tab strip colours.
	public static readonly Color TabBack = Color.FromArgb(24, 24, 37);
	public static readonly Color TabSelectedBack = Color.FromArgb(49, 50, 68);
	public static readonly Color TabAccent = Color.FromArgb(137, 180, 250);

	// Semantic status colours — bright enough to read on the dark background.
	public static readonly Color StatusSuccess = Color.FromArgb(166, 227, 161);
	public static readonly Color StatusWarning = Color.FromArgb(249, 226, 175);
	public static readonly Color StatusDanger = Color.FromArgb(243, 139, 168);
	public static readonly Color StatusInfo = Color.FromArgb(137, 180, 250);

	// Row tint backgrounds for status-coloured grid rows on the dark surface.
	public static readonly Color RowSuccessBack = Color.FromArgb(34, 50, 42);
	public static readonly Color RowWarningBack = Color.FromArgb(56, 50, 36);
	public static readonly Color RowDangerBack = Color.FromArgb(58, 34, 42);
	public static readonly Color RowMutedBack = Color.FromArgb(36, 37, 56);

	// Shared UI font for the whole Configurator (Segoe UI 9pt) so the typography matches the MikroTik
	// setup module.
	public static readonly Font UiFont = new("Segoe UI", 9f, FontStyle.Regular, GraphicsUnit.Point);

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Recursively themes a control and all of its descendants. Safe to call once on a fully
	/// constructed page; controls added later can be themed by calling <see cref="Apply"/> on them. The
	/// ContextMenuStrip attached to any control is themed too, even though it does not live in the
	/// Controls collection.</summary>
	public static void Apply(Control root)
	{
		ArgumentNullException.ThrowIfNull(root);
		// Apply the shared Segoe UI 9pt font once at the root; child controls inherit it unless they set
		// their own (e.g. the monospace command box on the MikroTik tab), so we never clobber a deliberate
		// per-control font choice further down the tree.
		if (root is Form or TabPage)
		{
			root.Font = UiFont;
		}

		ApplyToControl(root);

		// A control's right-click menu is not part of Controls, so theme it explicitly here.
		if (root.ContextMenuStrip is { } ctx)
		{
			StyleMenu(ctx);
		}

		foreach (Control child in root.Controls)
		{
			Apply(child);
		}
	}

	/// <summary>Applies the dark grid styling shared by every DataGridView in the Configurator.</summary>
	public static void StyleGrid(DataGridView grid)
	{
		ArgumentNullException.ThrowIfNull(grid);

		grid.EnableHeadersVisualStyles = false;
		grid.BorderStyle = BorderStyle.None;
		grid.BackgroundColor = GridBack;
		grid.GridColor = GridLines;
		grid.ForeColor = TextPrimary;
		grid.RowHeadersVisible = false;

		grid.DefaultCellStyle.BackColor = CellBack;
		grid.DefaultCellStyle.ForeColor = TextPrimary;
		grid.DefaultCellStyle.SelectionBackColor = SelectionBack;
		grid.DefaultCellStyle.SelectionForeColor = SelectionFore;

		grid.AlternatingRowsDefaultCellStyle.BackColor = AltRowBack;
		grid.AlternatingRowsDefaultCellStyle.ForeColor = TextPrimary;
		grid.AlternatingRowsDefaultCellStyle.SelectionBackColor = SelectionBack;
		grid.AlternatingRowsDefaultCellStyle.SelectionForeColor = SelectionFore;

		grid.ColumnHeadersDefaultCellStyle.BackColor = HeaderBack;
		grid.ColumnHeadersDefaultCellStyle.ForeColor = HeaderFore;
		grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = HeaderBack;
		grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = HeaderFore;

		grid.RowHeadersDefaultCellStyle.BackColor = HeaderBack;
		grid.RowHeadersDefaultCellStyle.ForeColor = HeaderFore;
	}

	/// <summary>Applies the dark flat styling shared by every command Button: a square accent face with a
	/// matching hover. Pass an explicit normal / hover colour to colour-code destructive (Danger) or
	/// confirming (Success) actions. Buttons are intentionally SQUARE (no rounded region) to match the
	/// MikroTik setup module's Probe / Run-diagnostics buttons.</summary>
	public static void StyleButton(Button button, Color? normal = null, Color? hover = null)
	{
		ArgumentNullException.ThrowIfNull(button);

		Color baseColor = normal ?? ButtonNormal;
		Color hoverColor = hover ?? ButtonHover;

		button.FlatStyle = FlatStyle.Flat;
		button.FlatAppearance.BorderSize = 1;
		button.FlatAppearance.BorderColor = baseColor;
		button.FlatAppearance.MouseOverBackColor = hoverColor;
		button.FlatAppearance.MouseDownBackColor = hoverColor;
		button.BackColor = baseColor;
		// Dark text on a bright face reads best; on a darker face keep light text. Choose automatically
		// from the perceived luminance of the face colour.
		button.ForeColor = Luminance(baseColor) > 0.6 ? ButtonFore : TextPrimary;
		button.UseVisualStyleBackColor = false;
		button.Cursor = Cursors.Hand;
		button.Font = UiFont;

		// Square corners: drop any rounded region a previous theme version may have installed so the
		// face paints to the control's full rectangle.
		if (button.Region is not null)
		{
			button.Region.Dispose();
			button.Region = null;
		}
	}

	/// <summary>Themes a ToolStripDropDown (ContextMenuStrip / MenuStrip drop-down) with the dark renderer
	/// and palette. Idempotent via the Tag marker. Recursively themes sub-menus.</summary>
	public static void StyleMenu(ToolStripDropDown menu)
	{
		ArgumentNullException.ThrowIfNull(menu);

		menu.BackColor = CardBack;
		menu.ForeColor = TextPrimary;
		menu.Renderer = CreateMenuRenderer();

		if (menu.Tag as string != MenuTag)
		{
			menu.Tag = MenuTag;
		}

		foreach (ToolStripItem item in menu.Items)
		{
			ThemeMenuItem(item);
		}
	}

	/// <summary>Creates a ready-to-use dark ToolStrip renderer for ContextMenuStrip / MenuStrip / ToolStrip.</summary>
	public static ToolStripProfessionalRenderer CreateMenuRenderer() => new DarkMenuRenderer();

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static void ApplyToControl(Control c)
	{
		switch (c)
		{
			case DataGridView grid:
				StyleGrid(grid);
				break;

			case Button button:
				// Every button is forced to the single accent blue from here EXCEPT buttons a page has
				// deliberately coloured with a recognised semantic face (Danger pink / Success green),
				// which keep their meaning. This guarantees no button is ever dark-on-dark and that the
				// whole Configurator shares one button style driven from this file.
				if (IsSemanticFace(button.BackColor, out Color semHover))
				{
					StyleButton(button, button.BackColor, semHover);
				}
				else
				{
					StyleButton(button);
				}
				break;

			case LinkLabel link:
				link.BackColor = ResolveBack(link.Parent);
				link.LinkColor = AccentHeader;
				link.ActiveLinkColor = ButtonHover;
				link.VisitedLinkColor = TextSecondary;
				link.ForeColor = TextPrimary;
				break;

			case Label label:
				label.BackColor = Color.Transparent;
				if (IsDefaultText(label.ForeColor))
				{
					label.ForeColor = TextPrimary;
				}
				break;

			case TextBoxBase text:
				text.BackColor = InputBack;
				text.ForeColor = TextPrimary;
				text.BorderStyle = BorderStyle.FixedSingle;
				break;

			case ComboBox combo:
				combo.BackColor = InputBack;
				combo.ForeColor = TextPrimary;
				combo.FlatStyle = FlatStyle.Flat;
				break;

			case NumericUpDown numeric:
				numeric.BackColor = InputBack;
				numeric.ForeColor = TextPrimary;
				numeric.BorderStyle = BorderStyle.FixedSingle;
				break;

			case CheckBox check:
				StyleCheckBox(check);
				break;

			case RadioButton radio:
				StyleRadioButton(radio);
				break;

			case GroupBox group:
				group.BackColor = CardBack;
				group.ForeColor = AccentHeader;
				break;

			case ListView listView:
				StyleListView(listView);
				break;

			case TreeView tree:
				tree.BackColor = CellBack;
				tree.ForeColor = TextPrimary;
				tree.BorderStyle = BorderStyle.FixedSingle;
				tree.LineColor = GridLines;
				break;

			case ProgressBar bar:
				bar.BackColor = InputBack;
				bar.ForeColor = SuccessAccent;
				break;

			case StatusStrip statusStrip:
				statusStrip.BackColor = StatusBack;
				statusStrip.ForeColor = StatusFore;
				foreach (ToolStripItem item in statusStrip.Items)
				{
					ThemeToolStripItem(item);
				}
				break;

			case ToolStrip toolStrip:
				toolStrip.BackColor = ToolbarBack;
				toolStrip.ForeColor = TextPrimary;
				toolStrip.Renderer = CreateMenuRenderer();
				foreach (ToolStripItem item in toolStrip.Items)
				{
					ThemeMenuItem(item);
				}
				break;

			case TabControl tabControl:
				StyleTabControl(tabControl);
				break;

			case Form form:
				form.BackColor = PageBack;
				form.ForeColor = TextPrimary;
				break;

			// Panel covers FlowLayoutPanel, TableLayoutPanel and SplitterPanel (all derive from Panel),
			// so listing those separately would be unreachable (CS8120).
			case TabPage:
			case Panel:
			case SplitContainer:
				ThemeContainerSurface(c);
				break;

			default:
				// Unknown container — give it the surface colour so no light gaps remain.
				if (c.HasChildren)
				{
					ThemeContainerSurface(c);
				}
				break;
		}
	}

	private static void ThemeContainerSurface(Control c)
	{
		// Keep an explicitly chosen non-default surface (cards, banners, toolbars); otherwise paint
		// the standard page surface so there are no light backgrounds behind the controls.
		if (IsDefaultFace(c.BackColor))
		{
			c.BackColor = PageBack;
		}

		if (IsDefaultText(c.ForeColor))
		{
			c.ForeColor = TextPrimary;
		}
	}

	private static void ThemeToolStripItem(ToolStripItem item)
	{
		if (IsDefaultText(item.ForeColor))
		{
			item.ForeColor = StatusFore;
		}
	}

	/// <summary>Themes a single menu item and its drop-down sub-menu, recursively.</summary>
	private static void ThemeMenuItem(ToolStripItem item)
	{
		item.BackColor = CardBack;
		if (IsDefaultText(item.ForeColor))
		{
			item.ForeColor = TextPrimary;
		}

		if (item is ToolStripDropDownItem { HasDropDownItems: true } dropDownItem)
		{
			StyleMenu(dropDownItem.DropDown);
		}
	}

	/// <summary>Owner-draws a CheckBox with a bright-green check on a dark box so the checked state reads
	/// clearly on the dark surface (the native flat glyph rendered light-on-light). Wired once.</summary>
	private static void StyleCheckBox(CheckBox check)
	{
		check.BackColor = Color.Transparent;
		check.ForeColor = TextPrimary;
		check.UseVisualStyleBackColor = false;

		if (check.Tag as string == CheckTag)
		{
			return;
		}

		check.Tag = CheckTag;
		// FlatStyle.Standard lets us suppress the native glyph (CheckAlign drawing is handled by us via
		// Appearance=Normal + custom paint) while keeping hit-testing and AutoSize intact.
		check.FlatStyle = FlatStyle.Flat;
		check.FlatAppearance.BorderSize = 0;
		check.FlatAppearance.CheckedBackColor = Color.Transparent;
		check.FlatAppearance.MouseOverBackColor = Color.Transparent;
		check.FlatAppearance.MouseDownBackColor = Color.Transparent;
		check.AutoCheck = true;
		check.Paint += OnPaintCheckBox;
	}

	/// <summary>Owner-draws a RadioButton with a bright-green filled dot on a dark circle so the selected
	/// option reads clearly on the dark surface. Wired once.</summary>
	private static void StyleRadioButton(RadioButton radio)
	{
		radio.BackColor = Color.Transparent;
		radio.ForeColor = TextPrimary;
		radio.UseVisualStyleBackColor = false;

		if (radio.Tag as string == RadioTag)
		{
			return;
		}

		radio.Tag = RadioTag;
		radio.FlatStyle = FlatStyle.Flat;
		radio.FlatAppearance.BorderSize = 0;
		radio.FlatAppearance.CheckedBackColor = Color.Transparent;
		radio.FlatAppearance.MouseOverBackColor = Color.Transparent;
		radio.FlatAppearance.MouseDownBackColor = Color.Transparent;
		radio.Paint += OnPaintRadioButton;
	}

	/// <summary>Custom paint for a themed CheckBox: draws a 14&#215;14 box (dark fill, accent border) with a
	/// bright-green tick when checked, plus the label text, over the whole client area. The control's own
	/// surface is repainted first so the native light-on-light glyph is fully hidden.</summary>
	private static void OnPaintCheckBox(object? sender, PaintEventArgs e)
	{
		if (sender is not CheckBox check)
		{
			return;
		}

		// Clear the whole control with the parent surface so the native glyph painted underneath is hidden,
		// then draw our own indicator and text on top.
		Color surface = ResolveBack(check.Parent);
		e.Graphics.Clear(surface);
		e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

		const int box = 14;
		int top = (check.Height - box) / 2;
		Rectangle rect = new(0, Math.Max(0, top), box, box);

		using (SolidBrush fill = new(IndicatorBox))
		{
			e.Graphics.FillRectangle(fill, rect);
		}

		using (Pen border = new(check.Checked ? IndicatorOn : IndicatorBorder))
		{
			e.Graphics.DrawRectangle(border, rect);
		}

		if (check.Checked)
		{
			using Pen tick = new(IndicatorOn, 2f);
			e.Graphics.DrawLines(tick, new[]
			{
				new Point(rect.Left + 3, rect.Top + 7),
				new Point(rect.Left + 6, rect.Top + 10),
				new Point(rect.Left + 11, rect.Top + 3),
			});
		}

		Rectangle textRect = new(box + 6, 0, check.Width - box - 6, check.Height);
		TextRenderer.DrawText(
			e.Graphics,
			check.Text,
			check.Font,
			textRect,
			check.Enabled ? check.ForeColor : TextSecondary,
			TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.WordEllipsis);
	}

	/// <summary>Custom paint for a themed RadioButton: a 14&#215;14 circle (dark fill, accent border) with
	/// a bright-green inner dot when selected, then the label text in the control's ForeColor.</summary>
	private static void OnPaintRadioButton(object? sender, PaintEventArgs e)
	{
		if (sender is not RadioButton radio)
		{
			return;
		}

		Color surface = ResolveBack(radio.Parent);
		e.Graphics.Clear(surface);
		e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

		const int box = 14;
		int top = (radio.Height - box) / 2;
		Rectangle rect = new(0, Math.Max(0, top), box, box);

		using (SolidBrush fill = new(IndicatorBox))
		{
			e.Graphics.FillEllipse(fill, rect);
		}

		using (Pen border = new(radio.Checked ? IndicatorOn : IndicatorBorder))
		{
			e.Graphics.DrawEllipse(border, rect);
		}

		if (radio.Checked)
		{
			Rectangle dot = Rectangle.Inflate(rect, -4, -4);
			using SolidBrush dotBrush = new(IndicatorOn);
			e.Graphics.FillEllipse(dotBrush, dot);
		}

		Rectangle textRect = new(box + 6, 0, radio.Width - box - 6, radio.Height);
		TextRenderer.DrawText(
			e.Graphics,
			radio.Text,
			radio.Font,
			textRect,
			radio.Enabled ? radio.ForeColor : TextSecondary,
			TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.WordEllipsis);
	}

	/// <summary>Themes a ListView for the dark surface. Item rows render natively (so per-row
	/// <see cref="ListViewItem.BackColor"/> status colouring set by a page keeps working); only the
	/// column header is owner-drawn, because the classic ListView header ignores BackColor entirely and
	/// would otherwise stay light. Owner-draw is wired exactly once even if Apply runs again.</summary>
	private static void StyleListView(ListView listView)
	{
		listView.BackColor = CellBack;
		listView.ForeColor = TextPrimary;
		listView.BorderStyle = BorderStyle.FixedSingle;

		if (listView.Tag as string == ThemedTag)
		{
			return;
		}

		listView.Tag = ThemedTag;
		listView.OwnerDraw = true;

		listView.DrawColumnHeader += (_, e) =>
		{
			using SolidBrush back = new(HeaderBack);
			e.Graphics.FillRectangle(back, e.Bounds);
			using Pen border = new(GridLines);
			e.Graphics.DrawRectangle(border, e.Bounds.X, e.Bounds.Y, e.Bounds.Width - 1, e.Bounds.Height - 1);
			Rectangle text = Rectangle.Inflate(e.Bounds, -4, 0);
			TextRenderer.DrawText(
				e.Graphics,
				e.Header?.Text ?? string.Empty,
				listView.Font,
				text,
				HeaderFore,
				TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
		};

		// Item / sub-item rows render with the system defaults against the dark BackColor we set above.
		listView.DrawItem += (_, e) => e.DrawDefault = true;
		listView.DrawSubItem += (_, e) => e.DrawDefault = true;
	}

	/// <summary>Owner-draws a TabControl so both the tab headers and the strip band match the dark-blue
	/// theme. WinForms paints the tab band and the page-area border with the classic light system colour
	/// regardless of <see cref="Control.BackColor"/>; left alone that produces the grey strip under the
	/// tabs and around nested tab pages. We set OwnerDrawFixed and paint every tab ourselves, recolour
	/// each contained TabPage, and size tabs to their text so labels like "Whitelist" are never clipped.
	/// Wired exactly once via the Tag marker. The MainForm shell wires its own equivalent drawing on the
	/// outer tab strip; this method themes every nested TabControl the recursive Apply finds.</summary>
	private static void StyleTabControl(TabControl tab)
	{
		tab.BackColor = PageBack;
		tab.ForeColor = TextPrimary;

		foreach (TabPage page in tab.TabPages)
		{
			page.BackColor = PageBack;
			page.ForeColor = TextPrimary;
			page.UseVisualStyleBackColor = false;
		}

		if (tab.Tag as string == TabbedTag)
		{
			return;
		}

		tab.Tag = TabbedTag;
		tab.DrawMode = TabDrawMode.OwnerDrawFixed;
		// Keep the classic (Normal) appearance rather than FlatButtons: with FlatButtons WinForms fills
		// the whole tab-strip band with the light system colour (the grey band the user saw under the
		// Blocklist / Whitelist row). In Normal mode the strip band takes the control BackColor we set to
		// PageBack, and we owner-draw the page-area edge ourselves in OnDrawTabAreaBackground so no light
		// border remains around the content.
		tab.Appearance = TabAppearance.Normal;
		// Size each tab to its own text so labels are never truncated (the reported "Whitel.." clipping
		// happened because the fixed tab width was narrower than the "Whitelist" caption). A little extra
		// padding keeps the labels from touching the tab edges.
		tab.SizeMode = TabSizeMode.Normal;
		tab.Padding = new Point(14, 4);
		tab.DrawItem += OnDrawDarkTab;
		// The managed Paint event never fires for the tab-strip header band (WinForms draws it itself in
		// the light system colour), so a Win32 subclass is the only reliable way to repaint the empty strip
		// area: the grey tail right of the last tab, the gaps between wrapped rows, and the band above /
		// under the headers. DarkTabStripPainter fills every non-tab region with PageBack while leaving the
		// owner-drawn tab glyphs intact.
		DarkTabStripPainter.AttachTo(tab, PageBack);
	}

	/// <summary>Shared owner-draw handler painting one dark tab header: the active tab sits on a raised
	/// surface with a bright accent bar; inactive tabs sit on the darker strip band. Used by every nested
	/// TabControl the recursive Apply discovers.</summary>
	private static void OnDrawDarkTab(object? sender, DrawItemEventArgs e)
	{
		if (sender is not TabControl tab || e.Index < 0 || e.Index >= tab.TabPages.Count)
		{
			return;
		}

		TabPage page = tab.TabPages[e.Index];
		bool selected = e.Index == tab.SelectedIndex;
		Rectangle bounds = e.Bounds;

		Color back = selected ? TabSelectedBack : TabBack;
		Color fore = selected ? AccentHeader : TextPrimary;

		using (SolidBrush backBrush = new(back))
		{
			e.Graphics.FillRectangle(backBrush, bounds);
		}

		if (selected)
		{
			using SolidBrush accentBrush = new(TabAccent);
			e.Graphics.FillRectangle(accentBrush, bounds.Left, bounds.Top, bounds.Width, 3);
		}

		using Font font = new(tab.Font, selected ? FontStyle.Bold : FontStyle.Regular);
		TextRenderer.DrawText(
			e.Graphics,
			page.Text,
			font,
			bounds,
			fore,
			TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
	}

	/// <summary>Perceived luminance (0..1) of a colour via the Rec. 601 weighting; used to pick a
	/// readable foreground over a button face.</summary>
	private static double Luminance(Color c) =>
		((0.299 * c.R) + (0.587 * c.G) + (0.114 * c.B)) / 255.0;

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static Color ResolveBack(Control? parent) =>
		parent is null || IsDefaultFace(parent.BackColor) ? PageBack : parent.BackColor;

	/// <summary>True when a back colour is still a default system face that the theme should override.</summary>
	private static bool IsDefaultFace(Color c) =>
		c == SystemColors.Control
		|| c == SystemColors.Window
		|| c == SystemColors.ButtonFace
		|| c == Color.Empty
		|| c == Color.Transparent
		|| c == Color.White
		|| c == Color.WhiteSmoke
		|| c == Color.Gainsboro;

	/// <summary>True when a fore colour is still a default system text colour the theme should override.</summary>
	private static bool IsDefaultText(Color c) =>
		c == SystemColors.ControlText
		|| c == SystemColors.WindowText
		|| c == Color.Empty
		|| c == Color.Black;

	/// <summary>True when a button face is one of the recognised semantic colours (Danger pink / Success
	/// green) a page set deliberately; the matching hover colour is returned via <paramref name="hover"/>.
	/// Any other face (including page-set dark faces that would otherwise vanish into the background) is
	/// not semantic, so the caller forces the single accent blue instead.</summary>
	private static bool IsSemanticFace(Color c, out Color hover)
	{
		if (c.ToArgb() == DangerButton.ToArgb())
		{
			hover = DangerHover;
			return true;
		}

		if (c.ToArgb() == SuccessAccent.ToArgb())
		{
			hover = SuccessHover;
			return true;
		}

		hover = ButtonHover;
		return false;
	}

	// ── Dark Menu Renderer ───────────────────────────────────────────────────────

	/// <summary>ToolStrip / menu renderer painting the dark palette for ContextMenuStrip, MenuStrip and
	/// ToolStrip so popups and toolbars match the rest of the Configurator.</summary>
	private sealed class DarkMenuRenderer : ToolStripProfessionalRenderer
	{
		public DarkMenuRenderer() : base(new DarkColorTable())
		{
			RoundedEdges = false;
		}

		protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
		{
			e.TextColor = e.Item.Selected ? SelectionFore : TextPrimary;
			base.OnRenderItemText(e);
		}

		protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
		{
			e.ArrowColor = e.Item is { Selected: true } ? SelectionFore : TextPrimary;
			base.OnRenderArrow(e);
		}
	}

	/// <summary>Colour table feeding <see cref="DarkMenuRenderer"/>.</summary>
	private sealed class DarkColorTable : ProfessionalColorTable
	{
		public override Color ToolStripDropDownBackground => CardBack;
		public override Color ImageMarginGradientBegin => CardBack;
		public override Color ImageMarginGradientMiddle => CardBack;
		public override Color ImageMarginGradientEnd => CardBack;
		public override Color MenuBorder => CardBorder;
		public override Color MenuItemBorder => SelectionBack;
		public override Color MenuItemSelected => SelectionBack;
		public override Color MenuItemSelectedGradientBegin => SelectionBack;
		public override Color MenuItemSelectedGradientEnd => SelectionBack;
		public override Color MenuItemPressedGradientBegin => PanelBack;
		public override Color MenuItemPressedGradientEnd => PanelBack;
		public override Color SeparatorDark => CardBorder;
		public override Color SeparatorLight => CardBorder;
		public override Color ToolStripBorder => ToolbarBack;
		public override Color ToolStripGradientBegin => ToolbarBack;
		public override Color ToolStripGradientMiddle => ToolbarBack;
		public override Color ToolStripGradientEnd => ToolbarBack;
		public override Color ButtonSelectedHighlight => SelectionBack;
		public override Color ButtonSelectedGradientBegin => SelectionBack;
		public override Color ButtonSelectedGradientEnd => SelectionBack;
	}
}
