// File:    src/RdpAudit.Configurator/Theming/DarkTabStripPainter.cs
// Module:  RdpAudit.Configurator.Theming
// Purpose: Attaches to an existing TabControl and paints the tab-strip band dark by intercepting
//          WM_PAINT / WM_ERASEBKGND at the Win32 level. The managed Paint event never fires for the
//          tab-strip header band (WinForms draws it itself in the light system colour), so a control
//          subclass via NativeWindow is the only reliable way to repaint the empty strip area — the
//          grey "tail" to the right of the last tab, the unused space on wrapped multiline rows, and
//          the band above / under the headers — without losing the native tab glyphs.
// Depends: System.Windows.Forms.NativeWindow, System.Windows.Forms.TabControl, System.Drawing.Graphics
// Extends: To change the band colour, change the colour passed to AttachTo. To paint extra decorations
//          (e.g. a separator line under the strip), extend PaintStripBand below.
//
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.0.0

using System.Drawing;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace RdpAudit.Configurator.Theming;

/// <summary>
/// Win32 subclass that repaints the tab-strip header band of a <see cref="TabControl"/> with a solid
/// dark colour. WinForms paints that band with the light system colour and raises no managed Paint
/// event for it, so this <see cref="NativeWindow"/> hooks the control's window procedure, lets the
/// control draw the tabs natively, and then fills every region of the strip band that is NOT occupied
/// by an actual tab rectangle. The result: dark, seamless tab rows with the native tab glyphs intact.
/// All drawing uses client coordinates (Graphics.FromHwnd + GetTabRect), so no window-border maths and
/// no P/Invoke are required.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class DarkTabStripPainter : NativeWindow, IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────
	private const int WmPaint = 0x000F;
	private const int WmEraseBkgnd = 0x0014;

	private readonly TabControl _tab;
	private readonly Color _bandColor;
	private bool _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────
	private DarkTabStripPainter(TabControl tab, Color bandColor)
	{
		_tab = tab;
		_bandColor = bandColor;
	}

	/// <summary>Attaches a painter to <paramref name="tab"/>. The painter wires/unwires itself around the
	/// handle lifecycle so it survives handle recreation, and disposes with the control.</summary>
	public static void AttachTo(TabControl tab, Color bandColor)
	{
		ArgumentNullException.ThrowIfNull(tab);

		DarkTabStripPainter painter = new(tab, bandColor);
		painter.Hook();

		tab.HandleCreated += (_, _) => painter.Hook();
		tab.HandleDestroyed += (_, _) => painter.Unhook();
		tab.Disposed += (_, _) => painter.Dispose();
	}

	// ── Public API ───────────────────────────────────────────────────────────────
	private void Hook()
	{
		if (_disposed)
		{
			return;
		}

		if (_tab.IsHandleCreated && Handle == IntPtr.Zero)
		{
			AssignHandle(_tab.Handle);
		}
	}

	private void Unhook()
	{
		if (Handle != IntPtr.Zero)
		{
			ReleaseHandle();
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────
	protected override void WndProc(ref Message m)
	{
		switch (m.Msg)
		{
			case WmEraseBkgnd:
				// Claim the erase so WinForms never flashes the light system colour; the dark fill below
				// (and the native tab paint on WM_PAINT) provide the actual surface.
				EraseBackground(m.WParam);
				m.Result = (IntPtr)1;
				return;

			case WmPaint:
				base.WndProc(ref m); // let the control draw its tabs natively first
				PaintStripBand(); // then cover every non-tab region of the strip with the dark colour
				return;

			default:
				base.WndProc(ref m);
				return;
		}
	}

	/// <summary>Fills the whole client rectangle with the band colour onto the DC supplied with
	/// WM_ERASEBKGND, suppressing the light system erase.</summary>
	private void EraseBackground(IntPtr hdc)
	{
		if (hdc == IntPtr.Zero || !_tab.IsHandleCreated)
		{
			return;
		}

		using Graphics g = Graphics.FromHdc(hdc);
		using SolidBrush brush = new(_bandColor);
		g.FillRectangle(brush, _tab.ClientRectangle);
	}

	/// <summary>Paints the dark band over every part of the tab-strip header not covered by an actual tab
	/// rectangle: the empty tail right of the last tab, the gaps between wrapped rows, and the thin strip
	/// directly under (and around) the headers. Tab glyphs are preserved because their rectangles are
	/// excluded from the fill region. Uses client coordinates throughout (Graphics.FromHwnd + GetTabRect).</summary>
	private void PaintStripBand()
	{
		if (!_tab.IsHandleCreated || _tab.TabCount == 0)
		{
			return;
		}

		using Graphics g = Graphics.FromHwnd(_tab.Handle);

		// The strip band spans from the top of the control down to the top of the display (page) area.
		// DisplayRectangle.Top is the first pixel of page content; everything above it is strip band.
		Rectangle client = _tab.ClientRectangle;
		int stripBottom = _tab.DisplayRectangle.Top;
		Rectangle band = stripBottom > 0
			? new Rectangle(0, 0, client.Width, stripBottom)
			: client;

		using Region region = new(band);

		// Exclude each tab header rectangle so the native glyphs remain visible.
		for (int i = 0; i < _tab.TabCount; i++)
		{
			region.Exclude(_tab.GetTabRect(i));
		}

		using SolidBrush brush = new(_bandColor);
		g.FillRegion(brush, region);
	}

	// ── Disposal ─────────────────────────────────────────────────────────────────
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		Unhook();
	}
}
