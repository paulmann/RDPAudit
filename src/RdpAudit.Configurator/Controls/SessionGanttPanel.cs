// File:    src/RdpAudit.Configurator/Controls/SessionGanttPanel.cs
// Module:  RdpAudit.Configurator.Controls
// Purpose: Owner-drawn GDI+ Gantt timeline for the Session Map tab (Backlog #6). Renders one
//          session timeline over a horizontal UTC time axis: lifecycle phases (logon start,
//          connected, reconnected, disconnected, logoff), process and file/other activity as
//          colour-coded markers on stacked lanes, an open-ended active-session beam to "now",
//          a legend, truncation badge and per-marker tooltips. No third-party chart libraries -
//          pure System.Drawing. The panel never throws: empty or degenerate timelines render
//          a "No timeline data" placeholder instead.
// Extends: System.Windows.Forms.UserControl
// Author:  RdpAudit Team
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Sessions;

namespace RdpAudit.Configurator.Controls;

/// <summary>GDI+ Gantt view of one session timeline.</summary>
[SupportedOSPlatform("windows")]
public sealed class SessionGanttPanel : UserControl
{
	// UI-level lane palette. Kept local to the control on purpose: colours are presentation
	// concerns and must never leak into RdpAudit.Core.
	private static readonly Color LaneLifecycle = Color.FromArgb(137, 180, 250);
	private static readonly Color LaneProcess = Color.FromArgb(166, 227, 161);
	private static readonly Color LaneFile = Color.FromArgb(249, 226, 175);
	private static readonly Color LaneOther = Color.FromArgb(203, 166, 247);
	private static readonly Color ActiveBeam = Color.FromArgb(137, 180, 250);
	private static readonly Color Axis = Color.FromArgb(88, 91, 112);
	private static readonly Color Tick = Color.FromArgb(137, 180, 250);
	private static readonly Color TruncatedBadge = Color.FromArgb(249, 226, 175);

	private const int LegendHeight = 26;
	private const int AxisLabelHeight = 18;

	private readonly ToolTip _toolTip = new();
	private readonly List<(Rectangle Rect, SessionTimelineEventDto Event)> _markers = new();

	private SessionTimelineDto? _timeline;
	private DateTime _start;
	private DateTime _end;

	public SessionGanttPanel()
	{
		DoubleBuffered = true;
		BackColor = DarkTheme.GridBack;
		ResizeRedraw = true;
		Paint += OnPaint;
		MouseMove += OnMouseMove;
		Disposed += (_, _) => _toolTip.Dispose();
	}

	/// <summary>Renders the supplied timeline; null clears the panel to the placeholder.</summary>
	public void SetTimeline(SessionTimelineDto? timeline)
	{
		_timeline = timeline;
		_markers.Clear();
		_toolTip.RemoveAll();

		if (timeline is null)
		{
			Invalidate();
			return;
		}

		_start = timeline.StartUtc;
		DateTime end = timeline.EndUtc ?? DateTime.UtcNow;
		if (end <= _start)
		{
			end = _start.AddMinutes(1);
		}

		_end = end;
		Invalidate();
	}

	private void OnPaint(object? sender, PaintEventArgs e)
	{
		Graphics g = e.Graphics;
		g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
		g.Clear(BackColor);

		Rectangle legendRect = new(0, 0, ClientSize.Width, LegendHeight);
		DrawLegend(g, legendRect);

		Rectangle chartRect = new(
			16,
			LegendHeight + 8,
			Math.Max(20, ClientSize.Width - 32),
			Math.Max(40, ClientSize.Height - LegendHeight - AxisLabelHeight - 24));

		if (_timeline is null || _timeline.Events.Count == 0 || _timeline.SessionId <= 0)
		{
			TextRenderer.DrawText(g, "No timeline data", DarkTheme.UiFont, chartRect,
				DarkTheme.TextSecondary, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
			return;
		}

		DrawChart(g, chartRect);
	}

	private void DrawLegend(Graphics g, Rectangle rect)
	{
		(string Label, Color Color)[] entries =
		[
			("Lifecycle", LaneLifecycle),
			("Process", LaneProcess),
			("File", LaneFile),
			("Other", LaneOther),
		];

		int x = rect.Left + 4;
		foreach ((string label, Color color) in entries)
		{
			using SolidBrush swatch = new(color);
			g.FillRectangle(swatch, x, rect.Top + 6, 12, 12);
			x += 16;
			TextRenderer.DrawText(g, label, DarkTheme.UiFont, new Point(x, rect.Top + 4), DarkTheme.TextSecondary);
			x += TextRenderer.MeasureText(label, DarkTheme.UiFont).Width + 14;
		}

		if (_timeline is { Truncated: true })
		{
			string badge = string.Format(CultureInfo.InvariantCulture,
				"TRUNCATED (matching {0}, cap {1})", _timeline.TotalMatching, _timeline.AppliedCap);
			Size size = TextRenderer.MeasureText(badge, DarkTheme.UiFont);
			int bx = rect.Right - size.Width - 4;
			using Pen pen = new(TruncatedBadge);
			using SolidBrush textBrush = new(TruncatedBadge);
			g.DrawRectangle(pen, bx - 4, rect.Top + 4, size.Width + 8, size.Height + 2);
			TextRenderer.DrawText(g, badge, DarkTheme.UiFont, new Point(bx, rect.Top + 5), TruncatedBadge);
		}
	}

	private void DrawChart(Graphics g, Rectangle rect)
	{
		SessionTimelineDto timeline = _timeline!;
		using Pen axisPen = new(Axis, 1);
		int axisY = rect.Top + (rect.Height / 2);
		g.DrawLine(axisPen, rect.Left, axisY, rect.Right, axisY);

		TimeSpan span = _end - _start;
		if (span.TotalSeconds <= 0)
		{
			span = TimeSpan.FromMinutes(1);
		}

		DrawTicks(g, rect, axisY);

		float Map(DateTime t)
		{
			double ratio = (t - _start).TotalMilliseconds / span.TotalMilliseconds;
			return rect.Left + (float)(ratio * (rect.Width - 24));
		}

		int laneTop = rect.Top;
		int laneHeight = rect.Height / 3;

		static int LaneFor(SessionTimelineEventKind kind) => kind switch
		{
			SessionTimelineEventKind.LogonStart or
			SessionTimelineEventKind.Connected or
			SessionTimelineEventKind.Reconnected or
			SessionTimelineEventKind.Disconnected or
			SessionTimelineEventKind.Logoff => 0,
			SessionTimelineEventKind.Process => 1,
			SessionTimelineEventKind.File => 2,
			_ => 2,
		};

		static Color ColorFor(SessionTimelineEventKind kind) => kind switch
		{
			SessionTimelineEventKind.LogonStart or
			SessionTimelineEventKind.Connected or
			SessionTimelineEventKind.Reconnected or
			SessionTimelineEventKind.Disconnected or
			SessionTimelineEventKind.Logoff => LaneLifecycle,
			SessionTimelineEventKind.Process => LaneProcess,
			SessionTimelineEventKind.File => LaneFile,
			_ => LaneOther,
		};

		foreach (SessionTimelineEventDto ev in timeline.Events)
		{
			float x = Map(ev.TimeUtc);
			if (float.IsNaN(x) || x < rect.Left - 4 || x > rect.Right + 4)
			{
				continue;
			}

			int lane = LaneFor(ev.Kind);
			int y = laneTop + (lane * laneHeight) + (laneHeight / 2);
			Color color = ColorFor(ev.Kind);

			using (Pen stem = new(Axis, 1))
			{
				g.DrawLine(stem, x, axisY, x, y - 6);
			}

			Point[] diamond =
			[
				new((int)x, y - 6),
				new((int)x + 6, y),
				new((int)x, y + 6),
				new((int)x - 6, y),
			];
			using SolidBrush markerBrush = new(color);
			g.FillPolygon(markerBrush, diamond);
			_markers.Add((new Rectangle((int)x - 8, y - 8, 16, 16), ev));
		}

		if (timeline.IsActive || !timeline.EndUtc.HasValue)
		{
			float nowX = Map(DateTime.UtcNow);
			if (nowX >= rect.Left && nowX <= rect.Right)
			{
				using Pen beam = new(ActiveBeam, 3) { DashStyle = System.Drawing.Drawing2D.DashStyle.Dash };
				g.DrawLine(beam, nowX, rect.Top + 4, nowX, rect.Bottom - 4);
				TextRenderer.DrawText(g, "now", DarkTheme.UiFont, new Point((int)nowX + 4, rect.Top + 4), ActiveBeam);
			}
		}

		DrawAxisLabels(g, rect);
	}

	private void DrawTicks(Graphics g, Rectangle rect, int axisY)
	{
		TimeSpan span = _end - _start;
		if (span.TotalSeconds <= 0)
		{
			return;
		}

		double[] steps =
		[
			1, 5, 15, 30, 60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400,
		];
		double stepSeconds = steps[0];
		foreach (double candidate in steps)
		{
			stepSeconds = candidate;
			if (span.TotalSeconds / candidate <= 12)
			{
				break;
			}
		}

		DateTime tick = RoundDownToStep(_start, stepSeconds);
		int guard = 0;
		while (tick <= _end.AddSeconds(stepSeconds) && guard++ < 400)
		{
			if (tick >= _start && tick <= _end)
			{
				double ratio = (tick - _start).TotalMilliseconds / span.TotalMilliseconds;
				float x = rect.Left + (float)(ratio * (rect.Width - 24));
				using Pen tickPen = new(Tick, 1);
				g.DrawLine(tickPen, x, axisY - 4, x, axisY + 4);
				string label = FormatTick(tick, stepSeconds);
				Size size = TextRenderer.MeasureText(label, DarkTheme.UiFont);
				TextRenderer.DrawText(g, label, DarkTheme.UiFont,
					new Point((int)x - (size.Width / 2), axisY + 8), DarkTheme.TextSecondary);
			}

			tick = tick.AddSeconds(stepSeconds);
		}
	}

	private void DrawAxisLabels(Graphics g, Rectangle rect)
	{
		string startLabel = "Start " + _start.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
		string endLabel = _end == _start ? string.Empty : "End " + _end.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
		TextRenderer.DrawText(g, startLabel, DarkTheme.UiFont, new Point(rect.Left, rect.Bottom + 4), DarkTheme.TextSecondary);
		Size endSize = TextRenderer.MeasureText(endLabel, DarkTheme.UiFont);
		TextRenderer.DrawText(g, endLabel, DarkTheme.UiFont,
			new Point(rect.Right - endSize.Width - 4, rect.Bottom + 4), DarkTheme.TextSecondary);
	}

	private static DateTime RoundDownToStep(DateTime t, double stepSeconds)
	{
		long ticks = t.Ticks;
		long stepTicks = (long)(stepSeconds * TimeSpan.TicksPerSecond);
		if (stepTicks <= 0)
		{
			return t;
		}

		return new DateTime(ticks - (ticks % stepTicks), t.Kind);
	}

	private static string FormatTick(DateTime t, double stepSeconds)
		=> stepSeconds >= 3600
			? t.ToString("HH:mm", CultureInfo.InvariantCulture)
			: t.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

	private void OnMouseMove(object? sender, MouseEventArgs e)
	{
		foreach ((Rectangle rect, SessionTimelineEventDto ev) in _markers)
		{
			if (!rect.Contains(e.Location))
			{
				continue;
			}

			_toolTip.SetToolTip(this, BuildTooltip(ev));
			return;
		}

		_toolTip.SetToolTip(this, string.Empty);
	}

	private static string BuildTooltip(SessionTimelineEventDto ev)
	{
		string time = ev.TimeUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
		string head = string.Format(CultureInfo.InvariantCulture,
			"{0}  |  {1}  |  correlation: {2}",
			time, ev.Kind, ev.CorrelationMethod);

		List<string> lines = new() { head };
		if (ev.EventId > 0)
		{
			lines.Add("Event " + ev.EventId.ToString(CultureInfo.InvariantCulture));
		}

		if (!string.IsNullOrWhiteSpace(ev.ProcessName))
		{
			lines.Add("Process: " + Truncate(ev.ProcessName, 200));
		}

		if (!string.IsNullOrWhiteSpace(ev.CommandLine))
		{
			lines.Add("Command: " + Truncate(ev.CommandLine, 400));
		}

		if (!string.IsNullOrWhiteSpace(ev.ObjectName))
		{
			lines.Add("Object: " + Truncate(ev.ObjectName, 300));
		}

		if (!string.IsNullOrWhiteSpace(ev.Status))
		{
			lines.Add("Status: " + Truncate(ev.Status, 120));
		}

		return string.Join(Environment.NewLine, lines);
	}

	private static string Truncate(string value, int max)
		=> value.Length <= max ? value : value[..(max - 3)] + "...";
}
