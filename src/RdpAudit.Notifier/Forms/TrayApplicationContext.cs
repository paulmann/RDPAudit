// File:    src/RdpAudit.Notifier/Forms/TrayApplicationContext.cs
// Module:  RdpAudit.Notifier.Forms
// Purpose: Tray context hosting the polling loop and the single NotifyIcon; the WinForms
//          lifetime anchor. Poll interval comes from live service settings; on failure it
//          degrades to the previous safe interval, and the tray tooltip reports the state.
// Extends: System.Windows.Forms.ApplicationContext
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Notifier.Ipc;
using RdpAudit.Notifier.Notifications;

namespace RdpAudit.Notifier.Forms;

/// <summary>WinForms tray lifetime anchor for the notifier.</summary>
[SupportedOSPlatform("windows10.0.19041.0")]
public sealed class TrayApplicationContext : ApplicationContext
{
	private readonly NotifyIcon _icon;
	private readonly NotificationPoller _poller;
	private readonly PollBackoffPolicy _backoff;
	private readonly SynchronizationContext? _uiContext;
	private readonly CancellationTokenSource _cts;
	private readonly Task _loop;
	private bool _disposed;

	public TrayApplicationContext(
		IAlertSource? source = null,
		INotificationSink? sink = null,
		TimeProvider? timeProvider = null)
	{
		_icon = new NotifyIcon
		{
			Icon = ShieldIcon(),
			Text = "RdpAudit Notifier",
			Visible = true,
		};

		try
		{
			ToastAppRegistration.EnsureRegistered();
		}
		catch
		{
			// HKCU registry failure should never block tray startup.
		}

		INotificationSink sinkChannel = sink ?? new ToastRouter(new NativeToastSender(), new TrayNotificationSink(_icon));
		_cts = new CancellationTokenSource();
		_poller = new NotificationPoller(
			source ?? new IpcAlertSource(),
			sinkChannel,
			timeProvider);
		_backoff = new PollBackoffPolicy(NotificationPolicy.Defaults().PollIntervalSeconds);
		_icon.DoubleClick += (_, _) => _icon.ShowBalloonTip(3000, "RdpAudit Notifier", "RdpAudit service alert notifications are active.", ToolTipIcon.Info);

		ToolStripMenuItem exit = new("Exit");
		exit.Click += (_, _) => ExitThreadCore();
		_icon.ContextMenuStrip = new ContextMenuStrip();
		_icon.ContextMenuStrip.Items.Add(exit);

		_uiContext = SynchronizationContext.Current;
		_loop = RunLoopAsync(_cts.Token);
	}

	private static Icon ShieldIcon()
	{
		using Bitmap shield = SystemIcons.Shield.ToBitmap();
		return Icon.FromHandle(shield.GetHicon());
	}

	private async Task RunLoopAsync(CancellationToken ct)
	{
		while (!ct.IsCancellationRequested)
		{
			try
			{
				await _poller.TickAsync(ct).ConfigureAwait(false);
				if (_poller.LastTickSucceeded)
				{
					_backoff.OnHealthy(_poller.CurrentPollIntervalSeconds);
				}
				else
				{
					_backoff.OnUnhealthy();
				}
				UpdateTrayTooltip(_poller.LastTickSucceeded);
			}
			catch (OperationCanceledException) when (ct.IsCancellationRequested)
			{
				break;
			}
			catch (Exception)
			{
				// Never tear down the tray on a transient poll failure.
			}

			try
			{
				await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, _backoff.CurrentDelaySeconds)), ct).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				break;
			}
		}
	}

	/// <summary>Marshals the tooltip update onto the UI thread that owns the tray icon.</summary>
	private void UpdateTrayTooltip(bool serviceReachable)
	{
		string text = TrayStatusText.For(serviceReachable, _backoff.CurrentDelaySeconds);
		if (_uiContext is null || SynchronizationContext.Current == _uiContext)
		{
			_icon.Text = text;
			return;
		}

		_uiContext.Post(state => _icon.Text = (string)state!, text);
	}

	protected override void ExitThreadCore()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_cts.Cancel();
		try
		{
			_loop.Wait(TimeSpan.FromSeconds(3));
		}
		catch (AggregateException)
		{
			// Best effort during shutdown.
		}

		try
		{
			_icon.Visible = false;
			_icon.Dispose();
		}
		finally
		{
			_cts.Dispose();
			base.ExitThreadCore();
		}
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing && !_disposed)
		{
			ExitThreadCore();
		}

		base.Dispose(disposing);
		_disposed = true;
	}
}
