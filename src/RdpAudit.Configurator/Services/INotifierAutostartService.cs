// File:    src/RdpAudit.Configurator/Services/INotifierAutostartService.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Abstraction over the Windows Task Scheduler registration of the tray notifier.
//          The notifier must run in the interactive user's session, so the ONLOGON task is
//          registered by the elevated Configurator (not the Session-0 service). The interface
//          exists so NotificationsPage can be tested without invoking real schtasks.exe.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of applying the notifier autostart state.</summary>
public sealed record NotifierAutostartResult(bool Success, bool TaskPresent, string Message);

/// <summary>Registers or removes the RdpAudit.Notifier ONLOGON scheduled task.</summary>
public interface INotifierAutostartService
{
	/// <summary>Applies the desired autostart state. Returns success even when the task is
	/// already in the desired state or when schtasks reports the task is absent while removing.
	/// Asynchronous because the underlying schtasks.exe round-trip must never block the UI thread:
	/// the caller is the Notifications tab's save path, which owns the WinForms context.</summary>
	Task<NotifierAutostartResult> ApplyAsync(bool startWithWindows);
}
