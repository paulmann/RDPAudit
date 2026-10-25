// File:    src/RdpAudit.Configurator/Services/SafeAsyncHandler.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: The single sanctioned way to attach an async page action to a WinForms event. A lambda
//          assigned to an EventHandler is async void at runtime, so an exception that escapes it has
//          no caller left to catch it: it reaches the message loop as an unhandled fault and takes the
//          process - and the operator's unsaved state - with it. The wrapper converts that class of
//          failure into a recorded, visible one: the type's shared journal keeps it
//          (ConfiguratorExceptionGuard) and the page's own failure report renders it on the surface the
//          operator is already looking at. Promoted from DatabasePage's private AsyncClick so pages
//          cannot drift apart on this contract; see docs/30-configurator.md.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;

namespace RdpAudit.Configurator.Services;

/// <summary>Wires async page actions to event handlers without ever letting an exception escape into
/// the WinForms message loop as <c>async void</c>.</summary>
[SupportedOSPlatform("windows")]
public static class SafeAsyncHandler
{
	/// <summary>Wraps a parameterless async action (Click, Tick, HandleCreated, …) into an
	/// <see cref="EventHandler"/>. <paramref name="reportFailure"/> is the page's last-resort report and
	/// runs on the same thread as the fault; it is optional because a page-less caller may legitimately
	/// only want the journal entry.</summary>
	public static EventHandler Wrap(Func<Task> action, Action<Exception>? reportFailure = null)
	{
		ArgumentNullException.ThrowIfNull(action);
		string origin = OriginOf(action);
		return async (_, _) => await InvokeAsync(action, reportFailure, origin).ConfigureAwait(true);
	}

	/// <summary>Wraps an async action that needs the event arguments into a typed handler
	/// (<see cref="EventHandler{TEventArgs}"/>, <c>FormClosing</c>, <c>ListChanged</c>, …).</summary>
	public static EventHandler<TEventArgs> Wrap<TEventArgs>(
		Func<TEventArgs, Task> action,
		Action<Exception>? reportFailure = null)
		where TEventArgs : EventArgs
	{
		ArgumentNullException.ThrowIfNull(action);
		string origin = OriginOf(action);
		return async (_, e) => await InvokeAsync(() => action(e), reportFailure, origin).ConfigureAwait(true);
	}

	/// <summary>Wraps an async key handler. Kept separate from <see cref="Wrap{TEventArgs}"/> so callers
	/// keep the <see cref="KeyEventHandler"/> shape the WinForms event expects.</summary>
	public static KeyEventHandler KeyDown(Func<KeyEventArgs, Task> action, Action<Exception>? reportFailure = null)
	{
		ArgumentNullException.ThrowIfNull(action);
		string origin = OriginOf(action);
		return async (_, e) => await InvokeAsync(() => action(e), reportFailure, origin).ConfigureAwait(true);
	}

	private static async Task InvokeAsync(Func<Task> action, Action<Exception>? reportFailure, string origin)
	{
		try
		{
			// ConfigureAwait(true): page actions touch controls and must resume on the UI thread that
			// owns them. Every page this wrapper is used from is also pumped by the STA test harness.
			await action().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			Report(origin, ex, reportFailure);
		}
	}

	private static void Report(string origin, Exception exception, Action<Exception>? reportFailure)
	{
		// Journal first: the page's own report may itself fail (a disposed surface), and the durable
		// record is the part that survives the session.
		try
		{
			ConfiguratorExceptionGuard.Default.ReportHandlerFailure(origin, exception);
		}
		catch (Exception)
		{
			// The guard is documented never to throw; keep the page report reachable even if that breaks.
		}

		try
		{
			reportFailure?.Invoke(exception);
		}
		catch (Exception)
		{
			// A failing failure-reporter must not become the fault it was meant to absorb.
		}
	}

	/// <summary>Names the page the wrapped action lives in, for the journal entry. A lambda compiles
	/// into a compiler-generated closure type nested inside its page, so the page name is the nearest
	/// enclosing non-generated type; the fallback keeps a lambda declared elsewhere (a test, a helper)
	/// from producing a meaningless origin.</summary>
	private static string OriginOf(Delegate action)
	{
		Type? type = action.Method.DeclaringType;
		while (type is not null
			&& (type.Name.Length == 0
				|| type.Name[0] == '<'
				|| type.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), inherit: false)))
		{
			type = type.DeclaringType;
		}

		return type?.Name ?? "Configurator";
	}
}
