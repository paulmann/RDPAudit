// File:    src/RdpAudit.Service/Services/StoreFingerprintAlarmSink.cs
// Module:  RdpAudit.Service.Services
// Purpose: The off-ProgramData mirror for the store-fingerprint chain (B19). The chain and its sealed tip
//          both live under %ProgramData%\RdpAudit\integrity, so an attacker who can write there can remove
//          both; this sink copies the KEY FACT - the chain's state and, at every clean shutdown, the head
//          digest the chain had - into a place that is not part of that tree, so a deletion leaves a trace
//          the operator can find without reading the integrity folder that was tampered with.
//          Two deliberate design points:
//            1. The Windows event-log source is NEVER created here. `manageEventSource: false` is what the
//               Serilog EventLog sink in Program.ConfigureSerilog already uses, and the source is registered
//               by the installation (install.ps1 / the installer), not at runtime by this code: creating an
//               event source writes to HKLM and requires elevation, which a service start must not depend on.
//               When the source does not exist, the sink reports itself UNAVAILABLE and the caller records
//               that fact instead of inventing a source. Mirrored facts then simply do not exist, and the
//               sealed tip remains the only second store - a limitation, stated in docs/88, not a silent
//               success.
//            2. Publishing is bounded. The chain appends a periodic entry on every maintenance pass, so
//               mirroring every entry would grow the Application log without adding information. The sink is
//               called for (a) a non-Ok chain state - the rare, loud case this exists for - and (b) the
//               clean-shutdown tip, which is bounded by service restarts and is the authoritative baseline
//               anyway.
//          HONEST LIMIT, stated in the type as well as in docs/88: the Application log is readable and
//          writable by administrators. This mirror raises the cost of a quiet substitution; it does not make
//          one impossible, and nothing here or in the docs claims otherwise.
// Extends: System.Object

using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Logging;

namespace RdpAudit.Service.Services;

/// <summary>One key fact about the store-fingerprint chain, as it is mirrored outside ProgramData.</summary>
/// <param name="Kind">What the fact is: <c>ChainState</c> for a chain verdict, <c>CleanShutdownTip</c> for
/// the authoritative tip written when the service stopped.</param>
/// <param name="State">The chain state, or <c>Ok</c> for a clean-shutdown tip.</param>
/// <param name="EntryCount">How many chain entries the fact refers to.</param>
/// <param name="HeadDigest">Digest of the newest entry at that moment.</param>
/// <param name="Detail">Operator-facing detail (the verdict or the tip summary).</param>
public readonly record struct StoreFingerprintAlarm(
	string Kind,
	string State,
	int EntryCount,
	string HeadDigest,
	string Detail);

/// <summary>Mirrors the fingerprint chain's key facts to a store outside the integrity folder.</summary>
public interface IStoreFingerprintAlarmSink
{
	/// <summary>True when this sink can actually publish on the current host. False means the facts are not
	/// mirrored anywhere, which callers must record rather than ignore.</summary>
	bool IsAvailable { get; }

	/// <summary>Why the sink is unavailable, in operator-facing English; empty when it is available.</summary>
	string UnavailableReason { get; }

	/// <summary>Publishes one fact. Never throws: a mirror that can fail the caller is worse than no mirror,
	/// because losing a mirror must not lose the store-integrity report it accompanies.</summary>
	void Publish(StoreFingerprintAlarm alarm);
}

/// <summary>Writes the fact into the Windows Application event log under the source the installation
/// already registered for the service. It never creates the source (see the file header).</summary>
public sealed class WindowsEventLogStoreFingerprintAlarmSink : IStoreFingerprintAlarmSink
{
	/// <summary>Event source shared with the Serilog EventLog sink configured in Program.ConfigureSerilog.
	/// The installation registers it; this type only writes to it.</summary>
	internal const string SourceName = "RdpAuditService";

	/// <summary>Event id for a clean-shutdown tip. Stable so an operator can filter on it.</summary>
	internal const int CleanShutdownTipEventId = 6100;

	/// <summary>Event id for a chain verdict that is not Ok.</summary>
	internal const int ChainStateAlarmEventId = 6101;

	private readonly ILogger<WindowsEventLogStoreFingerprintAlarmSink> _logger;
	private readonly Lazy<bool> _available;

	public WindowsEventLogStoreFingerprintAlarmSink(ILogger<WindowsEventLogStoreFingerprintAlarmSink> logger)
	{
		ArgumentNullException.ThrowIfNull(logger);
		_logger = logger;
		_available = new Lazy<bool>(ProbeSource, isThreadSafe: true);
	}

	/// <inheritdoc />
	public bool IsAvailable => _available.Value;

	/// <inheritdoc />
	public string UnavailableReason => IsAvailable
		? string.Empty
		: "The Windows event-log source \"" + SourceName + "\" does not exist on this host (or the event log "
			+ "could not be queried), so the fingerprint facts are not mirrored there. The source is registered "
			+ "by the installation; this service never creates it at runtime.";

	/// <inheritdoc />
	public void Publish(StoreFingerprintAlarm alarm)
	{
		if (!IsAvailable)
		{
			return;
		}

		try
		{
			EventLogEntryType type = string.Equals(alarm.State, "Ok", StringComparison.Ordinal)
				? EventLogEntryType.Information
				: EventLogEntryType.Warning;
			int eventId = string.Equals(alarm.Kind, "CleanShutdownTip", StringComparison.Ordinal)
				? CleanShutdownTipEventId
				: ChainStateAlarmEventId;

			string body = string.Format(
				CultureInfo.InvariantCulture,
				"RdpAudit store-fingerprint chain mirror (B19){0}"
				+ "Kind     : {1}{0}"
				+ "State    : {2}{0}"
				+ "Entries  : {3}{0}"
				+ "Head     : {4}{0}"
				+ "Detail   : {5}{0}"
				+ "This record exists so a deleted or rewritten fingerprint chain leaves a trace outside "
				+ "%ProgramData%\\RdpAudit\\integrity. It does not make the chain unforgeable.",
				Environment.NewLine,
				alarm.Kind,
				alarm.State,
				alarm.EntryCount.ToString(CultureInfo.InvariantCulture),
				alarm.HeadDigest,
				alarm.Detail);

			EventLog.WriteEntry(SourceName, body, type, eventId);
		}
		catch (Exception ex) when (ex is InvalidOperationException or System.Security.SecurityException
			or UnauthorizedAccessException or ArgumentException or System.ComponentModel.Win32Exception)
		{
			// Best effort by contract: the OperationLog row and the anomaly marker are the authoritative
			// records, and neither may be lost because the event log rejected a mirror write.
			_logger.LogWarning(ex, "The store-fingerprint fact could not be mirrored to the Windows event log");
		}
	}

	private bool ProbeSource()
	{
		try
		{
			return OperatingSystem.IsWindows() && EventLog.SourceExists(SourceName);
		}
		catch (Exception ex) when (ex is System.Security.SecurityException or InvalidOperationException
			or UnauthorizedAccessException or System.ComponentModel.Win32Exception or PlatformNotSupportedException)
		{
			// A host that forbids reading the event-log registry has no usable source from this process's
			// point of view: report unavailable rather than assume one exists.
			_logger.LogDebug(ex, "The Windows event-log source {Source} could not be queried", SourceName);
			return false;
		}
	}
}

/// <summary>A sink that mirrors nothing. Used where no event log exists (tests, non-Windows) so the
/// limitation is explicit and observable through <see cref="IsAvailable"/> instead of hidden in a null.</summary>
public sealed class NullStoreFingerprintAlarmSink : IStoreFingerprintAlarmSink
{
	/// <summary>Shared instance.</summary>
	public static readonly NullStoreFingerprintAlarmSink Instance = new();

	/// <inheritdoc />
	public bool IsAvailable => false;

	/// <inheritdoc />
	public string UnavailableReason =>
		"No mirror sink is configured on this host, so the fingerprint facts are recorded only in the "
		+ "integrity folder, the operation log and the (DPAPI-protected) sealed tip.";

	/// <inheritdoc />
	public void Publish(StoreFingerprintAlarm alarm)
	{
		// Intentionally empty: this sink exists to make "nothing is mirrored" a visible state.
	}
}
