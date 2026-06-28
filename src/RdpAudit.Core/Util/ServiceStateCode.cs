// File:    src/RdpAudit.Core/Util/ServiceStateCode.cs
// Module:  RdpAudit.Core.Util
// Purpose: Locale-stable numeric Windows SCM service state codes as returned by
//          sc.exe queryex's "STATE : <code>" line and the SERVICE_STATUS.dwCurrentState
//          win32 field. Using these constants in lifecycle decisions (button enablement,
//          "is running" checks) instead of comparing the localized textual state name
//          ("RUNNING" / "РАБОТАЕТ" / "EN COURS D'EXÉCUTION") makes the Service tab
//          behave correctly on non-English Windows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Windows SCM service state codes — stable across operator UI cultures.
/// Mirrors <c>SERVICE_STATUS.dwCurrentState</c> from <c>winsvc.h</c>.</summary>
public static class ServiceStateCode
{
	/// <summary>SERVICE_STOPPED (0x1).</summary>
	public const int Stopped = 1;

	/// <summary>SERVICE_START_PENDING (0x2).</summary>
	public const int StartPending = 2;

	/// <summary>SERVICE_STOP_PENDING (0x3).</summary>
	public const int StopPending = 3;

	/// <summary>SERVICE_RUNNING (0x4).</summary>
	public const int Running = 4;

	/// <summary>SERVICE_CONTINUE_PENDING (0x5).</summary>
	public const int ContinuePending = 5;

	/// <summary>SERVICE_PAUSE_PENDING (0x6).</summary>
	public const int PausePending = 6;

	/// <summary>SERVICE_PAUSED (0x7).</summary>
	public const int Paused = 7;
}
