// File:    src/RdpAudit.Core/Config/DiagnosticsOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Toggles verbose diagnostic logging while keeping sensitive data out of Information level.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>
/// Toggles verbose diagnostic logging.  Debug mode emits structured detail useful for
/// troubleshooting (channel restarts, channel drops, batch flush counts, alert evaluation
/// timings) without writing PII / credentials at Information level.
/// </summary>
public sealed class DiagnosticsOptions
{
	public bool DebugMode { get; set; }

	public bool LogEventXmlAtDebug { get; set; }

	public bool LogChannelDrops { get; set; } = true;

	public bool LogAlertEvaluationTimings { get; set; }

	public int MaxXmlBytesAtDebug { get; set; } = 16_384;
}
