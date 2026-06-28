// File:    src/RdpAudit.Configurator/Services/ServiceOperationResult.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Reusable result model for Service tab actions (Start / Stop / Restart /
//          Uninstall) so every action surfaces a consistent, user-actionable
//          payload: per-step success, final service status, PID when running,
//          captured sc.exe / ServiceController output, exception detail, and a
//          UTC timestamp. Replaces the previous ad-hoc MessageBox strings.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;

namespace RdpAudit.Configurator.Services;

/// <summary>One step inside a service operation (e.g. "Stop service", "sc delete").</summary>
public sealed record ServiceOperationStep(
	string Description,
	bool Ok,
	string? Detail = null);

/// <summary>Aggregate result for a single Service tab action.</summary>
public sealed record ServiceOperationResult(
	string Action,
	string ServiceName,
	string DisplayName,
	bool Success,
	string FinalState,
	int? ProcessId,
	string? ExecutablePath,
	DateTime? ProcessStartTimeUtc,
	IReadOnlyList<ServiceOperationStep> Steps,
	DateTime TimestampUtc,
	string? LogFilePath = null)
{
	/// <summary>Renders the result in the multi-line "OK / FAIL" shape the rest of the
	/// Configurator already uses for install/backup/restore outcomes.</summary>
	public string Format()
	{
		StringBuilder sb = new();
		sb.Append("Action:        ").AppendLine(Action);
		sb.Append("Service:       ").Append(DisplayName).Append(" (").Append(ServiceName).AppendLine(")");
		sb.Append("Final state:   ").AppendLine(FinalState);
		if (ProcessId is int pid)
		{
			sb.Append("PID:           ").AppendLine(pid.ToString(CultureInfo.InvariantCulture));
		}

		if (!string.IsNullOrEmpty(ExecutablePath))
		{
			sb.Append("Executable:    ").AppendLine(ExecutablePath);
		}

		if (ProcessStartTimeUtc is DateTime started)
		{
			sb.Append("Process start: ").AppendLine(started.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture));
		}

		sb.Append("Timestamp:     ").AppendLine(TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture));
		if (!string.IsNullOrEmpty(LogFilePath))
		{
			sb.Append("Log file:      ").AppendLine(LogFilePath);
		}

		sb.AppendLine();
		foreach (ServiceOperationStep step in Steps)
		{
			sb.Append(step.Ok ? "OK   " : "FAIL ");
			sb.Append(step.Description);
			if (!string.IsNullOrEmpty(step.Detail))
			{
				sb.Append(" — ").Append(step.Detail);
			}

			sb.AppendLine();
		}

		return sb.ToString();
	}
}
