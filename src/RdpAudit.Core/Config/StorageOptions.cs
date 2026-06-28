// File:    src/RdpAudit.Core/Config/StorageOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Database location, retention windows, and log retention settings.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Database location, retention, and log retention settings.</summary>
public sealed class StorageOptions
{
	public string DatabasePath { get; set; } = string.Empty;

	public int EventRetentionDays { get; set; } = 365;

	public int LogRetentionDays { get; set; } = 90;

	public int AlertRetentionDays { get; set; } = 730;

	public string LogDirectory { get; set; } = string.Empty;

	/// <summary>Retention window for rows in <c>AbuseReports</c>.
	/// Defaults to 365 days. Minimum effective value enforced by the maintenance worker is 30.</summary>
	public int AbuseReportRetentionDays { get; set; } = 365;

	/// <summary>Retention window for expired / removed rows in <c>ActiveBlocks</c>.
	/// Only rows whose <c>Status</c> is <c>Removed</c> or whose <c>ExpiresUtc</c> is in the past
	/// and is older than this window are eligible for pruning. Active rules are never deleted.
	/// Defaults to 90 days. Minimum effective value enforced by the maintenance worker is 7.</summary>
	public int ActiveBlockRetentionDays { get; set; } = 90;

	/// <summary>Retention window for stale rows in <c>AttackStats</c>. Rows whose <c>LastSeenUtc</c>
	/// has not been updated within this window are eligible for pruning. Defaults to 180 days.
	/// Minimum effective value enforced by the maintenance worker is 14.</summary>
	public int AttackStatRetentionDays { get; set; } = 180;

	/// <summary>Retention window for <c>SessionIpCorrelations</c>. Rows whose <c>LastSeenUtc</c>
	/// has not been refreshed within this window are eligible for pruning. Defaults to 30 days.
	/// Minimum effective value enforced by the maintenance worker is 7.</summary>
	public int SessionIpCorrelationRetentionDays { get; set; } = 30;

	/// <summary>Retention window for <c>RdpConnectionFacts</c>. Rows whose <c>LastSeenUtc</c> has
	/// not been refreshed within this window are eligible for pruning. Defaults to 90 days.
	/// Minimum effective value enforced by the maintenance worker is 30.</summary>
	public int RdpConnectionFactRetentionDays { get; set; } = 90;

	/// <summary>Maximum number of rows deleted from a single retention pass per table.
	/// Keeps the writer lock short on very large databases. Defaults to 50000.</summary>
	public int MaintenanceBatchSize { get; set; } = 50000;

	/// <summary>Returns the configured database path or a sensible default under ProgramData.</summary>
	public string ResolveDatabasePath()
	{
		if (!string.IsNullOrWhiteSpace(DatabasePath))
		{
			return DatabasePath;
		}

		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		return Path.Combine(programData, "RdpAudit", "rdpaudit.db");
	}

	/// <summary>Returns the configured log directory or a sensible default under ProgramData.</summary>
	public string ResolveLogDirectory()
	{
		if (!string.IsNullOrWhiteSpace(LogDirectory))
		{
			return LogDirectory;
		}

		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		return Path.Combine(programData, "RdpAudit", "logs");
	}
}
