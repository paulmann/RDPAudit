// File:    src/RdpAudit.Core/Models/AttackStatRowsExportFormatter.cs
// Module:  RdpAudit.Core.Models
// Purpose: Scope filter and export entry point for the RDP Activity tab "Export" submenu (Export
//          Selected Rows / Red Rows / Yellow Rows / All Rows, each offering JSON / TXT / Markdown /
//          CSV). The actual encoders live in TabularExportWriter so every grid in the Configurator
//          writes identical formats; this type owns only what is specific to RDP Activity: the band
//          classification, the deliberate exclusion of the unresolved-IP sentinel from the Red /
//          Yellow scopes, and the projection of AttackStatEntryDto onto the shared column set.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Models;

/// <summary>Which slice of the RDP Activity grid an export covers.</summary>
/// <remarks>
/// Not persisted and never sent over IPC — the values exist only inside the Configurator process,
/// so the append-only ABI contract is unaffected by changes here.
/// </remarks>
public enum AttackStatRowScope
{
	/// <summary>Exactly the rows the operator selected in the grid.</summary>
	Selected = 0,

	/// <summary>Red-band attacker rows (high-intensity failures / likely brute force).</summary>
	RedRows = 1,

	/// <summary>Yellow-band rows (low-intensity failed connections).</summary>
	YellowRows = 2,

	/// <summary>Every row currently displayed in the grid.</summary>
	AllRows = 3,
}

/// <summary>The resolved row set for one export: the rows plus what was deliberately left out.</summary>
/// <remarks>
/// <see cref="ExcludedSentinels"/> exists so the exclusion of the unresolved-IP sentinel row from the
/// Red / Yellow scopes can never happen silently: the count is printed in every format and reported
/// on the status line.
/// </remarks>
public sealed class AttackStatRowsExportSelection
{
	/// <summary>The scope this selection was produced for.</summary>
	public AttackStatRowScope Scope { get; init; }

	/// <summary>The rows to export, in the order the grid displays them.</summary>
	public IReadOnlyList<AttackStatEntryDto> Rows { get; init; } = [];

	/// <summary>Sentinel (unresolved-IP) rows that matched the scope's band but were excluded.</summary>
	public int ExcludedSentinels { get; init; }

	/// <summary>Human-readable scope label, e.g. <c>Red rows</c>.</summary>
	public string ScopeLabel => AttackStatRowsExportFormatter.GetScopeLabel(Scope);

	/// <summary>One-line description used on the status strip and in the exported header.</summary>
	public string Describe() => ExcludedSentinels == 0
		? string.Format(CultureInfo.InvariantCulture, "{0}: {1} row(s).", ScopeLabel, Rows.Count)
		: string.Format(
			CultureInfo.InvariantCulture,
			"{0}: {1} row(s); {2} unresolved-IP row(s) excluded.",
			ScopeLabel,
			Rows.Count,
			ExcludedSentinels);
}

/// <summary>Provenance for one export, so a saved file states how it was produced.</summary>
public sealed class AttackStatRowsExportContext
{
	/// <summary>Export timestamp (UTC).</summary>
	public DateTime NowUtc { get; init; }

	/// <summary>Description of the grid filters active at export time; null when none were set.</summary>
	public string? FilterSummary { get; init; }

	/// <summary>How many rows were displayed in the grid at export time.</summary>
	public int VisibleRowCount { get; init; }
}

/// <summary>Scope filter and export entry point for RDP Activity row exports.</summary>
public static class AttackStatRowsExportFormatter
{
	/// <summary>Operator-facing table name written into the export provenance.</summary>
	public const string SourceLabel = "RDP Activity";

	/// <summary>Stable column order, matching the DTO properties one-to-one.</summary>
	private static readonly string[] ColumnNames =
	[
		"Ip",
		"ThreatScore",
		"ThreatLevel",
		"IsHighRisk",
		"ThreatIntelConfidenceScore",
		"TotalAttempts",
		"Failed",
		"Successful",
		"FirstSeenUtc",
		"LastSeenUtc",
		"DurationSeconds",
		"Top10AttemptedLogins",
		"LastLoginType",
		"IsBlocked",
		"IsUnresolved",
		"Classification",
		"FactFailedLogons",
		"FactSuccessfulLogons",
		"HasActiveConnectionFact",
		"LastUpdatedUtc",
	];

	private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

	/// <summary>Resolves the rows an export scope covers.</summary>
	/// <param name="rows">
	/// Rows to draw from. For <see cref="AttackStatRowScope.Selected"/> the caller passes exactly the
	/// selected rows; for the band scopes it passes the displayed rows, which are then filtered.
	/// </param>
	/// <param name="scope">The requested scope.</param>
	/// <remarks>
	/// The unresolved-IP sentinel row renders with the red band on screen, but it is not an attacker:
	/// it represents logon events with no resolvable source address. It is therefore excluded from the
	/// Red and Yellow scopes — and counted in <see cref="AttackStatRowsExportSelection.ExcludedSentinels"/>
	/// so the exclusion is visible rather than silent. It is kept in the All and Selected scopes.
	/// </remarks>
	public static AttackStatRowsExportSelection Select(IReadOnlyList<AttackStatEntryDto> rows, AttackStatRowScope scope)
	{
		ArgumentNullException.ThrowIfNull(rows);

		if (scope is AttackStatRowScope.AllRows or AttackStatRowScope.Selected)
		{
			return new AttackStatRowsExportSelection { Scope = scope, Rows = new List<AttackStatEntryDto>(rows) };
		}

		AttackThreatLevel wanted = scope switch
		{
			AttackStatRowScope.RedRows => AttackThreatLevel.Red,
			AttackStatRowScope.YellowRows => AttackThreatLevel.Yellow,
			_ => throw new ArgumentOutOfRangeException(nameof(scope), scope, "Unsupported export scope."),
		};

		List<AttackStatEntryDto> matched = new();
		int excluded = 0;
		foreach (AttackStatEntryDto row in rows)
		{
			if (row.ThreatLevel != wanted)
			{
				continue;
			}

			if (IsUnresolvedSentinel(row))
			{
				excluded++;
				continue;
			}

			matched.Add(row);
		}

		return new AttackStatRowsExportSelection
		{
			Scope = scope,
			Rows = matched,
			ExcludedSentinels = excluded,
		};
	}

	/// <summary>Renders a resolved selection into <paramref name="format"/> via the shared tabular writer.</summary>
	/// <exception cref="ArgumentNullException">
	/// <paramref name="selection"/> or <paramref name="context"/> is null.
	/// </exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is not a defined value.</exception>
	public static string Format(
		AttackStatRowsExportSelection selection,
		AttackStatRowsExportContext context,
		TableExportFormat format)
	{
		ArgumentNullException.ThrowIfNull(selection);
		ArgumentNullException.ThrowIfNull(context);

		return TabularExportWriter.Format(BuildDocument(selection, context), format);
	}

	/// <summary>Builds the table document handed to <see cref="TabularExportWriter"/>.
	/// Exposed so the Configurator can pass the same document to the shared save/write runner.</summary>
	public static TabularExportDocument BuildDocument(
		AttackStatRowsExportSelection selection,
		AttackStatRowsExportContext context)
	{
		ArgumentNullException.ThrowIfNull(selection);
		ArgumentNullException.ThrowIfNull(context);

		List<IReadOnlyList<string>> rows = new(selection.Rows.Count);
		foreach (AttackStatEntryDto row in selection.Rows)
		{
			rows.Add(BuildColumnValues(row));
		}

		return new TabularExportDocument
		{
			Source = SourceLabel,
			Scope = selection.ScopeLabel,
			GeneratedUtc = context.NowUtc,
			FilterSummary = AppendExclusionNote(context.FilterSummary, selection.ExcludedSentinels),
			VisibleRowCount = context.VisibleRowCount,
			Columns = ColumnNames,
			Rows = rows,
		};
	}

	/// <summary>Stable operator-facing label for a scope, used in the file header and the status line.</summary>
	public static string GetScopeLabel(AttackStatRowScope scope) => scope switch
	{
		AttackStatRowScope.Selected => "Selected rows",
		AttackStatRowScope.RedRows => "Red rows",
		AttackStatRowScope.YellowRows => "Yellow rows",
		AttackStatRowScope.AllRows => "All rows",
		_ => scope.ToString(),
	};

	/// <summary>True when a row is the unresolved-IP sentinel rather than a real attacker address.</summary>
	public static bool IsUnresolvedSentinel(AttackStatEntryDto row) =>
		row.IsUnresolved || AttackStatsAggregator.IsSentinelUnresolvedIp(row.Ip);

	/// <summary>
	/// States the sentinel exclusion in the provenance line of every format, so a file that lists
	/// fewer red rows than the grid showed explains itself instead of looking truncated.
	/// </summary>
	private static string AppendExclusionNote(string? filterSummary, int excludedSentinels)
	{
		string filters = string.IsNullOrWhiteSpace(filterSummary) ? "(none)" : filterSummary!;
		return excludedSentinels == 0
			? filters
			: string.Format(
				CultureInfo.InvariantCulture,
				"{0}; unresolved-IP rows excluded: {1}",
				filters,
				excludedSentinels);
	}

	/// <summary>Projects one row into the stable column order. Null → empty cell, never a literal null.</summary>
	private static string[] BuildColumnValues(AttackStatEntryDto row) =>
	[
		row.Ip,
		row.ThreatScore.ToString("F1", CultureInfo.InvariantCulture),
		row.ThreatLevel.ToString(),
		row.IsHighRisk ? "yes" : "no",
		row.ThreatIntelConfidenceScore.ToString(CultureInfo.InvariantCulture),
		row.TotalAttempts.ToString(CultureInfo.InvariantCulture),
		row.Failed.ToString(CultureInfo.InvariantCulture),
		row.Successful.ToString(CultureInfo.InvariantCulture),
		row.FirstSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture),
		row.LastSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture),
		row.DurationSeconds.ToString(CultureInfo.InvariantCulture),
		AttackStatRowFormatter.FormatTopLogins(row.Top10AttemptedLogins),
		row.LastLoginType?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
		row.IsBlocked ? "yes" : "no",
		row.IsUnresolved ? "yes" : "no",
		row.Classification,
		row.FactFailedLogons.ToString(CultureInfo.InvariantCulture),
		row.FactSuccessfulLogons.ToString(CultureInfo.InvariantCulture),
		row.HasActiveConnectionFact ? "yes" : "no",
		row.LastUpdatedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture),
	];
}
