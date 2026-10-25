// File:    src/RdpAudit.Core/Models/TabularExportWriter.cs
// Module:  RdpAudit.Core.Models
// Purpose: Single writer for tabular exports (JSON / TXT / Markdown / CSV) shared by every
//          Configurator grid and list that offers an Export context submenu. Holding the cell
//          sanitiser, the CSV quoter, the Markdown escaper and the extension<->format mapping in one
//          place is what keeps the tabs from drifting apart: a value containing a comma, a quote or a
//          line break must be encoded identically no matter which grid produced it, and the format
//          written into a file must always be the format its extension claims. Rendering the generic
//          document shape here also keeps per-tab code down to "hand me headers and rows".
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RdpAudit.Core.Models;

/// <summary>File formats offered by the tabular Export submenus.</summary>
/// <remarks>
/// Not persisted and never sent over IPC, so the append-only ABI contract is unaffected.
/// </remarks>
public enum TableExportFormat
{
	/// <summary>Indented JSON envelope: provenance, column names and rows as value arrays.</summary>
	Json = 0,

	/// <summary>Human-readable text: provenance block followed by one line per record.</summary>
	Txt = 1,

	/// <summary>Markdown table with a header row and an alignment separator.</summary>
	Markdown = 2,

	/// <summary>Comma-separated table loadable straight into Excel.</summary>
	Csv = 3,
}

/// <summary>
/// One tabular export: what produced it, which slice it covers, the column names and the rows.
/// </summary>
/// <remarks>
/// Rows are arrays of already-formatted display strings in column order, not dictionaries. Grid
/// column headers are not guaranteed unique in WinForms, so a dictionary keyed by header would
/// silently drop a column; an ordered array cannot.
/// </remarks>
public sealed class TabularExportDocument
{
	/// <summary>Operator-facing name of the table the rows came from, e.g. <c>RDP Activity</c>.</summary>
	public string Source { get; init; } = string.Empty;

	/// <summary>Which slice of the table is covered, e.g. <c>Selected rows</c>.</summary>
	public string Scope { get; init; } = string.Empty;

	/// <summary>Export timestamp (UTC).</summary>
	public DateTime GeneratedUtc { get; init; }

	/// <summary>Description of the active filters at export time; null when none were set.</summary>
	public string? FilterSummary { get; init; }

	/// <summary>How many rows the table displayed at export time.</summary>
	public int VisibleRowCount { get; init; }

	/// <summary>Column headers in display order.</summary>
	public IReadOnlyList<string> Columns { get; init; } = [];

	/// <summary>Rows in display order; each array has exactly as many entries as <see cref="Columns"/>.</summary>
	public IReadOnlyList<IReadOnlyList<string>> Rows { get; init; } = [];
}

/// <summary>Scope filter and renderer for tabular exports.</summary>
public static class TabularExportWriter
{
	private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

	/// <summary>Schema tag written into JSON exports so a saved file identifies its own shape.</summary>
	public const string JsonSchema = "rdpaudit.table-export/v1";

	private static readonly JsonSerializerOptions JsonOptions = new()
	{
		WriteIndented = true,
		Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,

		// camelCase is the shape of every other JSON file this product writes (Core/Util/JsonOptions.cs);
		// an export in PascalCase would be the one file an operator's script could not read uniformly.
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		Converters = { new JsonStringEnumConverter() },
	};

	/// <summary>Renders a document into <paramref name="format"/>.</summary>
	/// <exception cref="ArgumentNullException"><paramref name="document"/> is null.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is not a defined value.</exception>
	public static string Format(TabularExportDocument document, TableExportFormat format)
	{
		ArgumentNullException.ThrowIfNull(document);

		return format switch
		{
			TableExportFormat.Json => FormatJson(document),
			TableExportFormat.Txt => FormatTxt(document),
			TableExportFormat.Markdown => FormatMarkdown(document),
			TableExportFormat.Csv => FormatCsv(document),
			_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
		};
	}

	// ── Low-level encoders shared by every tabular export ─────────────────────────

	/// <summary>Replaces tab / CR / LF with spaces so one record always stays on one line. Null and
	/// empty both become an empty cell: the grid's own display text is the source of truth, and a
	/// literal "null" typed into a report is worse than a blank.</summary>
	public static string SanitiseCell(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		StringBuilder sb = new(value.Length);
		foreach (char c in value)
		{
			sb.Append(c is '\r' or '\n' or '\t' ? ' ' : c);
		}

		return sb.ToString();
	}

	/// <summary>Appends one CSV cell, quoting (and doubling internal quotes) only when required.</summary>
	/// <remarks>
	/// A cell that begins with '=', '+', '-' or '@' is a formula to Excel, LibreOffice and Google
	/// Sheets. These exports carry event fields, and a user name or a process name is whatever the
	/// person on the other side of the RDP connection typed, so a file opened by an operator would
	/// otherwise evaluate text chosen by the attacker. Such a cell is prefixed with an apostrophe,
	/// which every spreadsheet application treats as "this is text".
	/// </remarks>
	public static void AppendCsvCell(StringBuilder sb, string? value)
	{
		ArgumentNullException.ThrowIfNull(sb);
		string clean = SanitiseCell(value);
		if (clean.Length == 0)
		{
			return;
		}

		if (NeedsFormulaGuard(clean))
		{
			clean = "'" + clean;
		}

		bool needsQuoting = clean.Contains(',', StringComparison.Ordinal)
			|| clean.Contains('"', StringComparison.Ordinal);
		if (!needsQuoting)
		{
			sb.Append(clean);
			return;
		}

		sb.Append('"');
		foreach (char c in clean)
		{
			if (c == '"')
			{
				sb.Append('"').Append('"');
			}
			else
			{
				sb.Append(c);
			}
		}
		sb.Append('"');
	}

	/// <summary>True when a spreadsheet would evaluate the cell as a formula instead of text.</summary>
	/// <remarks>
	/// The leading '-' of a number ("-7", "-7.25") is not a formula trigger: guarding it would turn
	/// a numeric column into text and break every consumer of the export.
	/// </remarks>
	internal static bool NeedsFormulaGuard(string cell)
	{
		if (string.IsNullOrEmpty(cell))
		{
			return false;
		}

		char first = cell[0];
		if (first is not ('=' or '+' or '-' or '@'))
		{
			return false;
		}

		bool negativeNumber = first == '-'
			&& cell.Length > 1
			&& (char.IsAsciiDigit(cell[1]) || cell[1] == '.');

		return !negativeNumber;
	}

	/// <summary>Escapes a value for a Markdown table cell.</summary>
	public static string EscapeMarkdown(string? value) =>
		SanitiseCell(value).Replace("|", "\\|", StringComparison.Ordinal);

	/// <summary>Returns the canonical file extension (lower-case, with leading dot) for a format.</summary>
	public static string GetFileExtension(TableExportFormat format) => format switch
	{
		TableExportFormat.Json => ".json",
		TableExportFormat.Txt => ".txt",
		TableExportFormat.Markdown => ".md",
		TableExportFormat.Csv => ".csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Returns a single SaveFileDialog filter line for a format.</summary>
	public static string GetSaveFileFilter(TableExportFormat format) => format switch
	{
		TableExportFormat.Json => "JSON (*.json)|*.json",
		TableExportFormat.Txt => "Text (*.txt)|*.txt",
		TableExportFormat.Markdown => "Markdown (*.md)|*.md",
		TableExportFormat.Csv => "CSV (*.csv)|*.csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Combined filter offered by the save dialog: the operator picks the format with the file name.</summary>
	public static string GetCombinedSaveFileFilter() =>
		string.Join('|',
			GetSaveFileFilter(TableExportFormat.Json),
			GetSaveFileFilter(TableExportFormat.Txt),
			GetSaveFileFilter(TableExportFormat.Markdown),
			GetSaveFileFilter(TableExportFormat.Csv),
			"All files (*.*)|*.*");

	/// <summary>
	/// Maps a file name or extension to the format to write into it. Returns false for an unknown
	/// extension, which lets the caller refuse rather than write JSON into a file named <c>.xlsx</c>.
	/// </summary>
	public static bool TryGetFormatForFile(string? fileNameOrExtension, out TableExportFormat format)
	{
		format = TableExportFormat.Json;
		if (string.IsNullOrWhiteSpace(fileNameOrExtension))
		{
			return false;
		}

		string candidate = fileNameOrExtension.Trim();
		int dot = candidate.LastIndexOf('.');
		string extension = dot < 0 ? candidate : candidate[dot..];
		switch (extension.ToLowerInvariant())
		{
			case ".json":
				format = TableExportFormat.Json;
				return true;
			case ".txt":
				format = TableExportFormat.Txt;
				return true;
			case ".md":
			case ".markdown":
				format = TableExportFormat.Markdown;
				return true;
			case ".csv":
				format = TableExportFormat.Csv;
				return true;
			default:
				return false;
		}
	}

	/// <summary>Replaces filesystem-unsafe characters so a source or scope label can be used in a file name.</summary>
	public static string SanitiseFileNameSegment(string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return "table";
		}

		StringBuilder sb = new(raw.Length);
		foreach (char c in raw.Trim())
		{
			bool safe = char.IsLetterOrDigit(c) || c is '-' or '_';
			sb.Append(safe ? char.ToLowerInvariant(c) : '-');
		}

		// Collapse runs of dashes introduced by spaces / punctuation so the name stays readable.
		string collapsed = sb.ToString().Trim('-');
		while (collapsed.Contains("--", StringComparison.Ordinal))
		{
			collapsed = collapsed.Replace("--", "-", StringComparison.Ordinal);
		}

		return collapsed.Length == 0 ? "table" : collapsed;
	}

	/// <summary>Builds the default file name: <c>rdpaudit-{source}-{scope}-{utc}.{ext}</c>.</summary>
	public static string GetDefaultFileName(
		string sourceToken,
		string scopeToken,
		TableExportFormat format,
		DateTime nowUtc) =>
		string.Format(
			CultureInfo.InvariantCulture,
			"rdpaudit-{0}-{1}-{2}{3}",
			SanitiseFileNameSegment(sourceToken),
			SanitiseFileNameSegment(scopeToken),
			nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture),
			GetFileExtension(format));

	// ── Generic document renderers ────────────────────────────────────────────────

	private static string FormatJson(TabularExportDocument document)
	{
		RowsExportEnvelope envelope = new()
		{
			Schema = JsonSchema,
			Source = document.Source,
			Scope = document.Scope,
			GeneratedUtc = document.GeneratedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture),
			RowCount = document.Rows.Count,
			VisibleRowCount = document.VisibleRowCount,
			Filters = DescribeFilters(document.FilterSummary),
			Columns = document.Columns,
			Rows = document.Rows,
		};

		return JsonSerializer.Serialize(envelope, JsonOptions);
	}

	private static string FormatTxt(TabularExportDocument document)
	{
		StringBuilder sb = new();
		sb.Append("=== RdpAudit — export: ").Append(document.Source).AppendLine(" ===");
		AppendProvenance(sb, document, prefix: string.Empty);
		sb.AppendLine();
		if (document.Rows.Count == 0)
		{
			sb.AppendLine("(no rows in this scope)");
			return sb.ToString().TrimEnd('\r', '\n');
		}

		sb.AppendLine(string.Join('\t', document.Columns.Select(SanitiseCell)));
		foreach (IReadOnlyList<string> row in document.Rows)
		{
			sb.AppendLine(string.Join('\t', row.Select(SanitiseCell)));
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatMarkdown(TabularExportDocument document)
	{
		StringBuilder sb = new();
		sb.Append("# RdpAudit — export: ").Append(document.Source).AppendLine();
		sb.AppendLine();
		sb.AppendLine("## Scope");
		sb.AppendLine();
		AppendProvenance(sb, document, prefix: "- ");
		sb.AppendLine();
		sb.Append("## Rows — ").Append(document.Rows.Count.ToString(CultureInfo.InvariantCulture)).AppendLine(" row(s)");
		sb.AppendLine();
		sb.Append('|').Append(string.Join('|', document.Columns.Select(c => " " + EscapeMarkdown(c) + " "))).AppendLine("|");
		sb.Append('|').Append(string.Join('|', document.Columns.Select(_ => "---"))).AppendLine("|");
		foreach (IReadOnlyList<string> row in document.Rows)
		{
			sb.Append('|');
			foreach (string value in row)
			{
				sb.Append(' ').Append(EscapeMarkdown(value)).Append(" |");
			}

			sb.AppendLine();
		}

		if (document.Rows.Count == 0)
		{
			sb.Append('|').Append(string.Join('|', document.Columns.Select(_ => " (none) "))).AppendLine("|");
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatCsv(TabularExportDocument document)
	{
		StringBuilder sb = new();
		// Provenance as leading '#' comment lines, so a file found later on disk still states what it is.
		sb.Append("# RdpAudit export; source=").Append(SanitiseCell(document.Source));
		sb.Append("; scope=").Append(SanitiseCell(document.Scope));
		sb.Append("; rows=").Append(document.Rows.Count.ToString(CultureInfo.InvariantCulture));
		sb.Append("; generatedUtc=").Append(document.GeneratedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		sb.Append("; filters=").AppendLine(SanitiseCell(DescribeFilters(document.FilterSummary)));

		AppendCsvLine(sb, document.Columns);
		foreach (IReadOnlyList<string> row in document.Rows)
		{
			AppendCsvLine(sb, row);
		}

		return sb.ToString();
	}

	private static void AppendCsvLine(StringBuilder sb, IReadOnlyList<string> values)
	{
		for (int i = 0; i < values.Count; i++)
		{
			if (i > 0)
			{
				sb.Append(',');
			}

			AppendCsvCell(sb, values[i]);
		}

		sb.AppendLine();
	}

	private static void AppendProvenance(StringBuilder sb, TabularExportDocument document, string prefix)
	{
		sb.Append(prefix).Append("Table: ").AppendLine(document.Source);
		sb.Append(prefix).Append("Scope: ").AppendLine(document.Scope);
		sb.Append(prefix).Append("Rows exported: ").AppendLine(document.Rows.Count.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Rows displayed: ").AppendLine(document.VisibleRowCount.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Filters: ").AppendLine(DescribeFilters(document.FilterSummary));
		sb.Append(prefix).Append("Generated (UTC): ").AppendLine(document.GeneratedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
	}

	private static string DescribeFilters(string? filterSummary) =>
		string.IsNullOrWhiteSpace(filterSummary) ? "(none)" : filterSummary!;

	/// <summary>
	/// Serialisation envelope. A property-initialised class (not a positional record) keeps the emitted
	/// key order equal to the declaration order regardless of compiler updates.
	/// </summary>
	private sealed class RowsExportEnvelope
	{
		public string Schema { get; init; } = string.Empty;

		public string Source { get; init; } = string.Empty;

		public string Scope { get; init; } = string.Empty;

		public string GeneratedUtc { get; init; } = string.Empty;

		public int RowCount { get; init; }

		public int VisibleRowCount { get; init; }

		public string Filters { get; init; } = string.Empty;

		public IReadOnlyList<string> Columns { get; init; } = [];

		public IReadOnlyList<IReadOnlyList<string>> Rows { get; init; } = [];
	}
}
