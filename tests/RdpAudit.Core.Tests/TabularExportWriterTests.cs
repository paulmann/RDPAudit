// File:    tests/RdpAudit.Core.Tests/TabularExportWriterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the one tabular writer every Configurator export submenu funnels through. These are
//          the rules that used to be duplicated per grid and would drift: a value holding a comma, a
//          quote or a line break must be encoded identically whichever table produced it, the format
//          written into a file must be the format its extension claims, and a file name must survive
//          a source label that contains separators.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text;
using System.Text.Json;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Shared tabular export writer coverage.</summary>
public class TabularExportWriterTests
{
	private static readonly DateTime Now = new(2026, 10, 12, 9, 30, 0, DateTimeKind.Utc);

	private static TabularExportDocument Document(
		IReadOnlyList<IReadOnlyList<string>>? rows = null,
		string? filterSummary = null) => new()
		{
			Source = "Session Map",
			Scope = "Selected rows",
			GeneratedUtc = Now,
			FilterSummary = filterSummary,
			VisibleRowCount = 12,
			Columns = ["Ip", "User", "Status"],
			Rows = rows ?? [["203.0.113.7", "administrator", "active"]],
		};

	[Theory]
	[InlineData(TableExportFormat.Json, ".json")]
	[InlineData(TableExportFormat.Txt, ".txt")]
	[InlineData(TableExportFormat.Markdown, ".md")]
	[InlineData(TableExportFormat.Csv, ".csv")]
	public void GetFileExtension_IsStable(TableExportFormat format, string expected) =>
		Assert.Equal(expected, TabularExportWriter.GetFileExtension(format));

	[Fact]
	public void GetFileExtension_RejectsAnUnknownFormat() =>
		Assert.Throws<ArgumentOutOfRangeException>(() => TabularExportWriter.GetFileExtension((TableExportFormat)99));

	[Theory]
	[InlineData(".csv", TableExportFormat.Csv)]
	[InlineData("export.CSV", TableExportFormat.Csv)]
	[InlineData("export.json", TableExportFormat.Json)]
	[InlineData("export.md", TableExportFormat.Markdown)]
	[InlineData("export.markdown", TableExportFormat.Markdown)]
	[InlineData("export.txt", TableExportFormat.Txt)]
	public void TryGetFormatForFile_MapsEveryOfferedExtension(string fileName, TableExportFormat expected)
	{
		Assert.True(TabularExportWriter.TryGetFormatForFile(fileName, out TableExportFormat format));
		Assert.Equal(expected, format);
	}

	[Theory]
	[InlineData("export.xlsx")]
	[InlineData("export")]
	[InlineData("export.json.bak")]
	[InlineData(null)]
	[InlineData("   ")]
	public void TryGetFormatForFile_RefusesAnythingItCannotHonour(string? fileName)
	{
		// Refusing is the point: the caller must not write JSON into a file named .xlsx.
		Assert.False(TabularExportWriter.TryGetFormatForFile(fileName, out _));
	}

	[Fact]
	public void Json_CarriesTheEnvelopeAndRowsAsArrays()
	{
		using JsonDocument parsed = JsonDocument.Parse(
			TabularExportWriter.Format(Document(), TableExportFormat.Json));
		JsonElement root = parsed.RootElement;

		Assert.Equal(TabularExportWriter.JsonSchema, root.GetProperty("schema").GetString());
		Assert.Equal("Session Map", root.GetProperty("source").GetString());
		Assert.Equal("Selected rows", root.GetProperty("scope").GetString());
		Assert.Equal("2026-10-12 09:30:00", root.GetProperty("generatedUtc").GetString());
		Assert.Equal(1, root.GetProperty("rowCount").GetInt32());
		Assert.Equal(12, root.GetProperty("visibleRowCount").GetInt32());
		Assert.Equal(3, root.GetProperty("columns").GetArrayLength());
		Assert.Equal("203.0.113.7", root.GetProperty("rows")[0][0].GetString());
	}

	/// <summary>Two columns with the same header text must both survive: rows are arrays, not a map.</summary>
	[Fact]
	public void DuplicateColumnHeaders_DoNotDropAColumn()
	{
		TabularExportDocument document = new()
		{
			Source = "Duplicate headers",
			Scope = "All rows",
			GeneratedUtc = Now,
			VisibleRowCount = 1,
			Columns = ["Value", "Value"],
			Rows = [["left", "right"]],
		};

		using JsonDocument parsed = JsonDocument.Parse(TabularExportWriter.Format(document, TableExportFormat.Json));
		JsonElement row = parsed.RootElement.GetProperty("rows")[0];

		Assert.Equal(2, row.GetArrayLength());
		Assert.Equal("left", row[0].GetString());
		Assert.Equal("right", row[1].GetString());

		string csv = TabularExportWriter.Format(document, TableExportFormat.Csv);
		Assert.Contains("left,right", csv, StringComparison.Ordinal);
	}

	[Fact]
	public void Csv_QuotesCellsHoldingACommaOrAQuote_AndNeutralisesLineBreaks()
	{
		TabularExportDocument document = Document([["10.0.0.1", "Public, \"hosted\"", "line\r\nbreak"]]);

		string csv = TabularExportWriter.Format(document, TableExportFormat.Csv);
		string[] lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);

		// Preamble comment + header + exactly one row: the embedded CR/LF must not become a new record.
		Assert.Equal(3, lines.Length);
		Assert.Contains("\"Public, \"\"hosted\"\"\"", csv, StringComparison.Ordinal);
		Assert.DoesNotContain('\t', csv);
		foreach (string line in lines)
		{
			Assert.DoesNotContain('\r', line.TrimEnd('\r'));
		}
	}

	[Fact]
	public void Csv_RecordsItsProvenanceBeforeTheHeader()
	{
		string csv = TabularExportWriter.Format(Document(filterSummary: "IP contains 203."), TableExportFormat.Csv);
		string[] lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);

		Assert.StartsWith("# RdpAudit export;", lines[0], StringComparison.Ordinal);
		Assert.Contains("scope=Selected rows", lines[0], StringComparison.Ordinal);
		Assert.Contains("filters=IP contains 203.", lines[0], StringComparison.Ordinal);
		Assert.StartsWith("Ip,User,Status", lines[1], StringComparison.Ordinal);
	}

	[Fact]
	public void Csv_StatesWhenNothingWasFiltered()
	{
		string csv = TabularExportWriter.Format(Document(), TableExportFormat.Csv);

		Assert.Contains("filters=(none)", csv, StringComparison.Ordinal);
	}

	[Fact]
	public void Markdown_EscapesPipesAndKeepsTheTableShape()
	{
		TabularExportDocument document = Document([["10.0.0.1", "user|name", "active"]]);

		string markdown = TabularExportWriter.Format(document, TableExportFormat.Markdown);

		Assert.Contains("\\|", markdown, StringComparison.Ordinal);
		foreach (string line in markdown.Split('\n', StringSplitOptions.RemoveEmptyEntries))
		{
			if (!line.StartsWith("| ", StringComparison.Ordinal))
			{
				continue;
			}

			// Each rendered table line carries structural pipes for 3 columns; an escaped "\|" is
			// content, so it is not counted.
			int structural = 0;
			for (int i = 0; i < line.Length; i++)
			{
				if (line[i] == '|' && (i == 0 || line[i - 1] != '\\'))
				{
					structural++;
				}
			}

			Assert.Equal(4, structural);
		}
	}

	[Fact]
	public void Txt_ListsTheHeaderLineThenOneLinePerRow()
	{
		TabularExportDocument document = Document([["10.0.0.1", "bob", "active"], ["10.0.0.2", "ann", "idle"]]);

		string txt = TabularExportWriter.Format(document, TableExportFormat.Txt);
		// AppendLine writes the platform newline, so splitting on '\n' leaves a trailing '\r' on every
		// record. The contract under test is the record text, not the platform's line terminator.
		string[] lines = txt
			.Split('\n', StringSplitOptions.RemoveEmptyEntries)
			.Select(line => line.TrimEnd('\r'))
			.ToArray();

		Assert.Contains(lines, l => l == "Ip\tUser\tStatus");
		Assert.Contains(lines, l => l == "10.0.0.1\tbob\tactive");
		Assert.Contains(lines, l => l == "10.0.0.2\tann\tidle");
		Assert.Contains("Table: Session Map", lines);
	}

	[Fact]
	public void EmptyRowSet_StillProducesEveryFormatWithoutThrowing()
	{
		TabularExportDocument empty = Document(rows: []);

		foreach (TableExportFormat format in Enum.GetValues<TableExportFormat>())
		{
			string body = TabularExportWriter.Format(empty, format);
			Assert.False(string.IsNullOrWhiteSpace(body));
		}

		using JsonDocument parsed = JsonDocument.Parse(TabularExportWriter.Format(empty, TableExportFormat.Json));
		Assert.Equal(0, parsed.RootElement.GetProperty("rowCount").GetInt32());

		string csv = TabularExportWriter.Format(empty, TableExportFormat.Csv);
		Assert.Contains("Ip,User,Status", csv, StringComparison.Ordinal);

		string txt = TabularExportWriter.Format(empty, TableExportFormat.Txt);
		Assert.Contains("(no rows in this scope)", txt, StringComparison.Ordinal);
	}

	[Fact]
	public void FileNaming_UsesTheSourceScopeAndFormat()
	{
		string name = TabularExportWriter.GetDefaultFileName("Session Map", "Selected rows", TableExportFormat.Markdown, Now);

		Assert.Equal("rdpaudit-session-map-selected-rows-20261012-093000.md", name);
	}

	[Fact]
	public void FileNaming_SanitisesSeparatorsInTheSourceLabel()
	{
		string name = TabularExportWriter.GetDefaultFileName(
			"Database / Shards * (store)",
			"All rows",
			TableExportFormat.Csv,
			Now);

		Assert.Equal("rdpaudit-database-shards-store-all-rows-20261012-093000.csv", name);
		Assert.DoesNotContain('/', name);
		Assert.DoesNotContain('*', name);
		Assert.DoesNotContain('(', name);
	}

	[Fact]
	public void FileNaming_FallsBackWhenTheLabelHasNothingUsable()
	{
		string name = TabularExportWriter.GetDefaultFileName("///", "---", TableExportFormat.Json, Now);

		Assert.StartsWith("rdpaudit-table-table-", name, StringComparison.Ordinal);
	}

	[Fact]
	public void SaveFilter_OffersEveryFormat()
	{
		string filter = TabularExportWriter.GetCombinedSaveFileFilter();

		Assert.Contains("JSON (*.json)|*.json", filter, StringComparison.Ordinal);
		Assert.Contains("Text (*.txt)|*.txt", filter, StringComparison.Ordinal);
		Assert.Contains("Markdown (*.md)|*.md", filter, StringComparison.Ordinal);
		Assert.Contains("CSV (*.csv)|*.csv", filter, StringComparison.Ordinal);
	}

	[Fact]
	public void SanitiseCell_ReplacesTabsAndNewlines()
	{
		Assert.Equal("a b c", TabularExportWriter.SanitiseCell("a\tb\nc"));
		Assert.Equal(string.Empty, TabularExportWriter.SanitiseCell(null));
		Assert.Equal(string.Empty, TabularExportWriter.SanitiseCell(string.Empty));
	}

	[Fact]
	public void AppendCsvCell_QuotesOnlyWhenRequired()
	{
		StringBuilder plain = new();
		TabularExportWriter.AppendCsvCell(plain, "plain");
		Assert.Equal("plain", plain.ToString());

		StringBuilder quoted = new();
		TabularExportWriter.AppendCsvCell(quoted, "a,b");
		Assert.Equal("\"a,b\"", quoted.ToString());

		StringBuilder escaped = new();
		TabularExportWriter.AppendCsvCell(escaped, "say \"hi\"");
		Assert.Equal("\"say \"\"hi\"\"\"", escaped.ToString());
	}

	[Theory]
	[InlineData("=1+1", "'=1+1")]
	[InlineData("=cmd|' /c calc'!A0", "'=cmd|' /c calc'!A0")]
	[InlineData("@SUM(A1)", "'@SUM(A1)")]
	[InlineData("+7", "'+7")]
	[InlineData("-SUM(A1)", "'-SUM(A1)")]
	[InlineData("-7", "-7")]
	[InlineData("-7.25", "-7.25")]
	[InlineData("contoso\\ivan", "contoso\\ivan")]
	public void AppendCsvCell_NeutralisesFormulaPrefixes(string cell, string expected)
	{
		// A user name in an exported event is whatever the attacker typed at the RDP prompt, and
		// Excel evaluates a cell that starts with '=', '+', '-' or '@'. The guard must be applied
		// to the CSV path only, and must not turn a negative number into text.
		StringBuilder sb = new();
		TabularExportWriter.AppendCsvCell(sb, cell);

		Assert.Equal(expected, sb.ToString());
	}

	[Fact]
	public void NeedsFormulaGuard_IgnoresNumbersAndOrdinaryText()
	{
		Assert.True(TabularExportWriter.NeedsFormulaGuard("=1+1"));
		Assert.True(TabularExportWriter.NeedsFormulaGuard("@x"));
		Assert.False(TabularExportWriter.NeedsFormulaGuard("-7"));
		Assert.False(TabularExportWriter.NeedsFormulaGuard("."));
		Assert.False(TabularExportWriter.NeedsFormulaGuard("contoso\\ivan"));
		Assert.False(TabularExportWriter.NeedsFormulaGuard(string.Empty));
	}

	[Fact]
	public void Format_RejectsAnUnknownFormatAndANullDocument()
	{
		Assert.Throws<ArgumentOutOfRangeException>(
			() => TabularExportWriter.Format(Document(), (TableExportFormat)99));
		Assert.Throws<ArgumentNullException>(
			() => TabularExportWriter.Format(null!, TableExportFormat.Json));
	}
}
