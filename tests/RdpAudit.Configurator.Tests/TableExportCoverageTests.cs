// File:    tests/RdpAudit.Configurator.Tests/TableExportCoverageTests.cs
// Module:  RdpAudit.Configurator.Tests
// Purpose: Keeps the tabular Export submenu from silently disappearing from a table. The requirement
//          is "every table and every list can export its selected rows", and a page that gains a new
//          grid — or an existing page whose menu is rebuilt — would otherwise lose the feature with
//          nothing turning red. The test enumerates the grids and lists declared in the Configurator
//          and asserts each one is wired to one of the shared export helpers, so the coverage claim in
//          docs/30-configurator.md stays true as the UI grows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class TableExportCoverageTests
{
	private static readonly Regex GridFieldPattern = new(
		@"private\s+readonly\s+DataGridView\s+(_[A-Za-z0-9]+)\s*;",
		RegexOptions.None,
		TimeSpan.FromSeconds(5));

	private static readonly Regex ListFieldPattern = new(
		@"private\s+readonly\s+ListView\s+(_[A-Za-z0-9]+)\s*;",
		RegexOptions.None,
		TimeSpan.FromSeconds(5));

	/// <summary>
	/// Every declared grid must appear as the target of one of the export helpers. Grids that build
	/// their own context menu pass themselves to AppendExportSubmenu from that menu builder, so the
	/// field name is searched across the whole file rather than next to a specific call.
	/// </summary>
	[Fact]
	public void EveryGrid_IsWiredToTheExportSubmenu()
	{
		List<string> missing = new();
		foreach (string path in EnumerateConfiguratorSources())
		{
			string text = File.ReadAllText(path);
			foreach (Match match in GridFieldPattern.Matches(text))
			{
				string field = match.Groups[1].Value;
				if (!IsWired(text, field, RelativeToConfigurator(path)))
				{
					missing.Add(RelativeToConfigurator(path) + " :: " + field);
				}
			}
		}

		Assert.True(missing.Count == 0,
			"These DataGridView fields have no Export Selected Rows submenu. Wire them with "
			+ "DataGridClipboardMenu.AttachWithExport(...) or AppendExportSubmenu(...): "
			+ string.Join("; ", missing));
	}

	[Fact]
	public void EveryListView_IsWiredToTheExportSubmenu()
	{
		List<string> missing = new();
		foreach (string path in EnumerateConfiguratorSources())
		{
			string text = File.ReadAllText(path);
			foreach (Match match in ListFieldPattern.Matches(text))
			{
				string field = match.Groups[1].Value;
				if (!IsWired(text, field, RelativeToConfigurator(path)))
				{
					missing.Add(RelativeToConfigurator(path) + " :: " + field);
				}
			}
		}

		Assert.True(missing.Count == 0,
			"These ListView fields have no Export Selected Rows submenu. Wire them with "
			+ "ListViewClipboardMenu.AttachWithExport(...): " + string.Join("; ", missing));
	}

	/// <summary>The shared writer must stay the only place that maps an extension to a format, so the
	/// per-page export code cannot grow a second, diverging implementation.</summary>
	[Fact]
	public void OnlyTheSharedWriter_DecidesTheFormatFromTheExtension()
	{
		List<string> offenders = new();
		foreach (string path in EnumerateConfiguratorSources())
		{
			string text = StripComments(File.ReadAllText(path));
			// A hand-rolled extension comparison would look like this; the shared helper exists so no
			// page needs one.
			if (Regex.IsMatch(text, @"""\.csv""|""\.json""|""\.txt""|""\.md""", RegexOptions.None, TimeSpan.FromSeconds(5)))
			{
				offenders.Add(RelativeToConfigurator(path));
			}
		}

		Assert.True(offenders.Count == 0,
			"These files compare file extensions by hand instead of calling TabularExportWriter."
			+ "TryGetFormatForFile: " + string.Join("; ", offenders));
	}

	/// <summary>
	/// Pages that own a bespoke, richer Export submenu instead of the shared one. Listed explicitly
	/// rather than pattern-matched, so the exclusion is a written decision and a new page cannot
	/// quietly join the list: adding one here is a deliberate edit to this test.
	/// </summary>
	private static readonly Dictionary<string, string> PagesWithOwnExportWiring = new(StringComparer.Ordinal)
	{
		["Forms/AttackStatisticsPage.cs"] =
			"RDP Activity builds its three-level Export submenu (Selected / Red / Yellow / All Rows × "
			+ "JSON / TXT / Markdown / CSV) directly on its own ContextMenuStrip.",
	};

	/// <summary>
	/// True when the field reaches an export helper. Three shapes count:
	/// <list type="number">
	/// <item>the helper is called on the same line as the field;</item>
	/// <item>the field is passed to a private method of the same file whose body calls a helper — the
	/// Firewall page builds its menus in one shared method and passes each grid in as an argument;</item>
	/// <item>the page is listed in <see cref="PagesWithOwnExportWiring"/>.</item>
	/// </list>
	/// </summary>
	private static bool IsWired(string fileText, string field, string relativePath)
	{
		if (PagesWithOwnExportWiring.ContainsKey(relativePath))
		{
			return true;
		}

		HashSet<string> menuBuilderMethods = FindMenuBuilderMethods(fileText);
		foreach (string line in fileText.Split('\n'))
		{
			bool isHelperCall = line.Contains("AttachWithExport(", StringComparison.Ordinal)
				|| line.Contains("AppendExportSubmenu(", StringComparison.Ordinal);
			bool isBuilderCall = menuBuilderMethods.Any(
				method => line.Contains(method, StringComparison.Ordinal));
			if ((isHelperCall || isBuilderCall) && line.Contains(field, StringComparison.Ordinal))
			{
				return true;
			}
		}

		return false;
	}

	/// <summary>Names of private methods in this file whose body calls one of the export helpers.</summary>
	private static HashSet<string> FindMenuBuilderMethods(string fileText)
	{
		HashSet<string> methods = new(StringComparer.Ordinal);
		MatchCollection declarations = Regex.Matches(
			fileText,
			@"private\s+(?:static\s+)?[A-Za-z0-9_<>,\[\]\?]+\s+([A-Za-z0-9_]+)\s*\(",
			RegexOptions.None,
			TimeSpan.FromSeconds(5));

		foreach (Match declaration in declarations)
		{
			string name = declaration.Groups[1].Value;
			if (name is "AttachWithExport" or "AppendExportSubmenu")
			{
				continue;
			}

			int bodyStart = fileText.IndexOf('{', declaration.Index);
			if (bodyStart < 0)
			{
				continue;
			}

			int bodyEnd = FindBlockEnd(fileText, bodyStart);
			if (bodyEnd < 0)
			{
				continue;
			}

			string body = fileText[bodyStart..bodyEnd];
			if (body.Contains("AttachWithExport(", StringComparison.Ordinal)
				|| body.Contains("AppendExportSubmenu(", StringComparison.Ordinal))
			{
				methods.Add(name);
			}
		}

		return methods;
	}

	/// <summary>Index of the brace that closes the block opened at <paramref name="openBraceIndex"/>.</summary>
	private static int FindBlockEnd(string text, int openBraceIndex)
	{
		int depth = 0;
		for (int i = openBraceIndex; i < text.Length; i++)
		{
			switch (text[i])
			{
				case '{':
					depth++;
					break;
				case '}':
					depth--;
					if (depth == 0)
					{
						return i;
					}

					break;
				default:
					break;
			}
		}

		return -1;
	}

	private static string StripComments(string text) =>
		Regex.Replace(text, @"//[^\r\n]*", string.Empty, RegexOptions.None, TimeSpan.FromSeconds(5));

	private static IEnumerable<string> EnumerateConfiguratorSources() =>
		Directory.EnumerateFiles(ConfiguratorProjectDirectory(), "*.cs", SearchOption.AllDirectories)
			.Where(path => !IsBuildArtifact(path));

	private static bool IsBuildArtifact(string path)
	{
		string[] segments = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
		return segments.Contains("bin", StringComparer.Ordinal) || segments.Contains("obj", StringComparer.Ordinal);
	}

	private static string RelativeToConfigurator(string absolutePath) =>
		Path.GetRelativePath(ConfiguratorProjectDirectory(), absolutePath).Replace('\\', '/');

	private static string ConfiguratorProjectDirectory() =>
		Path.Combine(FindRepositoryRoot(), "src", "RdpAudit.Configurator");

	private static string FindRepositoryRoot()
	{
		DirectoryInfo? directory = new(AppContext.BaseDirectory);
		while (directory is not null)
		{
			if (File.Exists(Path.Combine(directory.FullName, "RdpAudit.sln")))
			{
				return directory.FullName;
			}

			directory = directory.Parent;
		}

		throw new InvalidOperationException(
			string.Format(
				CultureInfo.InvariantCulture,
				"Repository root (RdpAudit.sln) not found above {0}",
				AppContext.BaseDirectory));
	}
}
