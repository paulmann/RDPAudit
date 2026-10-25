/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : RepositoryHygieneScenarioTests.cs
// Project: RdpAudit.ScenarioTests
// Purpose: P3 hygiene regression scenarios, adapted to the 2.0.x repository conventions. Each test
//          walks the repository the way a reviewer would: (1) every per-file "// Version: X.Y.Z"
//          header must use the canonical strict-triplet form or be absent, (2) declared CI jobs
//          must stay on windows-latest (no Linux/macOS runner claims), and (3) CHANGELOG.md must
//          keep its machine-maintained backup journal format - a deterministic
//          "- [yyyy-MM-ddTHH:mm:ss] path" entry per line - so the platform-written records stay
//          parseable. These guards fail and name the exact file whenever a non-canonical header
//          or a stale platform claim sneaks back in.
// Depends: xunit
// Extends: Add a guard here whenever a new cross-cutting repository-hygiene contract is adopted.

using System.Text.RegularExpressions;
using Xunit;

namespace RdpAudit.ScenarioTests;

public sealed class RepositoryHygieneScenarioTests
{
	private static string RepoRoot()
	{
		DirectoryInfo? dir = new(AppContext.BaseDirectory);
		while (dir is not null)
		{
			if (File.Exists(Path.Combine(dir.FullName, "RdpAudit.sln")))
			{
				return dir.FullName;
			}

			dir = dir.Parent;
		}

		throw new InvalidOperationException(
			"Repository root (RdpAudit.sln) not found above " + AppContext.BaseDirectory);
	}

	private static List<string> EnumerateSourceFiles(string root)
	{
		List<string> files = new();

		foreach (string area in new[] { "src", "tests" })
		{
			string baseDir = Path.Combine(root, area);
			foreach (string file in Directory.EnumerateFiles(baseDir, "*.cs", SearchOption.AllDirectories))
			{
				bool isBuildArtifact = file
					.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar })
					.Any(segment => segment is "bin" or "obj");
				if (isBuildArtifact)
				{
					continue;
				}

				files.Add(file);
			}
		}

		return files;
	}

	/// <summary>Given per-file version headers are a 2.0.x convention, when we scan every .cs file
	/// in src+tests, then any present "// Version:" line must carry the canonical strict-triplet
	/// form (M.N.P, nothing after it) so a suffix note cannot drift the version claim and a
	/// machine merge never writes a malformed marker. Files without the header are fine.</summary>
	[Fact]
	public void VersionHeaders_AreCanonicalTripletsOrAbsent()
	{
		string root = RepoRoot();
		// Match a "// Version:" line whose rest of line is NOT immediately a strict triplet
		// followed by optional trailing whitespace and end of line.
		Regex nonCanonicalVersionLine = new(
			@"^\s*//\s*Version\s*:(?!\s*\d{1,3}\.\d{1,3}\.\d{1,3}\s*$)",
			RegexOptions.Multiline);
		List<string> offenders = new();

		foreach (string file in EnumerateSourceFiles(root))
		{
			string text = File.ReadAllText(file);
			if (nonCanonicalVersionLine.IsMatch(text))
			{
				offenders.Add(Path.GetRelativePath(root, file).Replace('\\', '/'));
			}
		}

		Assert.True(offenders.Count == 0,
			"These .cs files carry a non-canonical '// Version:' header line (the only accepted " +
			"form is '// Version: M.N.P' with nothing after the number; historical notes belong on " +
			"a separate '// Note:' line): " + string.Join(", ", offenders));
	}

	/// <summary>Given the product is Windows-only and CI exercises only Windows hosts, when we
	/// read the declared workflow runners, then every runs-on value must be windows-latest and no
	/// Linux/macOS job may appear, because those platform claims are false and drift away from
	/// the single supported host. Guards the windows-only build contract.</summary>
	[Fact]
	public void CiWorkflows_DeclareWindowsRunnersOnly()
	{
		string workflowsDir = Path.Combine(RepoRoot(), ".github", "workflows");
		Assert.True(Directory.Exists(workflowsDir),
			".github/workflows directory is missing at the repository root.");

		Regex runsOn = new(@"^\s*runs-on\s*:\s*(.+)$", RegexOptions.Multiline);
		List<string> offenders = new();

		foreach (string file in Directory.EnumerateFiles(workflowsDir, "*.yml")
					 .Concat(Directory.EnumerateFiles(workflowsDir, "*.yaml")))
		{
			string text = File.ReadAllText(file);
			foreach (Match match in runsOn.Matches(text))
			{
				string value = match.Groups[1].Value.Trim();
				if (!string.Equals(value, "windows-latest", StringComparison.OrdinalIgnoreCase))
				{
					offenders.Add(Path.GetRelativePath(RepoRoot(), file).Replace('\\', '/')
						+ " (" + value + ")");
				}
			}
		}

		Assert.True(offenders.Count == 0,
			"These workflow jobs declare a non-Windows runner while the product is Windows-only; " +
			"keep every runs-on value as windows-latest: " + string.Join(", ", offenders));
	}

	/// <summary>Given CHANGELOG.md is the platform-maintained backup journal, when we read the
	/// file, then the header must stay '## Service Changelog' with the
	/// 'Automatically maintained by DevAgent.' marker directly below it, and every subsequent
	/// non-empty line must follow the deterministic '- [yyyy-MM-ddTHH:mm:ss] path' entry format,
	/// so the machine-written records remain parseable and human readers see the journal for what
	/// it is. Guards the journal-format contract.</summary>
	[Fact]
	public void Changelog_EntriesFollowMachineJournalFormat()
	{
		string changelogPath = Path.Combine(RepoRoot(), "CHANGELOG.md");
		Assert.True(File.Exists(changelogPath), "CHANGELOG.md is missing at the repository root.");

		string[] lines = File.ReadAllLines(changelogPath);
		Assert.True(lines.Length >= 3, "CHANGELOG.md is unexpectedly short.");
		Assert.Equal("# Service Changelog", lines[0].Trim());
		Assert.Equal("Automatically maintained by DevAgent.", lines[2].Trim());

		Regex entry = new(@"^- \[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\] \S");
		List<int> offenders = new();
		for (int i = 3; i < lines.Length; i++)
		{
			string line = lines[i];
			if (line.Length == 0)
			{
				continue;
			}

			if (!entry.IsMatch(line))
			{
				offenders.Add(i + 1);
			}
		}

		Assert.True(offenders.Count == 0,
			"CHANGELOG.md contains non-journal lines (reported 1-based line numbers). Every " +
			"non-empty line after the marker must use the '- [yyyy-MM-ddTHH:mm:ss] path' format: " +
			string.Join(", ", offenders));
	}
}
