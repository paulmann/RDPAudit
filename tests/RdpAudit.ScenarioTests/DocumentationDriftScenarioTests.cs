/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : DocumentationDriftScenarioTests.cs
// Project: RdpAudit.ScenarioTests
// Purpose: P2-3 regression scenarios. Each test walks the repository the way an operator or a
//          contributor would: an operator reads docs/50-ipc.md to understand the IPC surface,
//          a contributor relies on PROJECT_MAP.md to navigate the tree, and a reviewer opens
//          README.md/README.ru.md to see the worker pipeline. When source and docs diverge,
//          these guards fail and name the exact file/name that drifted.
// Depends: RdpAudit.Core (IpcCommand enum), xunit
// Extends: Add a new guard here whenever a documentation contract is added (new generated doc,
//          a new diagram block, a new command family).

using System.Text.RegularExpressions;
using RdpAudit.Core.Ipc;
using Xunit;

namespace RdpAudit.ScenarioTests;

public sealed class DocumentationDriftScenarioTests
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

	/// <summary>Given the append-only IPC ABI in code and the operator-facing IPC reference doc,
	/// when we compare every enum constant against the doc text, then no shipped command may be
	/// undocumented. Guards P2-3d against future ordinals being added without doc updates.</summary>
	[Fact]
	public void OperatorIpReference_CoversEveryCommandConstant()
	{
		string root = RepoRoot();
		string doc = File.ReadAllText(Path.Combine(root, "docs", "50-ipc.md"));

		List<string> missing = Enum.GetNames(typeof(IpcCommand))
			.Where(name => !doc.Contains(name, StringComparison.Ordinal))
			.ToList();

		Assert.True(missing.Count == 0,
			"docs/50-ipc.md is missing these IpcCommand entries: " + string.Join(", ", missing));
	}

	/// <summary>Given PROJECT_MAP.md is the contributor's navigation contract, when we enumerate
	/// every source file on disk, then every file must have a row in the map. Guards P2-3c.</summary>
	[Fact]
	public void ContributorProjectMap_CoversEverySourceFileOnDisk()
	{
		string root = RepoRoot();
		string map = File.ReadAllText(Path.Combine(root, "PROJECT_MAP.md"));
		List<string> missing = new();

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

				string relative = Path.GetRelativePath(root, file).Replace('\\', '/');
				if (!map.Contains(relative, StringComparison.Ordinal))
				{
					missing.Add(relative);
				}
			}
		}

		Assert.True(missing.Count == 0,
			"PROJECT_MAP.md is missing these on-disk files: " + string.Join(", ", missing));
	}

	/// <summary>Given the README architecture diagrams are the first thing a reviewer sees, when we
	/// read both language variants, then they must show the current worker pipeline and never the
	/// retired worker names. Guards P2-3e (word boundaries keep
	/// EventCollectorHostedWorker distinct from the retired EventCollectorWorker).</summary>
	[Fact]
	public void ReviewerReadmeDiagrams_UseCurrentWorkerPipeline()
	{
		string root = RepoRoot();
		Regex retired = new(@"\b(EventCollectorWorker|EventNormalizerWorker|AlertEvaluatorWorker)\b");

		foreach (string readme in new[] { "README.md", "README.ru.md" })
		{
			string text = File.ReadAllText(Path.Combine(root, readme));

			Assert.DoesNotMatch(retired, text);
			Assert.Contains("EventCollectorHostedWorker", text, StringComparison.Ordinal);
			Assert.Contains("EventProcessorWorker", text, StringComparison.Ordinal);
			Assert.Contains("AlertWorker", text, StringComparison.Ordinal);
		}
	}
}
