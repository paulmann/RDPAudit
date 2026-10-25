/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ElevationPreconditionMetaTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Two jobs, both about the elevation precondition (B21 / P1-1).
//            1. Deterministic coverage of BOTH branches of the guard. The automation host for this
//               engagement is ELEVATED and a non-elevated run is not available on it, so the "skip" branch
//               cannot be demonstrated by launching the suite differently. It is demonstrated instead
//               through the guard's own seam: `OverrideProbe(() => false)` makes the decision function and
//               the attribute report the recorded skip reason, `OverrideProbe(() => true)` makes them
//               report "run", and a throwing probe proves fail-closed. That is a real, repeatable proof of
//               the branch, not a restatement of the code.
//            2. A drift test that FAILS when a test that binds or drives the real production pipe lacks the
//               precondition - the mechanism that keeps the guard from disappearing again. It reads the
//               test sources, because "which test starts an IpcServerWorker" is a property of the code, and
//               the same idiom is already used by the Configurator hygiene tests
//               (ConfiguratorAsyncHandlerHygieneTests reads src/RdpAudit.Configurator).
//          The scanner removes comments AND string/character literals before it looks for pipe types. Both
//          matter: a doc comment that merely names a pipe must not count as a test that binds one, and a
//          string literal that spells a pipe type (this file contains several, as the detector's own
//          patterns) must not make the scanner flag itself.
//          KNOWN LIMIT, stated rather than hidden: the rule keys on a test method whose code mentions
//          `IpcServerWorker` together with `.StartAsync(`, in a file that owns a TestPipeNames pipe. A
//          future test that reaches the production pipe only through a helper type and never names the
//          worker would evade it. Closing that would need call-graph analysis the tree does not have; the
//          rule covers every shape that exists today and the shape the TestPipeNames header prescribes.
// Depends: ElevationTestGuard, xunit, source tree under tests/RdpAudit.Service.Tests
// Extends: When a new real-pipe test appears, mark it [ElevationFact] / [ElevationTheory]; when a test
//          binds a pipe with the DEFAULT DACL, record the file in DefaultDaclPipeFiles with its reason.

using System.Globalization;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Xunit;

namespace RdpAudit.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class ElevationPreconditionMetaTests
{
	// ── 1. The guard itself: both branches, and fail-closed ──────────────────────

	/// <summary>The pure decision function carries the whole precondition, so both answers are testable
	/// without a token.</summary>
	[Fact]
	public void ResolveSkipReason_ElevatedRuns_NonElevatedSkipsWithTheRecordedReason()
	{
		Assert.Null(ElevationTestGuard.ResolveSkipReason(elevated: true));
		Assert.Equal(
			ElevationTestGuard.NonElevatedSkipReason,
			ElevationTestGuard.ResolveSkipReason(elevated: false));

		// The reason must be a sentence an operator can act on, not an empty placeholder: it is often the
		// only thing a CI reader sees.
		Assert.False(string.IsNullOrWhiteSpace(ElevationTestGuard.NonElevatedSkipReason));
		Assert.Contains("elevated", ElevationTestGuard.NonElevatedSkipReason, StringComparison.OrdinalIgnoreCase);
		Assert.Contains("Administrator", ElevationTestGuard.NonElevatedSkipReason, StringComparison.Ordinal);
	}

	/// <summary>SKIP BRANCH. With the probe forced to "not elevated", the attribute xunit would use records
	/// the skip reason - which is exactly what makes the suite green instead of red on such a host.</summary>
	[Fact]
	public void ElevationFactAttribute_NonElevatedBranch_RecordsTheSkipReason()
	{
		using (ElevationTestGuard.OverrideProbe(() => false))
		{
			Assert.False(ElevationTestGuard.IsElevated);
			Assert.Equal(ElevationTestGuard.NonElevatedSkipReason, ElevationTestGuard.SkipReason);
			Assert.Equal(ElevationTestGuard.NonElevatedSkipReason, new ElevationFactAttribute().Skip);
			Assert.Equal(ElevationTestGuard.NonElevatedSkipReason, new ElevationTheoryAttribute().Skip);
		}
	}

	/// <summary>RUN BRANCH, through the same seam. This is the branch the real host exercises (see
	/// <see cref="Guard_MatchesTheHostItRunsOn"/>), and it is pinned here so a change that starts skipping
	/// unconditionally cannot pass unnoticed.</summary>
	[Fact]
	public void ElevationFactAttribute_ElevatedBranch_DoesNotSkip()
	{
		using (ElevationTestGuard.OverrideProbe(() => true))
		{
			Assert.True(ElevationTestGuard.IsElevated);
			Assert.Null(ElevationTestGuard.SkipReason);
			Assert.Null(new ElevationFactAttribute().Skip);
			Assert.Null(new ElevationTheoryAttribute().Skip);
		}
	}

	/// <summary>FAIL-CLOSED. A probe that cannot answer must not be read as "elevated": the tests skip
	/// rather than run and fail with a misleading UnauthorizedAccessException.</summary>
	[Fact]
	public void Guard_ProbeThatThrows_IsReportedAsNotElevated()
	{
		using (ElevationTestGuard.OverrideProbe(() => throw new InvalidOperationException("token unavailable")))
		{
			Assert.False(ElevationTestGuard.IsElevated);
			Assert.Equal(ElevationTestGuard.NonElevatedSkipReason, new ElevationFactAttribute().Skip);
		}
	}

	/// <summary>Pins the guard to the host it actually runs on. On the elevated automation host this asserts
	/// the RUN branch; on a non-elevated host it asserts the SKIP branch. Both readings are correct - that is
	/// the point of comparing against the live probe rather than a hard-coded expectation.</summary>
	[Fact]
	public void Guard_MatchesTheHostItRunsOn()
	{
		bool elevated = ElevationTestGuard.ProbeCurrentProcess();

		Assert.Equal(elevated, ElevationTestGuard.IsElevated);
		Assert.Equal(elevated, ElevationTestGuard.SkipReason is null);
		Assert.Equal(ElevationTestGuard.SkipReason, new ElevationFactAttribute().Skip);
	}

	/// <summary>The seam is scoped: leaving it restores the real probe, so no test can inherit a forced
	/// answer from another one.</summary>
	[Fact]
	public void Guard_OverrideScope_RestoresTheRealProbeOnDispose()
	{
		bool real = ElevationTestGuard.ProbeCurrentProcess();
		using (ElevationTestGuard.OverrideProbe(() => true))
		{
			Assert.True(ElevationTestGuard.IsElevated);
		}

		Assert.Equal(real, ElevationTestGuard.IsElevated);
	}

	// ── 2. The drift test: no real-pipe test without the precondition ────────────

	/// <summary>Every test method that starts an <c>IpcServerWorker</c> (or binds a pipe directly) in a file
	/// that owns a real test pipe must carry the elevation precondition.</summary>
	[Fact]
	public void RealPipeTests_CarryTheElevationPrecondition()
	{
		List<string> offenders = [];
		foreach ((string relativePath, string text) in EnumerateTestSources())
		{
			if (!FileOwnsTestPipe(text))
			{
				continue;
			}

			foreach (TestCandidate candidate in EnumerateTestMethods(text))
			{
				if (StartsARealPipe(candidate.Body) && !candidate.IsElevationGuarded)
				{
					offenders.Add(relativePath + "::" + candidate.Name);
				}
			}
		}

		Assert.True(offenders.Count == 0,
			"These test methods drive the real production named pipe but do not carry the elevation "
			+ "precondition, so on a non-elevated host they fail with a misleading UnauthorizedAccessException "
			+ "(B21). Mark them [ElevationFact] / [ElevationTheory]: " + string.Join(", ", offenders));
	}

	/// <summary>Second half of the same guarantee, and the reason the first half cannot rot into a vacuous
	/// pass: the detector must keep finding the tests it polices. If a rename or a refactor makes the rule
	/// stop matching, the suite fails here instead of reporting a clean run over nothing. The recorded counts
	/// are a floor, not a ceiling - adding a real-pipe test is expected and does not need this map updated.
	/// </summary>
	[Fact]
	public void RealPipeDetection_StillFindsTheRecordedRealPipeTests()
	{
		List<(string Path, string Text)> sources = [.. EnumerateTestSources()];
		Dictionary<string, int> detected = new(StringComparer.Ordinal);
		foreach ((string path, string text) in sources)
		{
			int count = EnumerateTestMethods(text).Count(candidate => StartsARealPipe(candidate.Body));
			if (count > 0)
			{
				detected[path] = count;
			}
		}

		List<string> lost = RecordedRealPipeTestMethods
			.Where(recorded => detected.GetValueOrDefault(recorded.Key) < recorded.Value)
			.Select(recorded => recorded.Key + ": found " + detected.GetValueOrDefault(recorded.Key).ToString(CultureInfo.InvariantCulture)
				+ ", recorded " + recorded.Value.ToString(CultureInfo.InvariantCulture))
			.ToList();

		Assert.True(lost.Count == 0,
			"The real-pipe detector no longer finds every test it is supposed to police, so the elevation "
			+ "precondition check has silently lost coverage. Fix the detection rule in StartsARealPipe (do not "
			+ "lower these counts): " + string.Join("; ", lost));

		int total = detected.Values.Sum();
		int recordedTotal = RecordedRealPipeTestMethods.Values.Sum();
		Assert.True(total >= recordedTotal,
			"The detector found " + total.ToString(CultureInfo.InvariantCulture)
			+ " real-pipe test method(s), fewer than the recorded " + recordedTotal.ToString(CultureInfo.InvariantCulture) + ".");
	}

	/// <summary>Files that own a real test pipe, and how many of their test methods the elevation rule must
	/// find. Recorded so the detector cannot stop matching without a failure (see the test above).</summary>
	private static readonly Dictionary<string, int> RecordedRealPipeTestMethods = new(StringComparer.Ordinal)
	{
		["tests/RdpAudit.Service.Tests/IpcServerWorkerInstanceCapTests.cs"] = 3,
		["tests/RdpAudit.Service.Tests/IpcServerWorkerLifecycleTests.cs"] = 6,
	};

	/// <summary>Third half: every file that names a named-pipe type must either own a real test pipe (and
	/// therefore already be covered above) or be recorded here with the reason it needs no elevation. A new
	/// pipe test therefore cannot slip in silently: it either uses the shared pipe-name helper, or it states
	/// in this list that its pipe is not protected by the production ACL.</summary>
	[Fact]
	public void PipeBindingFiles_AreAccountedFor()
	{
		List<(string Path, string Text)> sources = [.. EnumerateTestSources()];
		List<string> unaccounted = [];
		foreach ((string path, string text) in sources)
		{
			if (NamesAPipeType(text) && !FileOwnsTestPipe(text) && !DefaultDaclPipeFiles.ContainsKey(path))
			{
				unaccounted.Add(path);
			}
		}

		List<string> stale = DefaultDaclPipeFiles.Keys
			.Where(recorded => !sources.Any(source => string.Equals(source.Path, recorded, StringComparison.Ordinal)))
			.ToList();

		Assert.True(unaccounted.Count == 0,
			"These files name a Windows named-pipe type without using TestPipeNames (this project's real-pipe "
			+ "helper) and are not recorded as default-DACL pipes: " + string.Join(", ", unaccounted));
		Assert.True(stale.Count == 0,
			"These recorded default-DACL pipe files no longer exist; drop them from DefaultDaclPipeFiles: "
			+ string.Join(", ", stale));
	}

	/// <summary>Files that bind a named pipe WITHOUT the production security descriptor. The Windows default
	/// DACL grants the creating process access, so a non-elevated host runs them and an elevation
	/// precondition would drop coverage for no reason. Recorded rather than inferred, so the distinction is a
	/// decision a reviewer can see.</summary>
	private static readonly Dictionary<string, string> DefaultDaclPipeFiles = new(StringComparer.Ordinal)
	{
		["tests/RdpAudit.Service.Tests/CrossHostIpcTransportTests.cs"] =
			"Creates its server stream with the DEFAULT DACL (no security descriptor argument): the in-process "
			+ "test host both serves and connects, which works without elevation. Only IpcServerWorker applies "
			+ "the Administrators-only production ACL, and this file does not use it.",
	};

	// ── Source scanning ──────────────────────────────────────────────────────────

	private const string TestAttributePattern = @"\[(?:Elevation)?(?:Fact|Theory)\b";

	private static readonly Regex TestMethodPattern = new(
		@"(?<attrs>(?:[ \t]*\[[^\]\r\n]*\][ \t]*\r?\n)+)"
		+ @"[ \t]*(?:public|internal)\s+(?:static\s+)?(?:async\s+)?(?:Task|ValueTask|void)[ \t<>\w,\.\?]*\s+"
		+ @"(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
		RegexOptions.None,
		TimeSpan.FromSeconds(5));

	/// <summary>True when the file allocates a per-test pipe NAME (the project's real-pipe helper, called, not
	/// merely mentioned). The call form is required so a doc comment or a string literal cannot qualify.</summary>
	private static bool FileOwnsTestPipe(string text) =>
		text.Contains("TestPipeNames.Unique(", StringComparison.Ordinal);

	private static bool NamesAPipeType(string text) =>
		text.Contains("NamedPipeServerStream", StringComparison.Ordinal)
		|| text.Contains("NamedPipeClientStream", StringComparison.Ordinal)
		|| text.Contains("PipeSecurity", StringComparison.Ordinal);

	/// <summary>True when the body drives the real transport: it names the production worker and starts it.
	/// The worker is the only type in the product that applies the Administrators-only pipe ACL, so naming it
	/// together with a start is what makes elevation a precondition.</summary>
	private static bool StartsARealPipe(string body) =>
		body.Contains("IpcServerWorker", StringComparison.Ordinal)
		&& (body.Contains(".StartAsync(", StringComparison.Ordinal)
			|| body.Contains("NamedPipeServerStream", StringComparison.Ordinal)
			|| body.Contains("NamedPipeClientStream", StringComparison.Ordinal));

	private static IEnumerable<(string Path, string Text)> EnumerateTestSources()
	{
		string root = TestProjectDirectory();
		string repositoryRoot = FindRepositoryRoot();
		foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
		{
			string[] segments = file.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
			if (segments.Contains("bin", StringComparer.Ordinal) || segments.Contains("obj", StringComparer.Ordinal))
			{
				continue;
			}

			yield return (
				Path.GetRelativePath(repositoryRoot, file).Replace('\\', '/'),
				StripCommentsAndLiterals(File.ReadAllText(file)));
		}
	}

	/// <summary>Removes comment and literal content in one left-to-right pass, so a <c>//</c> inside a string
	/// is not mistaken for a comment and a brace inside a literal cannot unbalance the block scan.</summary>
	private static string StripCommentsAndLiterals(string text)
	{
		System.Text.StringBuilder builder = new(text.Length);
		int index = 0;
		while (index < text.Length)
		{
			char current = text[index];
			if (current == '/' && index + 1 < text.Length && text[index + 1] == '/')
			{
				index = SkipToLineEnd(text, index);
				continue;
			}

			if (current == '/' && index + 1 < text.Length && text[index + 1] == '*')
			{
				int end = text.IndexOf("*/", index + 2, StringComparison.Ordinal);
				index = end < 0 ? text.Length : end + 2;
				continue;
			}

			if (current == '"')
			{
				index = SkipString(text, index);
				continue;
			}

			if (current == '\'')
			{
				index = SkipCharLiteral(text, index);
				continue;
			}

			builder.Append(current);
			index++;
		}

		return builder.ToString();
	}

	private static int SkipToLineEnd(string text, int start)
	{
		int newline = text.IndexOf('\n', start);
		return newline < 0 ? text.Length : newline;
	}

	private static int SkipString(string text, int start)
	{
		bool verbatim = start > 0 && text[start - 1] == '@';
		for (int index = start + 1; index < text.Length; index++)
		{
			if (!verbatim && text[index] == '\\')
			{
				index++;
				continue;
			}

			if (text[index] != '"')
			{
				continue;
			}

			if (verbatim && index + 1 < text.Length && text[index + 1] == '"')
			{
				index++;
				continue;
			}

			return index + 1;
		}

		return text.Length;
	}

	private static int SkipCharLiteral(string text, int start)
	{
		for (int index = start + 1; index < text.Length; index++)
		{
			if (text[index] == '\\')
			{
				index++;
				continue;
			}

			if (text[index] == '\'')
			{
				return index + 1;
			}
		}

		return text.Length;
	}

	private static IEnumerable<TestCandidate> EnumerateTestMethods(string text)
	{
		foreach (Match match in TestMethodPattern.Matches(text))
		{
			string attributes = match.Groups["attrs"].Value;
			if (!Regex.IsMatch(attributes, TestAttributePattern))
			{
				continue;
			}

			int openBrace = text.IndexOf('{', match.Index + match.Length);
			if (openBrace < 0)
			{
				continue;
			}

			yield return new TestCandidate(
				match.Groups["name"].Value,
				SliceBlock(text, openBrace),
				attributes.Contains("ElevationFact", StringComparison.Ordinal)
					|| attributes.Contains("ElevationTheory", StringComparison.Ordinal));
		}
	}

	/// <summary>Returns the text of a brace-delimited block starting at <paramref name="openBrace"/>. Literals
	/// are already gone, so brace counting cannot be confused by one.</summary>
	private static string SliceBlock(string text, int openBrace)
	{
		int depth = 0;
		for (int index = openBrace; index < text.Length; index++)
		{
			if (text[index] == '{')
			{
				depth++;
			}
			else if (text[index] == '}')
			{
				depth--;
				if (depth == 0)
				{
					return text[openBrace..(index + 1)];
				}
			}
		}

		return text[openBrace..];
	}

	private readonly record struct TestCandidate(string Name, string Body, bool IsElevationGuarded);

	private static string TestProjectDirectory()
		=> Path.Combine(FindRepositoryRoot(), "tests", "RdpAudit.Service.Tests");

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
			"Repository root (RdpAudit.sln) not found above " + AppContext.BaseDirectory);
	}
}
