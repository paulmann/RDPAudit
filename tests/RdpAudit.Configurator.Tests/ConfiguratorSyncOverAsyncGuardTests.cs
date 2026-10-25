/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ConfiguratorSyncOverAsyncGuardTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: B1/F3 enforcement. Blocking a thread that owns the WinForms synchronization context is the
//          mechanism that hung the Configurator test suite and that freezes the form in production, so
//          the Configurator must contain no `GetAwaiter().GetResult()`, no `.Wait(...)` and no `.Result`
//          read on a task. `CA2007` is suppressed repo-wide, so a test is the practical gate. The first
//          test proves - by reflection - that the types the guard is supposed to protect really are
//          reachable from the UI types, so the guard cannot pass by being blind; the second scans the
//          project's sources (a superset of the reachable types, so nothing is silently skipped) and
//          fails on any finding that is not in the explicit allow-list below.
// Depends: RdpAudit.Configurator (Forms, Services), xunit

using System.Reflection;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using RdpAudit.Configurator.Forms;
using RdpAudit.Configurator.Services;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class ConfiguratorSyncOverAsyncGuardTests
{
	private static readonly Regex BlockingWaitPattern = new(
		@"\.Wait\s*\(|GetAwaiter\s*\(\s*\)\s*\.\s*GetResult\s*\(|(?<![A-Za-z0-9_])(?:[a-z_][A-Za-z0-9_]*|[)\]])\s*\.Result\b",
		RegexOptions.None,
		TimeSpan.FromSeconds(5));

	/// <summary>Assignments to a <c>Result</c> property of some other type (a dialog's outcome field, for
	/// example) are not task blocking. Expressed as a second regex so the exclusion - and the receiver rule
	/// in <see cref="BlockingWaitPattern"/>, which keeps a qualified type name such as
	/// <c>IpReputationUrlBuilder.Result</c> from looking like a task read - stay reviewable.</summary>
	private static readonly Regex ResultAssignmentPattern = new(
		@"\.Result\s*=(?!=)",
		RegexOptions.None,
		TimeSpan.FromSeconds(5));

	/// <summary>Findings that are knowingly tolerated. Empty: the Configurator is clean after B1/F3. An
	/// entry must name the file:line and state why the blocking wait cannot be removed - a silent
	/// allow-list is exactly the failure mode this guard exists to prevent.</summary>
	private static readonly Dictionary<string, string> AllowedFindings = new(StringComparer.Ordinal);

	/// <summary>The types the guard exists to protect. If reflection stops seeing them (renamed, moved,
	/// no longer referenced from a control), the scan below would still pass while the protection is
	/// gone - so their reachability is asserted instead of assumed. Static helper types such as
	/// SafeAsyncHandler are reached only from call sites inside method bodies, which the source scan
	/// covers in full, so they are deliberately not part of this list.</summary>
	private static readonly string[] MustBeReachable =
	{
		"FirewallProviderDiagnosticsProbe",
		"NotifierAutostartService",
		"PrerequisiteChecker",
		"DatabasePage",
		"FirewallPage",
		"ServicePage",
		"RemoteRdpClientsPage",
		"OverviewPage",
	};

	[Fact]
	public void UiReachableTypes_IncludeTheOnesThisGuardProtects()
	{
		HashSet<Type> reachable = CollectReachableTypes(typeof(MainForm).Assembly);

		List<string> missing = MustBeReachable
			.Where(name => !reachable.Any(type => string.Equals(type.Name, name, StringComparison.Ordinal)))
			.ToList();

		Assert.True(missing.Count == 0,
			"Reflection no longer reaches these types from the Configurator's UI types, so the blocking-wait "
			+ "guard below would silently stop covering them: " + string.Join(", ", missing));
	}

	[Fact]
	public void ConfiguratorSources_ContainNoBlockingTaskWaits()
	{
		List<string> findings = new();
		foreach (string path in EnumerateConfiguratorSources())
		{
			string[] lines = File.ReadAllLines(path);
			for (int i = 0; i < lines.Length; i++)
			{
				string code = StripComments(lines[i]);
				if (!BlockingWaitPattern.IsMatch(code))
				{
					continue;
				}

				if (ResultAssignmentPattern.IsMatch(code))
				{
					continue;
				}

				string location = RelativeToConfiguratorProject(path) + ":" + (i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
				if (!AllowedFindings.ContainsKey(location))
				{
					findings.Add(location + "  " + code.Trim());
				}
			}
		}

		Assert.True(findings.Count == 0,
			"Blocking task waits are forbidden in the Configurator: they freeze the form and deadlock against "
			+ "the page's own ConfigureAwait(true) continuations. Await the task instead, or - if the API is "
			+ "genuinely synchronous - keep it off the UI thread and record it in AllowedFindings with a "
			+ "reason. Findings: " + string.Join(" | ", findings));
	}

	/// <summary>Walks every type reachable from a WinForms control type through base types, field /
	/// property / event types, method signatures, generic arguments, array element types, nested types and
	/// the types the type's own methods construct (read from the IL's <c>newobj</c> operands).</summary>
	private static HashSet<Type> CollectReachableTypes(Assembly assembly)
	{
		HashSet<Type> visited = new();
		Queue<Type> pending = new();

		foreach (Type type in assembly.GetTypes().Where(t => !t.IsAbstract && typeof(Control).IsAssignableFrom(t)))
		{
			pending.Enqueue(type);
		}

		while (pending.Count > 0)
		{
			Type type = pending.Dequeue();
			if (!visited.Add(type))
			{
				continue;
			}

			foreach (Type related in RelatedTypes(type, assembly))
			{
				if (!visited.Contains(related) && related.Assembly == assembly)
				{
					pending.Enqueue(related);
				}
			}
		}

		return visited;
	}

	private static List<Type> RelatedTypes(Type type, Assembly assembly)
	{
		List<Type> related = new();
		Add(related, type.BaseType);
		Add(related, type.DeclaringType);

		const BindingFlags Members =
			BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

		foreach (FieldInfo field in type.GetFields(Members))
		{
			Add(related, field.FieldType);
		}

		foreach (PropertyInfo property in type.GetProperties(Members))
		{
			Add(related, property.PropertyType);
		}

		foreach (EventInfo raised in type.GetEvents(Members))
		{
			Add(related, raised.EventHandlerType);
		}

		foreach (MethodBase method in type.GetMethods(Members).Cast<MethodBase>().Concat(type.GetConstructors(Members)))
		{
			Add(related, method is MethodInfo info ? info.ReturnType : null);
			foreach (ParameterInfo parameter in method.GetParameters())
			{
				Add(related, parameter.ParameterType);
			}

			AddConstructedTypes(related, method, assembly);
		}

		return related;
	}

	private static void AddConstructedTypes(List<Type> related, MethodBase method, Assembly assembly)
	{
		MethodBody? body;
		try
		{
			body = method.GetMethodBody();
		}
		catch (Exception)
		{
			// No IL available (for example a runtime-provided method body) - nothing to inspect.
			return;
		}

		byte[]? il = body?.GetILAsByteArray();
		if (il is null)
		{
			return;
		}

		Module module = method.Module;
		for (int i = 0; i + 4 < il.Length; i++)
		{
			// 0x73 = newobj <token>. Only resolved tokens whose type lives in this assembly are kept, and a
			// mis-decoded token simply does not resolve, so a false positive is impossible by construction.
			if (il[i] != 0x73)
			{
				continue;
			}

			int token = BitConverter.ToInt32(il, i + 1);
			try
			{
				if (module.ResolveMember(token) is MethodBase constructor
					&& constructor.DeclaringType is Type created
					&& created.Assembly == assembly)
				{
					related.Add(created);
				}
			}
			catch (Exception)
			{
				// Not a member token - not a construction site we can use.
			}
		}
	}

	private static void Add(List<Type> related, Type? type)
	{
		if (type is null)
		{
			return;
		}

		related.Add(type);
		if (type.IsArray && type.GetElementType() is Type element)
		{
			related.Add(element);
		}

		if (type.IsGenericType)
		{
			related.AddRange(type.GetGenericArguments());
		}
	}

	/// <summary>Removes line comments (including XML doc lines) so prose that names a blocking call is not
	/// reported as one.</summary>
	private static string StripComments(string line)
		=> Regex.Replace(line, @"//.*$", string.Empty, RegexOptions.None, TimeSpan.FromSeconds(5));

	private static IEnumerable<string> EnumerateConfiguratorSources()
		=> Directory.EnumerateFiles(ConfiguratorProjectDirectory(), "*.cs", SearchOption.AllDirectories)
			.Where(path => !IsBuildArtifact(path));

	private static bool IsBuildArtifact(string path)
	{
		string[] segments = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
		return segments.Contains("bin", StringComparer.Ordinal) || segments.Contains("obj", StringComparer.Ordinal);
	}

	private static string RelativeToConfiguratorProject(string absolutePath)
		=> Path.GetRelativePath(ConfiguratorProjectDirectory(), absolutePath).Replace('\\', '/');

	private static string ConfiguratorProjectDirectory()
		=> Path.Combine(FindRepositoryRoot(), "src", "RdpAudit.Configurator");

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
