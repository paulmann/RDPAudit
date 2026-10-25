/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : TestPathsIsolation.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Keeps the Configurator's last-resort fault journal out of the machine's real
//          %ProgramData%\RdpAudit tree. RdpAuditPaths' contract is that no test run writes into the
//          production layout, and ConfiguratorExceptionGuard.Default resolves its journal through a
//          paths provider - so this module redirects that provider once, before any test runs, into a
//          temporary root that lives for the duration of the test process.
// Depends: RdpAudit.Core.Util (RdpAuditPaths), RdpAudit.Configurator (ConfiguratorExceptionGuard)

using System.Runtime.CompilerServices;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Tests;

/// <summary>Process-wide journal redirection for the Configurator test suite.</summary>
internal static class TestPathsIsolation
{
	/// <summary>Temporary ProgramData root the shared guard journals into.</summary>
	internal static string Root { get; } = Path.Combine(
		Path.GetTempPath(), "rdpaudit-configurator-tests-" + Guid.NewGuid().ToString("N"));

	/// <summary>The redirected journal file the shared guard appends to.</summary>
	internal static string JournalPath { get; } = Path.Combine(
		Root, RdpAuditPaths.LogsFolderName, RdpAuditPaths.ConfiguratorUnhandledLogFileName);

	/// <summary>Everything the shared guard has journalled so far, or an empty string when it has not
	/// written yet. xunit runs test classes in parallel and the journal is append-only, so assertions
	/// match on a marker unique to the fault under test instead of expecting an empty file.</summary>
	internal static string ReadJournal()
	{
		try
		{
			return File.Exists(JournalPath) ? File.ReadAllText(JournalPath) : string.Empty;
		}
		catch (IOException)
		{
			return string.Empty;
		}
	}

#pragma warning disable CA2255 // Module initializer in a library: deliberate. This test assembly must
	// redirect the guard before the first test exercises a page handler, and xunit v2 has no assembly
	// fixture to hang that on.
	[ModuleInitializer]
	internal static void RedirectLastResortJournal()
#pragma warning restore CA2255
	{
		Directory.CreateDirectory(Root);
		ConfiguratorExceptionGuard.PathsOverrideForTests = new TestPathsProvider(new RdpAuditPaths(Root));
	}

	private sealed class TestPathsProvider : IRdpAuditPathsProvider
	{
		internal TestPathsProvider(RdpAuditPaths paths) => Paths = paths;

		public RdpAuditPaths Paths { get; }
	}
}
