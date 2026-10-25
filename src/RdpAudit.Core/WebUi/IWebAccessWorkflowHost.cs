// File:    src/RdpAudit.Core/WebUi/IWebAccessWorkflowHost.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Contract between the Configurator "Web Access" tab and the IIS workflows
//          (Install IIS = Step 10, Configure IIS = Step 11). The tab knows nothing about
//          DISM elevations, winget packages, appcmd.exe deployments or service starts: it delegates
//          the run and renders the returned per-item results and one-line outcome. The install run
//          reports one result per IisInstallPlan item through IProgress, so the tab can paint a
//          tick / cross against every component without knowing how any of them is installed.
//          Implementing the host is outside this file; the host is intentionally injectable so the
//          page is testable with a fake.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace RdpAudit.Core.WebUi;

/// <summary>
/// Runs the operator-visible IIS workflows behind the Web Access tab. Implementations must
/// be fail-closed and return curated, operator-readable text; they must never throw
/// across this boundary (exceptions are translated into the returned outcome).
/// </summary>
public interface IWebAccessWorkflowHost
{
	/// <summary>Installs every component the web dashboard needs (Step 10 - see
	/// <see cref="IisInstallPlan"/>): the IIS feature set, the IIS management tools and the
	/// ASP.NET Core Hosting Bundle. Reports each plan item to <paramref name="progress"/> as it runs
	/// so the caller can render per-item results, and returns one outcome per plan item plus the
	/// curated one-line status for the tab. Never throws; an unavailable component is reported as a
	/// failed or skipped item, not as an exception.</summary>
	Task<IisInstallRunOutcome> RunInstallIisAsync(
		IProgress<IisInstallStepResult>? progress = null,
		CancellationToken ct = default);

	/// <summary>Configures an installed IIS: application pool, physical-path ACL and site
	/// mapping for the published WebUI (Step 11). Returns the one-line outcome.</summary>
	Task<string> RunConfigureIisAsync();
}

/// <summary>Result of one Install IIS run: the curated status line the tab shows, every plan item
/// with its own outcome (what the progress window paints as tick / cross), and whether the machine
/// already had everything.</summary>
/// <param name="StatusLine">Curated one-line outcome; never multi-line, never raw tool output.</param>
/// <param name="ItemResults">One row per plan item, in plan order.</param>
/// <param name="Success">False when any plan item failed.</param>
/// <param name="AlreadyInstalled">True when nothing had to be installed at all.</param>
public sealed record IisInstallRunOutcome(
	string StatusLine,
	IReadOnlyList<IisInstallStepResult> ItemResults,
	bool Success,
	bool AlreadyInstalled);
