// File:    src/RdpAudit.Core/WebUi/IisInstallCommandSet.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Feature catalog, status snapshot and command builders for the IIS-leg of the Web Access
//          tab. IIS is used purely as a STATIC file server for the published wwwroot: the required
//          feature set is therefore deliberately minimal (Web-Server role + static-content
//          features + basic HTTP error/docs). The builders live here in Core so every command
//          shape is unit-testable without a Windows host; nothing in this file EVER executes a
//          command or changes system state.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;

namespace RdpAudit.Core.WebUi;

/// <summary>Well-known Windows features required to serve the published static WebUI with IIS.</summary>
public static class IisFeatureCatalog
{
	/// <summary>Minimal static-file feature set the product itself serves through IIS. The WebUI is
	/// deliberately static-only on the IIS side, so no ASP.NET hosting feature and no CGI handler are
	/// included here. <see cref="DismManagementFeatures"/> is the separate management capability.</summary>
	public static readonly IReadOnlyList<string> StaticFeatures = new[]
	{
		"Web-Server",
		"Web-Static-Content",
		"Web-Default-Doc",
		"Web-Http-Errors",
	};

	/// <summary>Same capability set expressed as DISM feature names for /Online /Enable-Feature.</summary>
	public static readonly IReadOnlyList<string> DismFeatures = new[]
	{
		"IIS-WebServerRole",
		"IIS-WebServer",
		"IIS-StaticContent",
		"IIS-DefaultDocument",
		"IIS-HttpErrors",
	};

	/// <summary>Features the product needs beyond serving files: the IIS management tools, which provide
	/// <c>appcmd.exe</c>. The Configure IIS workflow drives appcmd.exe to inspect the installed modules
	/// before it touches the site, so without these the web access cannot be configured at all - on a
	/// machine that only ever ran this installer, the ASP.NET Core Module pre-check failed as "could not
	/// be started" and told the operator nothing useful. Kept separate from <see cref="DismFeatures"/>:
	/// they are a distinct capability with their own plan row and their own failure mode.</summary>
	public static readonly IReadOnlyList<string> DismManagementFeatures = new[]
	{
		"IIS-WebServerManagementTools",
		"IIS-ManagementScriptingTools",
	};

	/// <summary>Every DISM feature name this installer enables, in execution order: the static-file set
	/// first, then the management tools.</summary>
	public static IReadOnlyList<string> AllDismFeatureNames
	{
		get
		{
			List<string> all = new(DismFeatures.Count + DismManagementFeatures.Count);
			all.AddRange(DismFeatures);
			all.AddRange(DismManagementFeatures);
			return all;
		}
	}
}

/// <summary>Snapshot of what the Configurator knows about the local IIS installation.
/// The service is fail-closed: properties are only true when a probe actually confirmed them,
/// and <see cref="CanDeclare"/> marks whether the probe had the rights to inspect the system.</summary>
public sealed class IisStatusSnapshot
{
	/// <summary>True only when an authoritative source reported IIS as installed.</summary>
	public bool IisInstalled { get; set; }

	/// <summary>True only when the World Wide Web Publishing Service (W3SVC) is known to be present.</summary>
	public bool W3SvcPresent { get; set; }

	/// <summary>True when the probe actually determined the IIS installed state (true or false).</summary>
	public bool IisStateDetermined { get; set; }

	/// <summary>True when the probe actually determined the W3SVC service state (true or false).</summary>
	public bool W3SvcStateDetermined { get; set; }

	/// <summary>True only when the published WebUI folder exists and contains index.html.</summary>
	public bool PublishedWebUiPresent { get; set; }

	/// <summary>Probe origin: ServerManager powershell, DISM or registry.</summary>
	public string Provider { get; set; } = "Unknown";

	/// <summary>Empty when the probe succeeded; otherwise a curated refusal / failure reason with
	/// no secrets or machine-level details.</summary>
	public string? FailureReason { get; set; }

	/// <summary>Whether the probe could even determine the state; false when rights are missing.</summary>
	public bool CanDeclare => string.IsNullOrEmpty(FailureReason) || IisInstalled || W3SvcPresent;

	/// <summary>Human-readable one-line summary for the Web Access status label.</summary>
	public string Summary => FailureReason ?? (IisInstalled ? "IIS installed" : "IIS not installed");
}

/// <summary>Deterministic command sets for the Install IIS workflow. The builder never runs anything;
/// it returns what the workflow (Step 10) shows the operator and optionally executes after consent.</summary>
public static class IisInstallCommandSet
{
	/// <summary>Argument vector backing the DISM command for the static-file set only. Single source
	/// of truth: the operator-visible description and the executed command are built from the same
	/// feature catalog, so they can never drift. Never adds <c>/Restart</c> - the operator is asked
	/// to reboot only when the post-install verification finds that necessary.</summary>
	public static IReadOnlyList<string> BuildDismArguments() => BuildDismArguments(IisFeatureCatalog.DismFeatures);

	/// <summary>Argument vector for one DISM run that enables exactly the given features. The Install
	/// IIS workflow uses it to enable the static-file set and the management tools as separate,
	/// individually reported steps while sharing this one argument shape.</summary>
	public static IReadOnlyList<string> BuildDismArguments(IReadOnlyList<string> featureNames)
	{
		ArgumentNullException.ThrowIfNull(featureNames);
		if (featureNames.Count == 0)
		{
			throw new ArgumentException("At least one DISM feature name is required.", nameof(featureNames));
		}

		List<string> args = new(featureNames.Count + 3)
		{
			"/Online",
			"/Enable-Feature",
		};
		foreach (string feature in featureNames)
		{
			args.Add("/FeatureName:" + feature);
		}

		args.Add("/NoRestart");
		return args;
	}
}
