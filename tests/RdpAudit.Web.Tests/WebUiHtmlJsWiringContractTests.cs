// File:    tests/RdpAudit.Web.Tests/WebUiHtmlJsWiringContractTests.cs
// Module:  RdpAudit.Web.Tests
// Purpose: Browser-independent wiring checks between the dashboard script and the
//          page markup of plan step 5. The environment has no scriptable browser
//          (no Node.js; the Chromium binaries installed here are user-launcher
//          redirects and --dump-dom yields no console on this host), so the
//          deterministic subset of the smoke contract is asserted statically:
//          every DOM anchor the script uses by id must exist in index.html, and
//          every tab must be wired to its panel section and its data loader.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.RegularExpressions;
using Xunit;

namespace RdpAudit.Web.Tests;

public sealed class WebUiHtmlJsWiringContractTests
{
	[Fact]
	public void EveryDomAnchorReferencedByScript_ExistsInIndexHtml()
	{
		string html = Read("index.html");
		string js = Read(Path.Combine("assets", "js", "rdpaudit-web.js"));

		HashSet<string> anchorIds = new(StringComparer.Ordinal);
		foreach (Match match in Regex.Matches(js, "\\$\\(\\s*'([^']+)'\\s*\\)"))
		{
			anchorIds.Add(match.Groups[1].Value);
		}

		Assert.True(anchorIds.Count >= 20, "Expected the script to reference all widget anchors, got " + anchorIds.Count + ".");
		foreach (string id in anchorIds)
		{
			Assert.Contains("id='" + id + "'", html, StringComparison.Ordinal);
		}
	}

	[Fact]
	public void EveryTab_IsWiredTo_APanelAndALoader()
	{
		string html = Read("index.html");
		string js = Read(Path.Combine("assets", "js", "rdpaudit-web.js"));

		HashSet<string> tabIds = new(StringComparer.Ordinal);
		foreach (Match match in Regex.Matches(html, "data-tab='([a-z]+)'"))
		{
			tabIds.Add(match.Groups[1].Value);
		}

		Assert.True(tabIds.Count >= 6, "Expected six dashboard tabs, got " + tabIds.Count + ".");
		Assert.Equal(tabIds.Count, Regex.Matches(html, "class='tab-panel").Count);

		foreach (string tabId in tabIds)
		{
			Assert.Contains("id='tab-" + tabId + "'", html, StringComparison.Ordinal);
			Assert.Matches(tabId + @"\s*:\s*load", js);
		}
	}

	private static string Read(string relativePath)
	{
		return File.ReadAllText(Path.Combine(WebRoot(), relativePath));
	}

	private static string WebRoot()
	{
		DirectoryInfo? current = new(AppContext.BaseDirectory);
		while (current is not null)
		{
			if (File.Exists(Path.Combine(current.FullName, "RdpAudit.sln")))
			{
				string webRoot = Path.Combine(current.FullName, "src", "RdpAudit.Web", "wwwroot");
				if (Directory.Exists(webRoot))
				{
					return webRoot;
				}
			}

			current = current.Parent;
		}

		throw new InvalidOperationException("The repository root (RdpAudit.sln) could not be located from '"
			+ AppContext.BaseDirectory + "'.");
	}
}
