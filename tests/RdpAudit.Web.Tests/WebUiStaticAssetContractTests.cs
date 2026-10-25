// File:    tests/RdpAudit.Web.Tests/WebUiStaticAssetContractTests.cs
// Module:  RdpAudit.Web.Tests
// Purpose: Static contract checks for the dashboard assets of plan step 5. The proxy
//          serves them under a strict Content-Security-Policy (script-src 'self',
//          style-src 'self'), so the page must carry NO inline handlers, NO inline
//          style blocks or attributes and NO remote asset URLs. Every rendered value
//          must be produced through DOM APIs plus textContent (no innerHTML / eval /
//          new Function / document.write), so REST payloads can never execute in the
//          page. These checks run without a browser, making them cheap regression gates.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.RegularExpressions;
using Xunit;

namespace RdpAudit.Web.Tests;

public sealed class WebUiStaticAssetContractTests
{
	[Fact]
	public void IndexHtml_CarriesBranding_AndNoInlineCodeOrRemoteAssets()
	{
		string html = File.ReadAllText(Path.Combine(WebRoot(), "index.html"));

		Assert.Contains("RdpAudit Web Access", html, StringComparison.Ordinal);
		Assert.DoesNotContain("onclick", html, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("onload", html, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("style=", html, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("<style", html, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("https://", html, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("http://", html, StringComparison.OrdinalIgnoreCase);

		// Inline script bodies are forbidden by the strict CSP: every <script> must carry src.
		Assert.DoesNotMatch(ScriptWithBodyPattern(), html);
		Assert.Contains("<script src='assets/js/rdpaudit-web.js'></script>", html, StringComparison.Ordinal);
	}

	[Fact]
	public void DashboardScript_UsesSafeDomApisOnly()
	{
		string js = File.ReadAllText(Path.Combine(WebRoot(), "assets", "js", "rdpaudit-web.js"));

		Assert.DoesNotContain(".innerHTML", js, StringComparison.Ordinal);
		Assert.DoesNotContain("eval(", js, StringComparison.Ordinal);
		Assert.DoesNotContain("new Function", js, StringComparison.Ordinal);
		Assert.DoesNotContain("document.write", js, StringComparison.Ordinal);
		Assert.DoesNotContain("setAttribute('on", js, StringComparison.OrdinalIgnoreCase);

		Assert.Contains("textContent", js, StringComparison.Ordinal);
		Assert.Contains("addEventListener", js, StringComparison.Ordinal);
	}

	[Fact]
	public void Stylesheet_IsSelfContained_WithoutRemoteImports()
	{
		string rawCss = File.ReadAllText(Path.Combine(WebRoot(), "assets", "css", "rdpaudit-web.css"));

		// The author banner mentions https://Deynekin.com, so remote-URL checks run on the
		// comment-stripped stylesheet: a comment must not mask a real @import or remote URL.
		string css = CssCommentStripper().Replace(rawCss, string.Empty);

		Assert.DoesNotContain("@import", css, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("https://", css, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("http://", css, StringComparison.OrdinalIgnoreCase);
		Assert.Contains(":root", css, StringComparison.Ordinal);
		Assert.Contains("body.dark", css, StringComparison.Ordinal);
	}

	private static Regex ScriptWithBodyPattern()
	{
		// <script ...> that is NOT a pure src reference and is followed by visible content
		// means an inline script body. Empty attributes like charset are tolerated.
		return new Regex(
			"<script(?![^>]*\\bsrc\\s*=\\s*['\"])[^>]*>\\s*\\S",
			RegexOptions.IgnoreCase | RegexOptions.Compiled);
	}

	private static Regex CssCommentStripper()
	{
		return new Regex("/\\*[\\s\\S]*?\\*/", RegexOptions.Compiled);
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
