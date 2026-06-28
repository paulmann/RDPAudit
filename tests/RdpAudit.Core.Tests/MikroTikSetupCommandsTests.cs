// File:    tests/RdpAudit.Core.Tests/MikroTikSetupCommandsTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the MikroTik RouterOS v7 setup command bundle exposed on the Configurator
//          MikroTik tab: every required step is present, every placeholder is preserved, the
//          bundle is non-empty, every line is CRLF-terminated, and — critically — no plaintext
//          secret value is embedded anywhere (the password is always represented by the
//          PasswordPlaceholder token, never a literal). These tests guarantee that the
//          "Copy commands" button on the MikroTik tab will paste a ready-to-edit template into
//          the operator's terminal without ever leaking a credential.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Linq;
using RdpAudit.Core.MikroTik;
using Xunit;

namespace RdpAudit.Core.Tests;

public class MikroTikSetupCommandsTests
{
	[Fact]
	public void BuildAll_IsNonEmpty_AndCrlfTerminated()
	{
		string bundle = MikroTikSetupCommands.BuildAll();

		Assert.False(string.IsNullOrWhiteSpace(bundle));
		Assert.EndsWith("\r\n", bundle, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildAll_ContainsRequiredPlaceholders()
	{
		string bundle = MikroTikSetupCommands.BuildAll();

		Assert.Contains(MikroTikSetupCommands.HostPlaceholder, bundle, StringComparison.Ordinal);
		Assert.Contains(MikroTikSetupCommands.PasswordPlaceholder, bundle, StringComparison.Ordinal);
		Assert.Contains(MikroTikSetupCommands.CertificatePlaceholder, bundle, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildAll_ContainsHeaderAndAllRequiredSections()
	{
		string bundle = MikroTikSetupCommands.BuildAll();

		Assert.Contains(MikroTikSetupCommands.BundleHeader, bundle, StringComparison.Ordinal);

		// Each numbered section header is present in order — guards against accidental deletion.
		string[] sectionAnchors =
		{
			"# 1. Create a least-privilege group",
			"# 2. Create the dedicated service user",
			"# 3. Enable the REST endpoint",
			"# 4. Restrict allowed-address",
			"# 5. Production HTTPS certificate",
			"# 6. Verification",
		};
		int previousIndex = -1;
		foreach (string anchor in sectionAnchors)
		{
			int idx = bundle.IndexOf(anchor, StringComparison.Ordinal);
			Assert.True(idx >= 0, $"Section anchor missing from bundle: {anchor}");
			Assert.True(idx > previousIndex, $"Section anchor out of order: {anchor}");
			previousIndex = idx;
		}
	}

	[Fact]
	public void BuildAll_ContainsLeastPrivilegeGroupAndUserCreation()
	{
		string bundle = MikroTikSetupCommands.BuildAll();

		Assert.Contains("/user/group/add name=rdpaudit", bundle, StringComparison.Ordinal);
		Assert.Contains("policy=read,write,api,rest-api", bundle, StringComparison.Ordinal);
		Assert.Contains("!ssh", bundle, StringComparison.Ordinal);
		Assert.Contains("!ftp", bundle, StringComparison.Ordinal);
		Assert.Contains("!telnet", bundle, StringComparison.Ordinal);
		Assert.Contains("!winbox", bundle, StringComparison.Ordinal);
		Assert.Contains("!sensitive", bundle, StringComparison.Ordinal);
		Assert.Contains("/user/add group=rdpaudit name=rdpaudit", bundle, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildAll_EnablesWwwSslAndDocumentsHttpFallback()
	{
		string bundle = MikroTikSetupCommands.BuildAll();

		Assert.Contains("/ip/service/set www-ssl disabled=no", bundle, StringComparison.Ordinal);
		Assert.Contains("# /ip/service/set www disabled=no", bundle, StringComparison.Ordinal);
		Assert.Contains("address=" + MikroTikSetupCommands.HostPlaceholder + "/32", bundle, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildAll_DocumentsTlsCertificateBinding()
	{
		string bundle = MikroTikSetupCommands.BuildAll();

		Assert.Contains("certificate=" + MikroTikSetupCommands.CertificatePlaceholder, bundle, StringComparison.Ordinal);
		Assert.Contains("tls-version=only-1.2", bundle, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildAll_IncludesVerificationCommands()
	{
		string bundle = MikroTikSetupCommands.BuildAll();

		Assert.Contains("/ip/service/print where name~\"www\"", bundle, StringComparison.Ordinal);
		Assert.Contains("/user/print where name=rdpaudit", bundle, StringComparison.Ordinal);
		Assert.Contains("/ip/firewall/filter/print where comment~\"^RdpAudit\"", bundle, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildAll_PasswordIsAlwaysPlaceholder_NeverLiteral()
	{
		string bundle = MikroTikSetupCommands.BuildAll();

		// password=... must always be followed by the explicit placeholder token. This is a hard
		// guarantee that the Copy commands button can never paste a real secret.
		string passwordKey = "password=";
		int searchFrom = 0;
		bool foundAtLeastOne = false;
		while (true)
		{
			int idx = bundle.IndexOf(passwordKey, searchFrom, StringComparison.Ordinal);
			if (idx < 0)
			{
				break;
			}

			// Allow commented-out password= lines, but on uncommented occurrences require the
			// placeholder to appear immediately after the equals sign (optionally quoted).
			int lineStart = bundle.LastIndexOf('\n', idx) + 1;
			string lineHead = bundle[lineStart..idx].TrimStart();
			bool isCommented = lineHead.StartsWith('#');

			string afterEquals = bundle.Substring(idx + passwordKey.Length);
			string firstToken = afterEquals.Split('\r', '\n')[0].Trim();
			// Strip surrounding quotes and a trailing RouterOS line-continuation backslash if any.
			firstToken = firstToken.TrimEnd('\\').Trim();
			if (firstToken.StartsWith('"'))
			{
				int closeQuote = firstToken.IndexOf('"', 1);
				firstToken = closeQuote > 0 ? firstToken.Substring(1, closeQuote - 1) : firstToken.TrimStart('"');
			}

			if (!isCommented)
			{
				foundAtLeastOne = true;
				Assert.Equal(MikroTikSetupCommands.PasswordPlaceholder, firstToken);
			}

			searchFrom = idx + passwordKey.Length;
		}

		Assert.True(foundAtLeastOne, "Bundle must contain at least one uncommented password= assignment with the placeholder.");
	}

	[Fact]
	public void BuildAll_DoesNotEmbedAnyCommonSecretMarkers()
	{
		string bundle = MikroTikSetupCommands.BuildAll();

		// Sanity check: the bundle is a template; it must not contain any literal credential
		// strings, common weak defaults, or accidental leftovers from manual edits.
		string[] forbidden =
		{
			"hunter2",
			"qwerty",
			"123456",
			"changeme",
			"password=admin",
			"password=root",
			"password=rdpaudit",
		};

		foreach (string token in forbidden)
		{
			Assert.DoesNotContain(token, bundle, StringComparison.OrdinalIgnoreCase);
		}
	}

	[Fact]
	public void EnumerateLines_MatchesBuildAll()
	{
		string joined = string.Join("\r\n", MikroTikSetupCommands.EnumerateLines()) + "\r\n";
		Assert.Equal(MikroTikSetupCommands.BuildAll(), joined);
	}

	[Fact]
	public void EnumerateLines_ContainsHeaderAndStartsWithComment()
	{
		string[] lines = MikroTikSetupCommands.EnumerateLines().ToArray();

		Assert.NotEmpty(lines);
		Assert.StartsWith("#", lines[0], StringComparison.Ordinal);
		Assert.Equal(MikroTikSetupCommands.BundleHeader, lines[0]);
	}
}
