// File:    tests/RdpAudit.Core.Tests/WebUiAppSettingsEditorTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the contract of the security-critical appsettings editor used by the Configure IIS
//          workflow (plan step 11): the editor must write ONLY the intended surface (RdpAudit:Api
//          Enabled/Token and the WebUiProxy section), preserve every other section and every other
//          Api property (loopback listen address, port, certificate selectors) untouched, keep the
//          inline-script CSP switch at its fail-safe default, surface the pre-edit certificate
//          selectors to the caller, and fail curatedly on corrupt or unwritable settings files.
//          Every test works inside a temporary directory and restores nothing outside it.
// Depends: WebUiAppSettingsEditor, xUnit
// Extends: Add a case here whenever the editor gains a field or a rule.

using System.Text;
using System.Text.Json.Nodes;
using RdpAudit.Core.WebUi;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class WebUiAppSettingsEditorTests : IDisposable
{
	private readonly string _root;

	public WebUiAppSettingsEditorTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-appsettingseditor-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(_root);
	}

	public void Dispose()
	{
		try
		{
			if (Directory.Exists(_root))
			{
				Directory.Delete(_root, recursive: true);
			}
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	private string NewPath(string name) => Path.Combine(_root, name);

	private static void WriteText(string path, string text)
		=> File.WriteAllText(path, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

	private static JsonNode? ReadRoot(string path)
		=> JsonNode.Parse(File.ReadAllText(path, Encoding.UTF8));

	[Fact]
	public void EnsureApiSection_CreatesMissingSections_AndWritesOnlyTheApiSurface()
	{
		string path = NewPath("appsettings.json");

		AppSettingsEditResult result = WebUiAppSettingsEditor.EnsureApiSection(path, "DPAPI:envelope");

		Assert.True(result.Ok);
		Assert.Null(result.Failure);
		Assert.Null(result.ExistingCertificateThumbprint);
		Assert.Null(result.ExistingCertificateSubject);
		JsonNode? api = ReadRoot(path)?["RdpAudit"]?["Api"];
		Assert.NotNull(api);
		Assert.True(api["Enabled"]!.GetValue<bool>());
		Assert.Equal("DPAPI:envelope", api["Token"]!.GetValue<string>());
		Assert.Null(api["ListenAddress"]);
		Assert.Null(api["Port"]);
	}

	[Fact]
	public void EnsureApiSection_PreservesExistingApiFieldsAndUnrelatedSections_AndReturnsSelectors()
	{
		string path = NewPath("appsettings.json");
		const string original = """
			{
			  "RdpAudit": {
			    "Api": {
			      "Enabled": false,
			      "Token": "",
			      "ListenAddress": "127.0.0.1",
			      "Port": 8443,
			      "CertificateThumbprint": "AB12",
			      "CertificateSubject": "CN=RdpAudit"
			    },
			    "Monitoring": { "PollIntervalSeconds": 5 }
			  },
			  "Logging": { "LogLevel": "Information" }
			}
			""";
		WriteText(path, original);

		AppSettingsEditResult result = WebUiAppSettingsEditor.EnsureApiSection(path, "DPAPI:envelope");

		Assert.True(result.Ok);
		Assert.Equal("AB12", result.ExistingCertificateThumbprint);
		Assert.Equal("CN=RdpAudit", result.ExistingCertificateSubject);
		JsonNode? root = ReadRoot(path);
		JsonNode? api = root?["RdpAudit"]?["Api"];
		Assert.NotNull(api);
		Assert.True(api["Enabled"]!.GetValue<bool>());
		Assert.Equal("DPAPI:envelope", api["Token"]!.GetValue<string>());
		Assert.Equal("127.0.0.1", api["ListenAddress"]!.GetValue<string>());
		Assert.Equal(8443, api["Port"]!.GetValue<int>());
		Assert.Equal("AB12", api["CertificateThumbprint"]!.GetValue<string>());
		Assert.Equal("CN=RdpAudit", api["CertificateSubject"]!.GetValue<string>());
		Assert.Equal(5, root!["RdpAudit"]!["Monitoring"]!["PollIntervalSeconds"]!.GetValue<int>());
		Assert.Equal("Information", root["Logging"]!["LogLevel"]!.GetValue<string>());
	}

	[Fact]
	public void EnsureApiSection_BlankPathOrEnvelope_IsRejected()
	{
		Assert.Throws<ArgumentException>(() => WebUiAppSettingsEditor.EnsureApiSection(string.Empty, "x"));
		Assert.Throws<ArgumentException>(() => WebUiAppSettingsEditor.EnsureApiSection(NewPath("a.json"), "   "));
	}

	[Fact]
	public void EnsureApiSection_CorruptJson_ReturnsCuratedFailure()
	{
		string path = NewPath("corrupt.json");
		WriteText(path, "{ not valid json");

		AppSettingsEditResult result = WebUiAppSettingsEditor.EnsureApiSection(path, "DPAPI:envelope");

		Assert.False(result.Ok);
		Assert.Contains("could not be read", result.Failure, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void EnsureApiSection_UnwritableFolder_ReturnsCuratedFailure()
	{
		string blocker = NewPath("blocker.txt");
		WriteText(blocker, "occupied");
		string path = Path.Combine(blocker, "sub", "appsettings.json");

		AppSettingsEditResult result = WebUiAppSettingsEditor.EnsureApiSection(path, "DPAPI:envelope");

		Assert.False(result.Ok);
		Assert.Contains("could not be created", result.Failure, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void EnsureApiSection_TypeMismatchedSelector_ReturnsStructureFailure()
	{
		string path = NewPath("typed.json");
		WriteText(path, "{ \"RdpAudit\": { \"Api\": { \"CertificateThumbprint\": 12345 } } }");

		AppSettingsEditResult result = WebUiAppSettingsEditor.EnsureApiSection(path, "DPAPI:envelope");

		Assert.False(result.Ok);
		Assert.Contains("unexpected structure", result.Failure, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void EnsureWebUiProxySection_WritesBackendUrlTrimmed_WithFailSafeInlineScripts()
	{
		string path = NewPath("webui.json");
		WriteText(path, "{ \"Other\": 1 }");

		AppSettingsEditResult result = WebUiAppSettingsEditor.EnsureWebUiProxySection(
			path, "https://127.0.0.1:8443/", "ABC");

		Assert.True(result.Ok);
		JsonNode? root = ReadRoot(path);
		JsonNode? proxy = root?["WebUiProxy"];
		Assert.NotNull(proxy);
		Assert.Equal("https://127.0.0.1:8443", proxy["BackendBaseUrl"]!.GetValue<string>());
		Assert.Equal("ABC", proxy["BackendCertificateThumbprint"]!.GetValue<string>());
		Assert.False(proxy["AllowInlineScripts"]!.GetValue<bool>());
		Assert.Equal(1, root!["Other"]!.GetValue<int>());
	}

	[Fact]
	public void EnsureWebUiProxySection_BlankThumbprint_RemovesThePin()
	{
		string path = NewPath("webui.json");
		WriteText(path, "{ \"WebUiProxy\": { \"BackendCertificateThumbprint\": \"ABC\" } }");

		AppSettingsEditResult result = WebUiAppSettingsEditor.EnsureWebUiProxySection(path, "https://127.0.0.1:8443", null);

		Assert.True(result.Ok);
		JsonNode? proxy = ReadRoot(path)?["WebUiProxy"];
		Assert.NotNull(proxy);
		Assert.Null(proxy["BackendCertificateThumbprint"]);
		Assert.False(proxy["AllowInlineScripts"]!.GetValue<bool>());
	}
}
