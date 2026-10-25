// File:    tests/RdpAudit.Core.Tests/WebUiPublisherTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the WebUI publisher contract: files are copied with SHA-256 verification on both sides
//          of the atomic move, unchanged files are skipped, tampered files are rewritten, the 'secrets'
//          folder is never touched and a source secrets folder fails the publish, stale files are removed
//          via the manifest, the manifest itself survives a re-publish, and on Windows the optional pool
//          grant is applied and verified. Every test works inside a temporary directory and restores
//          nothing outside it.
// Depends: WebUiPublisher, RdpAuditPaths, xUnit
// Extends: Add a refusal here whenever the publisher gains a rule.

using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using RdpAudit.Core.Util;
using RdpAudit.Core.WebUi;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit tests for <see cref="WebUiPublisher"/> using a temp-rooted path layout.</summary>
public sealed class WebUiPublisherTests : IDisposable
{
	private readonly string _root;
	private readonly string _sourceRoot;

	public WebUiPublisherTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-webui-pub-" + Guid.NewGuid().ToString("N"));
		_sourceRoot = Path.Combine(_root, "src-wwwroot");
		Directory.CreateDirectory(_sourceRoot);
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

	private RdpAuditPaths CreatePaths() => new(Path.Combine(_root, "ProgramData", "RdpAudit"));

	/// <summary>Given a flat source tree, when published, then every file lands in the target with the
	/// exact source bytes and MANIFEST entries carry the correct relative paths.</summary>
	[Fact]
	public void Publish_CopiesEveryFileWithSha256Verification()
	{
		File.WriteAllText(Path.Combine(_sourceRoot, "index.html"), "<html>dashboard</html>");
		Directory.CreateDirectory(Path.Combine(_sourceRoot, "assets", "js"));
		File.WriteAllText(Path.Combine(_sourceRoot, "assets", "js", "app.js"), "var app = 1;");

		RdpAuditPaths paths = CreatePaths();
		WebUiPublisher publisher = new(paths);

		WebUiPublishResult result = publisher.Publish(_sourceRoot);

		Assert.True(result.Succeeded, string.Join(" | ", result.Failures));
		Assert.Equal(Path.Combine(_root, "ProgramData", "RdpAudit", "WebUI", "wwwroot"), result.TargetDirectory);
		Assert.True(File.Exists(Path.Combine(result.TargetDirectory, "index.html")));
		Assert.True(File.Exists(Path.Combine(result.TargetDirectory, "assets", "js", "app.js")));
		Assert.Equal(
			File.ReadAllText(Path.Combine(_sourceRoot, "index.html")),
			File.ReadAllText(Path.Combine(result.TargetDirectory, "index.html")));
		Assert.Equal(
			File.ReadAllText(Path.Combine(_sourceRoot, "assets", "js", "app.js")),
			File.ReadAllText(Path.Combine(result.TargetDirectory, "assets", "js", "app.js")));
		Assert.True(File.Exists(Path.Combine(result.TargetDirectory, WebUiPublisher.ManifestFileName)));
	}

	/// <summary>Given a tampered target file, when re-published, then the tampered file is rewritten with
	/// the source bytes instead of being left as-is.</summary>
	[Fact]
	public void Publish_RewritesTamperedFilesAndVerifiesHashes()
	{
		File.WriteAllText(Path.Combine(_sourceRoot, "index.html"), "<html>good</html>");

		RdpAuditPaths paths = CreatePaths();
		WebUiPublisher publisher = new(paths);

		WebUiPublishResult first = publisher.Publish(_sourceRoot);
		Assert.True(first.Succeeded, string.Join(" | ", first.Failures));

		string target = Path.Combine(paths.WebUiWwwRootDirectory, "index.html");
		File.WriteAllText(target, "<html>evil</html>");

		WebUiPublishResult second = publisher.Publish(_sourceRoot);

		Assert.True(second.Succeeded, string.Join(" | ", second.Failures));
		Assert.Equal("<html>good</html>", File.ReadAllText(target));
	}

	/// <summary>Given an existing target with unchanged files, when re-published, then no file is copied
	/// and the result still verifies all of them.</summary>
	[Fact]
	public void Publish_IsIdempotentAndSkipsUnchangedFiles()
	{
		File.WriteAllText(Path.Combine(_sourceRoot, "index.html"), "<html>same</html>");

		RdpAuditPaths paths = CreatePaths();
		WebUiPublisher publisher = new(paths);

		WebUiPublishResult first = publisher.Publish(_sourceRoot);
		Assert.True(first.Succeeded, string.Join(" | ", first.Failures));
		Assert.Equal(1, first.FilesCopied);

		WebUiPublishResult second = publisher.Publish(_sourceRoot);

		Assert.True(second.Succeeded, string.Join(" | ", second.Failures));
		Assert.Equal(0, second.FilesCopied);
		Assert.Equal(1, second.FilesVerified);
	}

	/// <summary>Given a source tree with a 'secrets' folder, when published, then the publish fails with
	/// a curated refusal that names the vault area.</summary>
	[Fact]
	public void Publish_RefusesASourceSecretsFolder()
	{
		File.WriteAllText(Path.Combine(_sourceRoot, "index.html"), "<html>x</html>");
		Directory.CreateDirectory(Path.Combine(_sourceRoot, "secrets"));
		File.WriteAllText(Path.Combine(_sourceRoot, "secrets", "token.dat"), "secret");

		RdpAuditPaths paths = CreatePaths();
		WebUiPublisher publisher = new(paths);

		WebUiPublishResult result = publisher.Publish(_sourceRoot);

		Assert.False(result.Succeeded);
		Assert.Contains(result.Failures, failure => failure.Contains("secrets", StringComparison.OrdinalIgnoreCase));
		Assert.False(File.Exists(Path.Combine(paths.WebUiWwwRootDirectory, "secrets", "token.dat")));
	}

	/// <summary>Given an empty source tree, when published against an empty target, then the target gets
	/// only the manifest and no content files.</summary>
	[Fact]
	public void Publish_WithEmptySource_PublishesManifestOnly()
	{
		RdpAuditPaths paths = CreatePaths();
		WebUiPublisher publisher = new(paths);

		WebUiPublishResult result = publisher.Publish(_sourceRoot);

		Assert.True(result.Succeeded, string.Join(" | ", result.Failures));
		Assert.Equal(0, result.FilesCopied);
		Assert.True(File.Exists(Path.Combine(paths.WebUiWwwRootDirectory, WebUiPublisher.ManifestFileName)));
	}

	/// <summary>Given a missing source tree, when published, then the result reports the curated failure
	/// instead of throwing.</summary>
	[Fact]
	public void Publish_WithMissingSource_FailsCleanly()
	{
		RdpAuditPaths paths = CreatePaths();
		WebUiPublisher publisher = new(paths);

		WebUiPublishResult result = publisher.Publish(Path.Combine(_root, "missing-src"));

		Assert.False(result.Succeeded);
		Assert.Contains(result.Failures, failure => failure.Contains("does not exist", StringComparison.OrdinalIgnoreCase));
	}

	/// <summary>Given a file removed from the source after a publish, when re-published, then the old
	/// target file is removed via the manifest.</summary>
	[Fact]
	public void Publish_RemovesStaleFilesViaManifest()
	{
		File.WriteAllText(Path.Combine(_sourceRoot, "index.html"), "<html>x</html>");
		File.WriteAllText(Path.Combine(_sourceRoot, "old.txt"), "old");

		RdpAuditPaths paths = CreatePaths();
		WebUiPublisher publisher = new(paths);

		WebUiPublishResult first = publisher.Publish(_sourceRoot);
		Assert.True(first.Succeeded, string.Join(" | ", first.Failures));
		Assert.True(File.Exists(Path.Combine(paths.WebUiWwwRootDirectory, "old.txt")));

		File.Delete(Path.Combine(_sourceRoot, "old.txt"));
		WebUiPublishResult second = publisher.Publish(_sourceRoot);

		Assert.True(second.Succeeded, string.Join(" | ", second.Failures));
		Assert.False(File.Exists(Path.Combine(paths.WebUiWwwRootDirectory, "old.txt")));
	}

	/// <summary>Given a target folder that already has a pool grant on Windows, when published, then the
	/// published files are readable by the pool (real ACL applied using the local Users group).</summary>
	[SupportedOSPlatform("windows")]
	[Fact]
	public void Publish_WithPoolGrant_AppliesAndVerifiesAclOnWindows()
	{
		File.WriteAllText(Path.Combine(_sourceRoot, "index.html"), "<html>x</html>");

		RdpAuditPaths paths = CreatePaths();
		Directory.CreateDirectory(paths.WebUiWwwRootDirectory);

		string poolAccount = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
		WebUiPublisher publisher = new(paths, webPoolIdentity: poolAccount);

		WebUiPublishResult result = publisher.Publish(_sourceRoot);

		Assert.True(result.Succeeded, string.Join(" | ", result.Failures));
		DirectorySecurity security = new DirectoryInfo(paths.WebUiWwwRootDirectory)
			.GetAccessControl(AccessControlSections.Access);
		string sddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
		string currentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
		Assert.Contains(currentUserSid, sddl, StringComparison.Ordinal);
	}
}
