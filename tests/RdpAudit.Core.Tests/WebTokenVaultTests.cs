// File:    tests/RdpAudit.Core.Tests/WebTokenVaultTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the web-UI bearer-token vault contract: cryptographically random token minting, the
//          store/load round-trip (the file must never contain the plaintext), the refusal paths
//          (missing, empty, oversized, plaintext, wrong-scoped and corrupt vault files; unavailable
//          protector), the pure file-DACL checker used as the post-write refusal gate, and the real
//          filesystem behaviour - on Windows the secrets folder is hardened to the storage ACL policy
//          and the written token file grants nothing to Users / Everyone / Authenticated Users.
//          Every test works inside a temporary directory and restores nothing outside it.
// Depends: WebTokenVault, InMemorySecretProtector, StorageAclPolicy, xUnit
// Extends: Add a refusal here whenever the vault gains a rule.

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using RdpAudit.Core.Security;
using Xunit;

namespace RdpAudit.Core.Tests;

[SupportedOSPlatform("windows")]
public sealed class WebTokenVaultTests : IDisposable
{
	// ── Fields ───────────────────────────────────────────────────────────────────

	private readonly string _root;

	public WebTokenVaultTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-webvault-" + Guid.NewGuid().ToString("N"));
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

	/// <summary>A protector that transparently reports itself unavailable; used to prove the vault
	/// refuses to persist a plaintext token when no protection exists.</summary>
	private sealed class UnavailableProtector : ISecretProtector
	{
		public bool IsAvailable => false;

		public bool IsProtectedEnvelope(string? value) => ProtectedEnvelope.IsEnvelope(value);

		public string Protect(string plaintext, SecretScope scope = SecretScope.LocalMachine)
			=> throw new NotSupportedException("This protector is unavailable by design.");

		public string Unprotect(string envelopeOrPlaintext)
			=> throw new NotSupportedException("This protector is unavailable by design.");
	}

	private WebTokenVault CreateVault()
	{
		string tokenPath = Path.Combine(_root, "secrets", "token.dat");
		return new WebTokenVault(new InMemorySecretProtector(), tokenPath);
	}

	// ── Token minting ───────────────────────────────────────────────────────────

	/// <summary>Given the vault mints a token, then it is 64 lowercase hex characters, and two
	/// consecutive mints do not collide.</summary>
	[Fact]
	public void GenerateNewToken_Returns64LowercaseHexCharactersAndDoesNotRepeat()
	{
		string first = WebTokenVault.GenerateNewToken();
		string second = WebTokenVault.GenerateNewToken();

		Assert.Equal(64, first.Length);
		Assert.All(first, character => Assert.True(Uri.IsHexDigit(character), "token must be hex"));
		Assert.Equal(first, first.ToLowerInvariant());
		Assert.NotEqual(first, second);
	}

	// ── Round trip ──────────────────────────────────────────────────────────────

	/// <summary>Given a stored token, when the vault loads it back, then the plaintext round-trips - and
	/// the file on disk is a protected envelope that never contains the plaintext.</summary>
	[Fact]
	public void StoreThenLoad_RoundTripsTokenAndFileNeverContainsPlaintext()
	{
		WebTokenVault vault = CreateVault();
		const string token = "shared-web-token-0123456789-abcdefghij";

		vault.StoreToken(token);

		Assert.True(vault.Exists);
		string persisted = File.ReadAllText(vault.TokenFilePath);
		Assert.StartsWith("{", persisted, StringComparison.Ordinal);
		Assert.DoesNotContain(token, persisted, StringComparison.Ordinal);
		Assert.Equal(token, vault.LoadToken());
	}

	/// <summary>Given a minted-and-stored token, when it is loaded, then the returned value is the same
	/// minted plaintext; the convenience combines generate with store atomically.</summary>
	[Fact]
	public void GenerateAndStoreToken_ThenLoad_ReturnsTheSameToken()
	{
		WebTokenVault vault = CreateVault();

		string minted = vault.GenerateAndStoreToken();
		string loaded = vault.LoadToken();

		Assert.Equal(64, minted.Length);
		Assert.Equal(minted, loaded);
	}

	// ── Store refusals ──────────────────────────────────────────────────────────

	/// <summary>Given no working protector, when a token is stored, then the vault refuses BEFORE any
	/// file is written: a plaintext token file is the one outcome this class must never produce.</summary>
	[Fact]
	public void StoreToken_WhenTheProtectorIsUnavailable_RefusesAndWritesNothing()
	{
		string tokenPath = Path.Combine(_root, "secrets", "token.dat");
		WebTokenVault vault = new(new UnavailableProtector(), tokenPath);

		SecretProtectionException exception = Assert.Throws<SecretProtectionException>(
			() => vault.StoreToken("shared-web-token-0123456789-abcdefghij"));

		Assert.Contains("refuses", exception.Message, StringComparison.OrdinalIgnoreCase);
		Assert.False(File.Exists(tokenPath));
	}

	/// <summary>Given a token shorter than the accepted floor, when it is stored, then the argument is
	/// rejected: weak shared secrets must fail loudly, not silently.</summary>
	[Theory]
	[InlineData("a")]
	[InlineData("short-token")]
	[InlineData("   ")]
	public void StoreToken_WithTooShortOrBlankToken_Throws(string token)
	{
		WebTokenVault vault = CreateVault();

		Assert.Throws<ArgumentException>(() => vault.StoreToken(token));
		Assert.False(vault.Exists);
	}

	// ── Load refusals ───────────────────────────────────────────────────────────

	/// <summary>Given no vault file yet, when the token is loaded, then the refusal names the
	/// operator action (configure web access) and never invents a token.</summary>
	[Fact]
	public void LoadToken_WhenTheFileIsMissing_Refuses()
	{
		WebTokenVault vault = CreateVault();

		SecretProtectionException exception = Assert.Throws<SecretProtectionException>(() => vault.LoadToken());

		Assert.Contains("does not exist", exception.Message, StringComparison.Ordinal);
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	public void LoadToken_WhenTheFileIsEmpty_Refuses(string content)
	{
		WebTokenVault vault = CreateVault();
		Directory.CreateDirectory(Path.GetDirectoryName(vault.TokenFilePath)!);
		File.WriteAllText(vault.TokenFilePath, content);

		SecretProtectionException exception = Assert.Throws<SecretProtectionException>(() => vault.LoadToken());

		Assert.Contains("empty or corrupted", exception.Message, StringComparison.Ordinal);
	}

	/// <summary>Given a file far larger than any envelope, when the token is loaded, then the vault
	/// refuses instead of parsing a foreign file.</summary>
	[Fact]
	public void LoadToken_WhenTheFileIsOversized_Refuses()
	{
		WebTokenVault vault = CreateVault();
		Directory.CreateDirectory(Path.GetDirectoryName(vault.TokenFilePath)!);
		File.WriteAllText(vault.TokenFilePath, new string('x', 8000));

		SecretProtectionException exception = Assert.Throws<SecretProtectionException>(() => vault.LoadToken());

		Assert.Contains("larger than", exception.Message, StringComparison.Ordinal);
	}

	/// <summary>Given a plaintext file, when the token is loaded, then the vault refuses: the vault
	/// file is shared with the web proxy, so even an accidentally plaintext token must not be served.</summary>
	[Fact]
	public void LoadToken_WhenTheFileIsPlaintext_Refuses()
	{
		WebTokenVault vault = CreateVault();
		Directory.CreateDirectory(Path.GetDirectoryName(vault.TokenFilePath)!);
		File.WriteAllText(vault.TokenFilePath, "shared-web-token-0123456789-abcdefghij");

		SecretProtectionException exception = Assert.Throws<SecretProtectionException>(() => vault.LoadToken());

		Assert.Contains("protected envelope", exception.Message, StringComparison.Ordinal);
	}

	/// <summary>Given a user-scoped envelope, when the token is loaded, then the vault refuses: the
	/// proxy runs as the IIS application-pool identity and could never unseal a user-scoped secret.</summary>
	[Fact]
	public void LoadToken_WhenTheEnvelopeIsUserScoped_Refuses()
	{
		WebTokenVault vault = CreateVault();
		Directory.CreateDirectory(Path.GetDirectoryName(vault.TokenFilePath)!);
		string envelope = new InMemorySecretProtector().Protect(
			"shared-web-token-0123456789-abcdefghij",
			SecretScope.CurrentUser);
		File.WriteAllText(vault.TokenFilePath, envelope);

		SecretProtectionException exception = Assert.Throws<SecretProtectionException>(() => vault.LoadToken());

		Assert.Contains("machine-scoped", exception.Message, StringComparison.Ordinal);
	}

	/// <summary>Given a JSON envelope whose payload is not valid base64, when the token is loaded, then
	/// the vault refuses with a curated message that contains no vault content.</summary>
	[Fact]
	public void LoadToken_WhenTheEnvelopeIsCorrupt_Refuses()
	{
		WebTokenVault vault = CreateVault();
		Directory.CreateDirectory(Path.GetDirectoryName(vault.TokenFilePath)!);
		File.WriteAllText(vault.TokenFilePath, "{\"$protected\":\"!!!not-base64!!!\",\"scope\":\"LocalMachine\"}");

		SecretProtectionException exception = Assert.Throws<SecretProtectionException>(() => vault.LoadToken());

		Assert.DoesNotContain("not-base64", exception.Message, StringComparison.Ordinal);
	}

	// ── Pure file-DACL gate ─────────────────────────────────────────────────────

	/// <summary>The post-write gate accepts exactly the hardened descriptor: SYSTEM + Administrators
	/// full control, nothing else.</summary>
	[Theory]
	[InlineData("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")]
	[InlineData("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")]
	public void FileDacl_WhenOnlySystemAndAdministrators_IsAccepted(string sddl)
	{
		Assert.True(WebTokenVault.FileDaclAllowsOnlySystemAndAdministrators(sddl));
	}

	/// <summary>The post-write gate refuses any permissive known SID: the token file may be read by
	/// SYSTEM, Administrators and - when configured - only the dedicated pool identity.</summary>
	[Theory]
	[InlineData("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")]
	[InlineData("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)")]
	[InlineData("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)")]
	public void FileDacl_WhenAPermissiveSidIsGranted_IsRefused(string sddl)
	{
		Assert.False(WebTokenVault.FileDaclAllowsOnlySystemAndAdministrators(sddl));
	}

	/// <summary>A descriptor without a DACL segment means everyone has full control; the gate refuses it.</summary>
	[Theory]
	[InlineData("")]
	[InlineData("O:BAG:SY")]
	public void FileDacl_WhenThereIsNoDacl_IsRefused(string sddl)
	{
		Assert.False(WebTokenVault.FileDaclAllowsOnlySystemAndAdministrators(sddl));
	}

	/// <summary>When a dedicated pool identity was configured, its grant is part of the expected file
	/// ACL; the SAME descriptor without that sid remains refused.</summary>
	[Fact]
	public void FileDacl_WhenTheConfiguredPoolSidIsGranted_IsAccepted()
	{
		string poolSidValue = "S-1-5-21-1234567890-123456789-1234567890-1001";
		SecurityIdentifier poolSid = new(poolSidValue);
		string sddl = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + poolSidValue + ")";

		Assert.True(WebTokenVault.FileDaclAllowsOnlySystemAndAdministrators(sddl, poolSid));
		Assert.False(WebTokenVault.FileDaclAllowsOnlySystemAndAdministrators(sddl));
	}

	// ── Real filesystem behaviour (Windows) ─────────────────────────────────────

	/// <summary>Given a successful store, when the secrets folder is read back from the filesystem, then
	/// it is hardened exactly like the evidence tree: protected DACL, SYSTEM + Administrators full
	/// control and no permissive well-known grant.</summary>
	[Fact]
	public void StoreToken_HardensTheSecretsFolderToTheStoragePolicy()
	{
		WebTokenVault vault = CreateVault();
		vault.StoreToken("shared-web-token-0123456789-abcdefghij");

		string folder = Path.GetDirectoryName(vault.TokenFilePath)!;
		DirectorySecurity security = new DirectoryInfo(folder).GetAccessControl(AccessControlSections.Access);
		string sddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);

		Assert.True(StorageAclPolicy.Assess(sddl).IsCompliant, sddl);
		Assert.True(security.AreAccessRulesProtected, "inheritance must be disabled on the secrets folder");
	}

	/// <summary>Given a successful store, when the token file ACL is read back, then it grants nothing to
	/// Users, Everyone or Authenticated Users: the file carries only the hardened folder's grants.</summary>
	[Fact]
	public void StoreToken_TheTokenFileGrantsNothingToPermissiveSids()
	{
		WebTokenVault vault = CreateVault();
		vault.StoreToken("shared-web-token-0123456789-abcdefghij");

		FileSecurity security = new FileInfo(vault.TokenFilePath).GetAccessControl(AccessControlSections.Access);
		string[] permissive = [
			new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Value,
			new SecurityIdentifier(WellKnownSidType.WorldSid, null).Value,
			new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null).Value,
		];
		foreach (FileSystemAccessRule rule in security.GetAccessRules(
			includeExplicit: true,
			includeInherited: true,
			targetType: typeof(SecurityIdentifier)))
		{
			Assert.DoesNotContain(((SecurityIdentifier)rule.IdentityReference).Value, permissive);
		}
	}

	/// <summary>Given a secrets folder with a permissive Users grant, when a token is stored, then the
	/// vault re-hardens the folder instead of proceeding under the permissive ACL.</summary>
	[Fact]
	public void StoreToken_RehardensASecretsFolderThatHadAPermissiveGrant()
	{
		WebTokenVault vault = CreateVault();
		string folder = Path.GetDirectoryName(vault.TokenFilePath)!;
		Directory.CreateDirectory(folder);
		DirectoryInfo info = new(folder);
		DirectorySecurity security = info.GetAccessControl();
		security.AddAccessRule(new FileSystemAccessRule(
			new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
			FileSystemRights.ReadAndExecute,
			InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
			PropagationFlags.None,
			AccessControlType.Allow));
		info.SetAccessControl(security);

		vault.StoreToken("shared-web-token-0123456789-abcdefghij");

		DirectorySecurity after = new DirectoryInfo(folder).GetAccessControl(AccessControlSections.Access);
		Assert.True(
			StorageAclPolicy.Assess(after.GetSecurityDescriptorSddlForm(AccessControlSections.Access)).IsCompliant,
			"the vault must re-harden a secrets folder that had a permissive grant");
		Assert.Equal("shared-web-token-0123456789-abcdefghij", vault.LoadToken());
	}
}
