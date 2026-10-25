// File:    src/RdpAudit.Core/Security/WebTokenVault.cs
// Module:  RdpAudit.Core.Security
// Purpose: Shared bearer-token vault for the IIS web proxy. Stores the WebUI proxy token as a
//          machine-scope DPAPI protected envelope inside %ProgramData%\RdpAudit\WebUI\secrets\token.dat
//          so the service and the IIS application-pool identity can both unseal it. Writes are atomic
//          (temp file + move) and the secrets folder is hardened with the storage ACL policy
//          (protected DACL, SYSTEM + Administrators full control, optionally read access for the web
//          pool identity). The vault REFUSES to write into or serve from a folder whose ACL is not
//          compliant, and refuses to serve a file that is empty, plaintext, oversized, wrong-scoped
//          or corrupt. Token plaintext never appears in exception messages.
//          Honest limit, stated because a security check that overstates itself is worse than none:
//          the ACL is asserted on the OWNED folder before and after the write; the token file itself
//          inherits the folder's protected DACL at creation time, so no per-file pass is performed.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Security;

/// <summary>
/// File-backed vault for the shared web-UI bearer token. Construct with the token file path
/// (tests use a temp root; production uses <c>RdpAuditPaths.WebUiTokenPath</c>). The vault is
/// deliberately free of any dependency on the real %ProgramData% root.
/// </summary>
public sealed class WebTokenVault
{
	/// <summary>Shortest accepted shared token length. Rotation mints 64-char tokens, comfortably above this.</summary>
	public const int MinTokenLength = 32;

	/// <summary>Longest accepted shared token length (guards against accidental content in the file).</summary>
	public const int MaxTokenLength = 512;

	/// <summary>Largest vault file accepted by <see cref="LoadToken"/>; anything bigger is corruption.</summary>
	public const long MaxVaultFileBytes = 4096;

	private static readonly SecurityIdentifier LocalSystemSid = new(WellKnownSidType.LocalSystemSid, null);
	private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
	private static readonly SecurityIdentifier UsersSid = new(WellKnownSidType.BuiltinUsersSid, null);
	private static readonly SecurityIdentifier EveryoneSid = new(WellKnownSidType.WorldSid, null);
	private static readonly SecurityIdentifier AuthenticatedUsersSid = new(WellKnownSidType.AuthenticatedUserSid, null);

	private readonly ISecretProtector _protector;
	private readonly string _tokenFilePath;
	private readonly string? _webPoolIdentity;

	/// <summary>Creates the vault for a token file path.</summary>
	/// <param name="protector">Secret protector producing machine-scope envelopes (DPAPI on Windows).</param>
	/// <param name="tokenFilePath">Full path of the token file (any directory; tests use a temp root).</param>
	/// <param name="webPoolIdentity">
	/// Optional IIS application-pool identity (e.g. <c>IIS APPPOOL\RdpAuditWebUi</c>) that receives
	/// read access to the secrets folder. Null/blank means only SYSTEM and Administrators may read.
	/// </param>
	public WebTokenVault(ISecretProtector protector, string tokenFilePath, string? webPoolIdentity = null)
	{
		_protector = protector ?? throw new ArgumentNullException(nameof(protector));
		ArgumentException.ThrowIfNullOrWhiteSpace(tokenFilePath);
		_tokenFilePath = Path.GetFullPath(tokenFilePath);
		_webPoolIdentity = webPoolIdentity;
	}

	/// <summary>Absolute path of the token file this vault reads and writes.</summary>
	public string TokenFilePath => _tokenFilePath;

	/// <summary>True when the token file already exists.</summary>
	public bool Exists => File.Exists(_tokenFilePath);

	/// <summary>Production-shaped vault rooted at <c>%ProgramData%\RdpAudit\WebUI\secrets\token.dat</c>.</summary>
	public static WebTokenVault CreateDefault(ISecretProtector protector, string? webPoolIdentity = null)
		=> new(protector, RdpAuditPaths.Default.WebUiTokenPath, webPoolIdentity);

	/// <summary>
	/// Mints a fresh cryptographically random shared token (64 hex characters). The value is returned
	/// exactly once so the caller can hand it to the service configuration; the vault itself only ever
	/// persists the protected envelope.
	/// </summary>
	public static string GenerateNewToken()
	{
		byte[] bytes = RandomNumberGenerator.GetBytes(32);
		return Convert.ToHexString(bytes).ToLowerInvariant();
	}

	/// <summary>Mints and stores a new shared token. Returns the plaintext once for the caller to wire up.</summary>
	public string GenerateAndStoreToken()
	{
		string token = GenerateNewToken();
		StoreToken(token);
		return token;
	}

	/// <summary>
	/// Protects and atomically stores the shared token. The secrets folder is created and hardened
	/// first; a folder whose ACL does not satisfy the storage policy causes the write to be REFUSED
	/// before any token bytes touch the disk.
	/// </summary>
	/// <exception cref="SecretProtectionException">On ACL refusal, protection failure or I/O failure.</exception>
	public void StoreToken(string plaintextToken)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(plaintextToken);
		string token = plaintextToken.Trim();
		if (token.Length < MinTokenLength || token.Length > MaxTokenLength)
		{
			throw new ArgumentException(
				"The web-UI token must be between " + MinTokenLength.ToString(System.Globalization.CultureInfo.InvariantCulture)
				+ " and " + MaxTokenLength.ToString(System.Globalization.CultureInfo.InvariantCulture) + " characters.",
				nameof(plaintextToken));
		}

		if (!_protector.IsAvailable)
		{
			throw new SecretProtectionException(
				"No secret protector is available on this host; the web-UI token vault refuses to persist a plaintext token.");
		}

		string directory = Path.GetDirectoryName(_tokenFilePath) ?? throw new SecretProtectionException(
			"The web-UI token vault path has no parent directory.");

		try
		{
			Directory.CreateDirectory(directory);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			throw new SecretProtectionException("The web-UI secrets folder could not be created.", ex);
		}

		SecurityIdentifier? poolSid = null;
		SecurityIdentifier? writerSid = null;
		if (OperatingSystem.IsWindows())
		{
			poolSid = ResolvePoolIdentitySid();
			writerSid = ResolveWriterSid();
			ApplyDirectoryAcl(directory, poolSid, writerSid);
			AssertHardenedFolder(directory);
		}

		string envelope = _protector.Protect(token, SecretScope.LocalMachine);
		string temporaryPath = _tokenFilePath + ".tmp";
		try
		{
			File.WriteAllText(temporaryPath, envelope, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
			File.Move(temporaryPath, _tokenFilePath, overwrite: true);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			TryDelete(temporaryPath);
			throw new SecretProtectionException("The web-UI token vault file could not be written atomically.", ex);
		}

		if (OperatingSystem.IsWindows())
		{
			// Post-write proof that the file inherited the hardened folder DACL; on failure the file is
			// removed so a permissive token file is never left behind.
			try
			{
				AssertFileAcl(_tokenFilePath, poolSid, writerSid);
			}
			catch (SecretProtectionException)
			{
				TryDelete(_tokenFilePath);
				throw;
			}
		}
	}

	/// <summary>
	/// Loads and unseals the shared token. Refuses to serve when the file is missing, empty, oversized,
	/// not a protected envelope, not machine-scoped, or unreadable; in every refusal the message is
	/// curated and never contains vault content.
	/// </summary>
	/// <exception cref="SecretProtectionException">On any refusal or unprotect failure.</exception>
	public string LoadToken()
	{
		if (!File.Exists(_tokenFilePath))
		{
			throw new SecretProtectionException(
				"The web-UI token vault does not exist yet; configure web access before starting the web proxy.");
		}

		string content;
		try
		{
			content = File.ReadAllText(_tokenFilePath, Encoding.UTF8).Trim();
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			throw new SecretProtectionException("The web-UI token vault could not be read.", ex);
		}

		if (string.IsNullOrWhiteSpace(content))
		{
			throw new SecretProtectionException("The web-UI token vault file is empty or corrupted.");
		}

		if (content.Length > MaxVaultFileBytes)
		{
			throw new SecretProtectionException(
				"The web-UI token vault file is larger than a protected envelope can be; refusing to use it.");
		}

		if (!_protector.IsProtectedEnvelope(content))
		{
			throw new SecretProtectionException(
				"The web-UI token vault does not contain a protected envelope; it may be corrupted or tampered with.");
		}

		// Refuse CurrentUser envelopes eagerly: the proxy runs as the IIS application-pool identity and
		// could never unseal a user-scoped envelope. Parsing only for the scope check keeps the cipher
		// bytes out of any message.
		(_, SecretScope scope) = ProtectedEnvelope.Parse(content);
		if (scope != SecretScope.LocalMachine)
		{
			throw new SecretProtectionException(
				"The web-UI token vault is not machine-scoped and cannot be shared with the web proxy.");
		}

		try
		{
			return _protector.Unprotect(content);
		}
		catch (SecretProtectionException ex)
		{
			throw new SecretProtectionException(
				"The web-UI token vault could not be unsealed; it may be corrupted or written by a different host.", ex);
		}
	}

	/// <summary>Translates the configured pool identity to a SID and forbids the well-known permissive SIDs.</summary>
	[SupportedOSPlatform("windows")]
	private SecurityIdentifier? ResolvePoolIdentitySid()
	{
		if (string.IsNullOrWhiteSpace(_webPoolIdentity))
		{
			return null;
		}

		try
		{
			SecurityIdentifier translated = (SecurityIdentifier)new NTAccount(_webPoolIdentity.Trim())
				.Translate(typeof(SecurityIdentifier));
			if (translated == UsersSid || translated == EveryoneSid || translated == AuthenticatedUsersSid)
			{
				throw new SecretProtectionException(
					"The configured web pool identity is a permissive well-known group (Users, Everyone or Authenticated Users); "
					+ "the storage policy forbids granting it access to the secrets folder.");
			}

			return translated;
		}
		catch (SecretProtectionException)
		{
			throw;
		}
		catch (Exception ex) when (ex is IdentityNotMappedException or PlatformNotSupportedException or SystemException)
		{
			throw new SecretProtectionException(
				"The configured web pool identity could not be resolved to a security identifier.", ex);
		}
	}

	/// <summary>
	/// SID of the identity performing this write, or null when the DACL already covers it. The secrets
	/// folder is hardened to SYSTEM and Administrators, but the writer is not necessarily either: a
	/// filtered administrator token carries BUILTIN\Administrators as deny-only, and a standard user is
	/// not a member of it at all. Hardening that does not name the writer locks the vault against the
	/// process that stores the token. A single identity is added - never a group.
	/// </summary>
	[SupportedOSPlatform("windows")]
	private static SecurityIdentifier? ResolveWriterSid()
	{
		using WindowsIdentity identity = WindowsIdentity.GetCurrent();
		SecurityIdentifier? writer = identity.User;
		return writer is null || writer == LocalSystemSid || writer == AdministratorsSid ? null : writer;
	}

	/// <summary>
	/// Idempotently hardens the secrets folder: protect-first (inherited ACEs dropped), then SYSTEM +
	/// Administrators full control, then optional read-and-execute for the web pool identity, then Modify
	/// for the identity performing the write (skipped when that identity is SYSTEM or Administrators).
	/// </summary>
	[SupportedOSPlatform("windows")]
	private static void ApplyDirectoryAcl(string directory, SecurityIdentifier? poolSid, SecurityIdentifier? writerSid)
	{
		try
		{
			DirectoryInfo info = new(directory);
			DirectorySecurity security = info.GetAccessControl();

			// Order matters: protect first, then rebuild the grants, so a failure in between never
			// leaves the inherited Users grant alongside the intended ones.
			security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
			foreach (FileSystemAccessRule rule in security.GetAccessRules(
				includeExplicit: true,
				includeInherited: false,
				targetType: typeof(SecurityIdentifier)))
			{
				security.RemoveAccessRule(rule);
			}

			security.AddAccessRule(new FileSystemAccessRule(
				LocalSystemSid,
				FileSystemRights.FullControl,
				InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
				PropagationFlags.None,
				AccessControlType.Allow));
			security.AddAccessRule(new FileSystemAccessRule(
				AdministratorsSid,
				FileSystemRights.FullControl,
				InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
				PropagationFlags.None,
				AccessControlType.Allow));
			if (poolSid is not null)
			{
				security.AddAccessRule(new FileSystemAccessRule(
					poolSid,
					FileSystemRights.ReadAndExecute,
					InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
					PropagationFlags.None,
					AccessControlType.Allow));
			}

			// The writer keeps access to the folder it just hardened. Modify is enough to create the temp
			// file and to replace token.dat (Write on a directory carries FILE_DELETE_CHILD) and is less
			// than the SYSTEM/Administrators grant because the writer needs no WRITE_DAC.
			if (writerSid is not null)
			{
				security.AddAccessRule(new FileSystemAccessRule(
					writerSid,
					FileSystemRights.Modify,
					InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
					PropagationFlags.None,
					AccessControlType.Allow));
			}

			info.SetAccessControl(security);
		}
		catch (Exception ex) when (ex is UnauthorizedAccessException or PrivilegeNotHeldException
			or IOException or InvalidOperationException or PlatformNotSupportedException)
		{
			throw new SecretProtectionException(
				"The web-UI secrets folder ACL could not be hardened; the token will not be stored under it.", ex);
		}
	}

	/// <summary>Reads the folder DACL and refuses the write when it is not compliant with the storage policy.</summary>
	[SupportedOSPlatform("windows")]
	private static void AssertHardenedFolder(string directory)
	{
		StorageAclAssessment assessment;
		try
		{
			DirectorySecurity security = new DirectoryInfo(directory)
				.GetAccessControl(AccessControlSections.Access);
			string sddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
			assessment = StorageAclPolicy.Assess(sddl);
		}
		catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException
			or PlatformNotSupportedException or SystemException)
		{
			throw new SecretProtectionException(
				"The web-UI secrets folder ACL could not be read; refusing to store the token under 'we could not look'.", ex);
		}

		if (!assessment.IsVerifiable || !assessment.IsCompliant)
		{
			throw new SecretProtectionException(
				"Refusing to store the web-UI token: the secrets folder ACL is not compliant with the storage policy ("
				+ assessment.Describe() + ").");
		}
	}

	/// <summary>Verifies the token file inherited only the declared single identities and no permissive
	/// well-known SID.</summary>
	[SupportedOSPlatform("windows")]
	private static void AssertFileAcl(string filePath, SecurityIdentifier? poolSid, SecurityIdentifier? writerSid)
	{
		string sddl;
		try
		{
			FileSecurity security = new FileInfo(filePath).GetAccessControl(AccessControlSections.Access);
			sddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
		}
		catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException
			or PlatformNotSupportedException or SystemException)
		{
			throw new SecretProtectionException(
				"The web-UI token file ACL could not be read after writing; the token file was removed.", ex);
		}

		if (!FileDaclAllowsOnlySystemAndAdministrators(sddl, poolSid, writerSid))
		{
			throw new SecretProtectionException(
				"The web-UI token file ACL does not restrict access to SYSTEM, Administrators, the configured "
				+ "pool identity and the identity that wrote it; the token file was removed.");
		}
	}

	/// <summary>
	/// True when every allow ACE of the file DACL grants SYSTEM, Administrators, the configured pool
	/// identity or the single identity that wrote the file. Inherited ACEs are accepted (files normally
	/// inherit the hardened folder DACL); a grant to any group - including Users, Everyone or Authenticated
	/// Users - fails the check, and so does a SID that was not declared for this write. A missing DACL also
	/// fails: 'D:' absent means everyone has full control.
	/// </summary>
	internal static bool FileDaclAllowsOnlySystemAndAdministrators(
		string sddl,
		SecurityIdentifier? poolSid = null,
		SecurityIdentifier? writerSid = null)
	{
		int daclIndex = StorageAclPolicy.FindDaclSegment(sddl);
		if (daclIndex < 0)
		{
			return false;
		}

		string dacl = sddl[daclIndex..];
		bool foundAnyAllowAce = false;
		int index = dacl.IndexOf('(');
		while (index >= 0 && index < dacl.Length)
		{
			int end = dacl.IndexOf(')', index);
			if (end < 0)
			{
				break;
			}

			string ace = dacl[(index + 1)..end];
			if (ace.Length > 0 && ace[0] == 'A')
			{
				foundAnyAllowAce = true;
				string[] parts = ace.Split(';');
				string sid = parts.Length >= 6 ? parts[5] : string.Empty;
				string? allowedPoolSid = poolSid?.Value;
				string? allowedWriterSid = writerSid?.Value;
				if (!string.Equals(sid, "SY", StringComparison.Ordinal)
					&& !string.Equals(sid, "BA", StringComparison.Ordinal)
					&& !string.Equals(sid, allowedPoolSid, StringComparison.Ordinal)
					&& !string.Equals(sid, allowedWriterSid, StringComparison.Ordinal))
				{
					return false;
				}
			}

			index = dacl.IndexOf('(', end);
		}

		return foundAnyAllowAce;
	}

	private static void TryDelete(string path)
	{
		try
		{
			if (File.Exists(path))
			{
				File.Delete(path);
			}
		}
		catch
		{
			// Best-effort cleanup; the refusal has already been reported.
		}
	}
}
