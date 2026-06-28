// File:    src/RdpAudit.Core/Util/RdpConfigurationEditModel.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure, UI- and OS-agnostic edit model that backs the editable "RDP Configuration"
//          tab. Mirrors the subset of the live Windows Terminal Services configuration the
//          operator can change from the Configurator UI (Enable Remote Desktop, RDP port,
//          Single session per user, Hide users on logon screen, Authentication mode, Session
//          Shadowing mode). Performs all validation client-side so the UI can show clear
//          inline errors before any write is attempted, and emits a deterministic
//          RdpConfigurationChangeSet that describes the exact registry mutations the
//          downstream writer must perform. The model is registry- and Windows-API free so it
//          is fully unit-testable on Linux CI.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>One registry value the apply path must write. <c>Value</c> is the int DWORD value;
/// null means "delete value" (only used when the existing snapshot has a value but the operator
/// switched it back to "not configured"). Every entry is HKLM-rooted and uses the canonical key
/// paths declared in <see cref="RdpConfigurationModel"/> / <see cref="ShadowPolicyModel"/>.</summary>
public sealed record RdpRegistryWrite(string KeyPath, string ValueName, int? Value);

/// <summary>Deterministic plan of registry mutations produced by <see cref="RdpConfigurationEditModel"/>.
/// Empty when no edits diverge from the original snapshot.</summary>
public sealed record RdpConfigurationChangeSet(IReadOnlyList<RdpRegistryWrite> Writes)
{
	/// <summary>True when the change set has at least one pending write.</summary>
	public bool HasChanges => Writes.Count > 0;
}

/// <summary>Validation outcome for an <see cref="RdpConfigurationEditModel"/> snapshot. Errors
/// are returned as a list of English strings the UI can render verbatim.</summary>
public sealed record RdpConfigurationValidationResult(IReadOnlyList<string> Errors)
{
	/// <summary>True when no errors were collected.</summary>
	public bool IsValid => Errors.Count == 0;

	/// <summary>Cached empty result for convenience.</summary>
	public static RdpConfigurationValidationResult Ok { get; } = new(Array.Empty<string>());
}

/// <summary>Editable counterpart of <see cref="RdpConfigurationDto"/>. The model exposes the
/// subset of values the Configurator UI lets the operator change; helpers map a captured DTO
/// into a clean edit form and then diff the edited form back into an
/// <see cref="RdpConfigurationChangeSet"/>.</summary>
public sealed class RdpConfigurationEditModel
{
	/// <summary>True when Remote Desktop is enabled (registry: fDenyTSConnections = 0).</summary>
	public bool RdpEnabled { get; set; }

	/// <summary>Configured listener TCP port (1..65535). The UI default is
	/// <see cref="RdpConfigurationModel.DefaultRdpPort"/> when the registry value is absent.</summary>
	public int Port { get; set; } = RdpConfigurationModel.DefaultRdpPort;

	/// <summary>True when only one RDP session per user account is permitted at a time
	/// (registry: fSingleSessionPerUser = 1).</summary>
	public bool SingleSessionPerUser { get; set; }

	/// <summary>True when the operator wants user names hidden on the secure logon screen
	/// (writes dontdisplaylastusername = 1 AND DontEnumerateConnectedUsers = 1 atomically).</summary>
	public bool HideUsersOnLogon { get; set; }

	/// <summary>Authentication mode. Maps to UserAuthentication + SecurityLayer atomically per
	/// <see cref="RdpConfigurationEditModel.AuthModeToRegistry"/>.</summary>
	public RdpAuthenticationMode AuthenticationMode { get; set; } = RdpAuthenticationMode.NetworkLevelAuth;

	/// <summary>Session shadowing mode (raw 0..4, or <see cref="ShadowPolicyMode.NotConfigured"/>
	/// to leave the registry value absent).</summary>
	public ShadowPolicyMode ShadowMode { get; set; } = ShadowPolicyMode.NotConfigured;

	/// <summary>True when the host must prompt for credentials on every RDP connection (writes
	/// fPromptForPassword = 1 under the Terminal Services policy key; the apply path also clears
	/// the per-listener fallback when it is set to a contradictory value so the effective state
	/// stays deterministic).</summary>
	public bool AlwaysPromptForPassword { get; set; }

	/// <summary>Builds an edit model preloaded with the values captured in <paramref name="dto"/>.
	/// Missing / out-of-range values fall back to the conservative recommended defaults so the
	/// operator never accidentally clears a setting just by hitting Apply.</summary>
	public static RdpConfigurationEditModel FromSnapshot(RdpConfigurationDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);

		bool rdpEnabled = dto.RdpEnabled ?? false;
		int port = dto.ConfiguredPort is int p && RdpConfigurationModel.IsValidPort(p)
			? p
			: RdpConfigurationModel.DefaultRdpPort;

		bool singleSession = RdpConfigurationModel.BoolFlagFromRaw(dto.SingleSessionPerUserRaw);
		bool hideUsers = RdpConfigurationModel.BoolFlagFromRaw(dto.DontDisplayLastUserNameRaw)
			|| RdpConfigurationModel.BoolFlagFromRaw(dto.DontEnumerateConnectedUsersRaw);

		RdpAuthenticationMode auth = AuthenticationFromRaw(
			dto.UserAuthenticationRaw == -1 ? null : dto.UserAuthenticationRaw,
			dto.SecurityLayerRaw == -1 ? null : dto.SecurityLayerRaw);

		ShadowPolicyMode shadow = dto.ShadowModeRaw == -1
			? ShadowPolicyMode.NotConfigured
			: ShadowPolicyModel.FromRawValue(dto.ShadowModeRaw);

		bool alwaysPrompt = RdpConfigurationModel.EffectivePromptForPassword(
			dto.PromptForPasswordPolicyRaw,
			dto.PromptForPasswordListenerRaw) ?? false;

		return new RdpConfigurationEditModel
		{
			RdpEnabled = rdpEnabled,
			Port = port,
			SingleSessionPerUser = singleSession,
			HideUsersOnLogon = hideUsers,
			AuthenticationMode = auth,
			ShadowMode = shadow,
			AlwaysPromptForPassword = alwaysPrompt,
		};
	}

	/// <summary>Validates every field. Errors are returned in the order the UI renders them.</summary>
	public RdpConfigurationValidationResult Validate()
	{
		List<string> errors = new();

		if (!RdpConfigurationModel.IsValidPort(Port))
		{
			errors.Add(string.Format(CultureInfo.InvariantCulture,
				"RDP port {0} is out of range (1..65535).", Port));
		}

		if (!Enum.IsDefined(typeof(RdpAuthenticationMode), AuthenticationMode))
		{
			errors.Add(string.Format(CultureInfo.InvariantCulture,
				"Authentication mode {0} is not a recognised value.", (int)AuthenticationMode));
		}

		if (ShadowMode != ShadowPolicyMode.NotConfigured
			&& !ShadowPolicyModel.IsValidShadowValue((int)ShadowMode))
		{
			errors.Add(string.Format(CultureInfo.InvariantCulture,
				"Session shadowing mode {0} is not in the 0..4 range.", (int)ShadowMode));
		}

		return errors.Count == 0
			? RdpConfigurationValidationResult.Ok
			: new RdpConfigurationValidationResult(errors);
	}

	/// <summary>Compares this edit model against the captured snapshot it was loaded from
	/// (or any baseline DTO) and returns the deterministic set of registry writes required
	/// to bring the host into the edited state. Unchanged values are not emitted so the
	/// writer can apply the smallest possible mutation.</summary>
	public RdpConfigurationChangeSet ComputeChanges(RdpConfigurationDto baseline)
	{
		ArgumentNullException.ThrowIfNull(baseline);
		List<RdpRegistryWrite> writes = new();

		// --- fDenyTSConnections (inverse of RdpEnabled) -------------------------------------------
		int desiredDeny = RdpEnabled ? 0 : 1;
		int? currentDeny = baseline.RdpEnabled switch
		{
			true => 0,
			false => 1,
			_ => null,
		};
		if (currentDeny != desiredDeny)
		{
			writes.Add(new RdpRegistryWrite(
				RdpConfigurationModel.TerminalServerKey,
				RdpConfigurationModel.DenyTsConnectionsValueName,
				desiredDeny));
		}

		// --- PortNumber ----------------------------------------------------------------------------
		int currentPort = baseline.ConfiguredPort
			?? RdpConfigurationModel.DefaultRdpPort;
		if (currentPort != Port)
		{
			writes.Add(new RdpRegistryWrite(
				RdpConfigurationModel.RdpTcpListenerKey,
				RdpConfigurationModel.PortNumberValueName,
				Port));
		}

		// --- fSingleSessionPerUser ----------------------------------------------------------------
		int desiredSingle = SingleSessionPerUser ? 1 : 0;
		int? currentSingle = baseline.SingleSessionPerUserRaw;
		if (currentSingle != desiredSingle)
		{
			writes.Add(new RdpRegistryWrite(
				RdpConfigurationModel.TerminalServerKey,
				RdpConfigurationModel.SingleSessionPerUserValueName,
				desiredSingle));
		}

		// --- Hide users on logon (two values, applied atomically) ---------------------------------
		int desiredHide = HideUsersOnLogon ? 1 : 0;
		int? currentDontDisplay = baseline.DontDisplayLastUserNameRaw;
		int? currentDontEnumerate = baseline.DontEnumerateConnectedUsersRaw;
		if (currentDontDisplay != desiredHide)
		{
			writes.Add(new RdpRegistryWrite(
				RdpConfigurationModel.SystemPolicyKey,
				RdpConfigurationModel.DontDisplayLastUserNameValueName,
				desiredHide));
		}

		if (currentDontEnumerate != desiredHide)
		{
			writes.Add(new RdpRegistryWrite(
				RdpConfigurationModel.SystemPolicyKey,
				RdpConfigurationModel.DontEnumerateConnectedUsersValueName,
				desiredHide));
		}

		// --- Authentication mode (UserAuthentication + SecurityLayer, atomic pair) ----------------
		(int desiredAuth, int desiredSec) = AuthModeToRegistry(AuthenticationMode);
		int? currentAuth = baseline.UserAuthenticationRaw == -1 ? null : baseline.UserAuthenticationRaw;
		int? currentSec = baseline.SecurityLayerRaw == -1 ? null : baseline.SecurityLayerRaw;
		if (currentAuth != desiredAuth)
		{
			writes.Add(new RdpRegistryWrite(
				RdpConfigurationModel.RdpTcpListenerKey,
				RdpConfigurationModel.UserAuthenticationValueName,
				desiredAuth));
		}

		if (currentSec != desiredSec)
		{
			writes.Add(new RdpRegistryWrite(
				RdpConfigurationModel.RdpTcpListenerKey,
				RdpConfigurationModel.SecurityLayerValueName,
				desiredSec));
		}

		// --- Session shadowing mode (or remove when set to NotConfigured) ------------------------
		int? desiredShadow = ShadowMode == ShadowPolicyMode.NotConfigured ? null : (int)ShadowMode;
		int? currentShadow = baseline.ShadowModeRaw == -1 ? null : baseline.ShadowModeRaw;
		if (currentShadow != desiredShadow)
		{
			writes.Add(new RdpRegistryWrite(
				ShadowPolicyModel.TerminalServicesPolicyKey,
				ShadowPolicyModel.ShadowValueName,
				desiredShadow));
		}

		// --- Always prompt for password (policy key is authoritative) ----------------------------
		// The policy key wins over the per-listener fallback. We emit a write only when the
		// effective current state (policy if set, otherwise listener) differs from the desired
		// state. The write always targets the policy key — never the listener fallback — so the
		// applied value is enforced exactly the way Group Policy would enforce it.
		bool? currentEffectivePrompt = RdpConfigurationModel.EffectivePromptForPassword(
			baseline.PromptForPasswordPolicyRaw,
			baseline.PromptForPasswordListenerRaw);
		bool currentPromptBool = currentEffectivePrompt ?? false;
		if (currentPromptBool != AlwaysPromptForPassword)
		{
			writes.Add(new RdpRegistryWrite(
				RdpConfigurationModel.TerminalServicesPolicyKey,
				RdpConfigurationModel.PromptForPasswordValueName,
				AlwaysPromptForPassword ? 1 : 0));
		}

		return new RdpConfigurationChangeSet(writes);
	}

	/// <summary>Maps a UserAuthentication + SecurityLayer pair to a high-level
	/// <see cref="RdpAuthenticationMode"/>. Unrecognised combinations are reported as
	/// <see cref="RdpAuthenticationMode.NetworkLevelAuth"/> so the UI surfaces the recommended
	/// default rather than silently writing an undefined value.</summary>
	public static RdpAuthenticationMode AuthenticationFromRaw(int? userAuthRaw, int? securityLayerRaw)
	{
		RdpUserAuthenticationMode auth = RdpConfigurationModel.AuthenticationFromRaw(userAuthRaw);
		RdpSecurityLayerMode sec = RdpConfigurationModel.SecurityLayerFromRaw(securityLayerRaw);

		if (auth == RdpUserAuthenticationMode.NlaRequired)
		{
			return RdpAuthenticationMode.NetworkLevelAuth;
		}

		if (auth == RdpUserAuthenticationMode.NlaNotRequired)
		{
			return sec == RdpSecurityLayerMode.RdpSecurity
				? RdpAuthenticationMode.RdpSecurityLayer
				: RdpAuthenticationMode.NegotiateNoNla;
		}

		return RdpAuthenticationMode.NetworkLevelAuth;
	}

	/// <summary>Returns the deterministic UserAuthentication + SecurityLayer DWORD pair the
	/// writer must persist to set the supplied high-level authentication mode.</summary>
	public static (int UserAuthentication, int SecurityLayer) AuthModeToRegistry(RdpAuthenticationMode mode) => mode switch
	{
		RdpAuthenticationMode.NetworkLevelAuth => (1, (int)RdpSecurityLayerMode.SslTls),
		RdpAuthenticationMode.NegotiateNoNla => (0, (int)RdpSecurityLayerMode.Negotiate),
		RdpAuthenticationMode.RdpSecurityLayer => (0, (int)RdpSecurityLayerMode.RdpSecurity),
		_ => (1, (int)RdpSecurityLayerMode.SslTls),
	};
}

/// <summary>Operator-facing authentication mode. Hides the underlying UserAuthentication +
/// SecurityLayer pair behind three meaningful presets so the UI does not surface invalid
/// combinations to the operator.</summary>
public enum RdpAuthenticationMode
{
	/// <summary>Network Level Authentication required (UserAuthentication=1, SecurityLayer=2). Recommended.</summary>
	NetworkLevelAuth = 0,

	/// <summary>Negotiate without NLA (UserAuthentication=0, SecurityLayer=1) — equivalent to the
	/// "Default RDP authentication" choice in RDPConf.</summary>
	NegotiateNoNla = 1,

	/// <summary>Legacy RDP Security Layer (UserAuthentication=0, SecurityLayer=0). Avoid on
	/// production hosts; exposed for compatibility with very old clients.</summary>
	RdpSecurityLayer = 2,
}
