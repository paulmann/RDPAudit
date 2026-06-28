// File:    src/RdpAudit.Core/Util/ShadowPolicyModel.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure, UI- and OS-agnostic model of the Windows Terminal Services Shadow
//          policy. Encapsulates registry-key/value identity, the Microsoft Shadow
//          value mapping (0..4) and the canonical "enable all permissions" preset.
//          Free of any Windows-specific APIs so it can be unit-tested on Linux.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Microsoft <c>Shadow</c> registry value semantics.</summary>
/// <remarks>
/// 0 = no shadow,
/// 1 = full control with user permission,
/// 2 = full control without user permission,
/// 3 = view session with user permission,
/// 4 = view session without user permission.
/// </remarks>
public enum ShadowPolicyMode
{
	NotConfigured = -1,
	NoShadow = 0,
	FullControlWithConsent = 1,
	FullControlNoConsent = 2,
	ViewWithConsent = 3,
	ViewNoConsent = 4,
}

/// <summary>One registry value tracked by the shadow policy backend.</summary>
public sealed record ShadowPolicyValue(
	string KeyPath,
	string ValueName,
	int? CurrentValue,
	int? DesiredValue,
	string Description);

/// <summary>Pure helpers describing the canonical Windows shadow policy surface.</summary>
public static class ShadowPolicyModel
{
	/// <summary>HKLM-rooted policy key for Terminal Services group policy.</summary>
	public const string TerminalServicesPolicyKey =
		@"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";

	/// <summary>HKLM-rooted machine key for Terminal Services config (per-machine).</summary>
	public const string TerminalServicesMachineKey =
		@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";

	/// <summary>Name of the Microsoft "Shadow" value under both keys.</summary>
	public const string ShadowValueName = "Shadow";

	/// <summary>Name of the "fAllowToGetHelp" value (legacy flag, kept for completeness).</summary>
	public const string AllowToGetHelpValueName = "fAllowToGetHelp";

	/// <summary>Returns the canonical list of registry keys captured by backup / restore for
	/// shadow policy management. These mirror what the Stage 7 backup runner exports.</summary>
	public static IReadOnlyList<string> BackupRegistryKeys { get; } = new[]
	{
		TerminalServicesPolicyKey,
		TerminalServicesMachineKey,
	};

	/// <summary>The "enable all permissions" preset — full control with no consent prompt under
	/// the group-policy key. This is the most permissive supported setting and the one the UI
	/// applies when the operator clicks "Enable all permissions".</summary>
	public const int EnableAllPermissionsValue = (int)ShadowPolicyMode.FullControlNoConsent;

	/// <summary>True when a raw registry integer represents a valid <c>Shadow</c> policy value.</summary>
	public static bool IsValidShadowValue(int value) => value is >= 0 and <= 4;

	/// <summary>Maps a raw integer or null to the equivalent <see cref="ShadowPolicyMode"/>.</summary>
	public static ShadowPolicyMode FromRawValue(int? raw)
	{
		if (!raw.HasValue || !IsValidShadowValue(raw.Value))
		{
			return ShadowPolicyMode.NotConfigured;
		}

		return (ShadowPolicyMode)raw.Value;
	}

	/// <summary>Human-readable description for a shadow policy mode — used by the Configurator UI.</summary>
	public static string Describe(ShadowPolicyMode mode) => mode switch
	{
		ShadowPolicyMode.NoShadow => "No shadow allowed",
		ShadowPolicyMode.FullControlWithConsent => "Full control — user consent required",
		ShadowPolicyMode.FullControlNoConsent => "Full control — no user consent prompt",
		ShadowPolicyMode.ViewWithConsent => "View only — user consent required",
		ShadowPolicyMode.ViewNoConsent => "View only — no user consent prompt",
		_ => "Not configured (defaults to Windows default behaviour)",
	};

	/// <summary>Returns true when the configured shadow value permits the requested
	/// <see cref="SessionCommandBuilder.ShadowMode"/> without requiring user consent.</summary>
	public static bool AllowsMode(ShadowPolicyMode policy, SessionCommandBuilder.ShadowMode requested) => requested switch
	{
		SessionCommandBuilder.ShadowMode.ViewOnly => policy is
			ShadowPolicyMode.ViewWithConsent
			or ShadowPolicyMode.ViewNoConsent
			or ShadowPolicyMode.FullControlWithConsent
			or ShadowPolicyMode.FullControlNoConsent,
		SessionCommandBuilder.ShadowMode.Control => policy is
			ShadowPolicyMode.FullControlWithConsent
			or ShadowPolicyMode.FullControlNoConsent,
		SessionCommandBuilder.ShadowMode.ControlNoConsent => policy == ShadowPolicyMode.FullControlNoConsent,
		_ => false,
	};
}
