// File:    tests/RdpAudit.Core.Tests/RdpConfigurationEditModelTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the pure edit-model behaviour that backs the editable RDP Configuration tab —
//          DTO-to-model mapping, validation (port range / enum bounds), and the deterministic
//          change-set diff that the downstream writer turns into registry mutations.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class RdpConfigurationEditModelTests
{
	[Fact]
	public void FromSnapshot_MapsKnownValuesCleanly()
	{
		RdpConfigurationDto dto = new()
		{
			RdpEnabled = true,
			ConfiguredPort = 33890,
			SingleSessionPerUserRaw = 1,
			DontDisplayLastUserNameRaw = 1,
			DontEnumerateConnectedUsersRaw = 1,
			UserAuthenticationRaw = 1,
			SecurityLayerRaw = 2,
			ShadowModeRaw = 1,
		};

		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(dto);

		Assert.True(model.RdpEnabled);
		Assert.Equal(33890, model.Port);
		Assert.True(model.SingleSessionPerUser);
		Assert.True(model.HideUsersOnLogon);
		Assert.Equal(RdpAuthenticationMode.NetworkLevelAuth, model.AuthenticationMode);
		Assert.Equal(ShadowPolicyMode.FullControlWithConsent, model.ShadowMode);
	}

	[Fact]
	public void FromSnapshot_FallsBackToDefaults_WhenValuesMissing()
	{
		RdpConfigurationDto dto = new()
		{
			RdpEnabled = null,
			ConfiguredPort = null,
			SingleSessionPerUserRaw = null,
			DontDisplayLastUserNameRaw = null,
			DontEnumerateConnectedUsersRaw = null,
			UserAuthenticationRaw = -1,
			SecurityLayerRaw = -1,
			ShadowModeRaw = -1,
		};

		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(dto);

		Assert.False(model.RdpEnabled);
		Assert.Equal(RdpConfigurationModel.DefaultRdpPort, model.Port);
		Assert.False(model.SingleSessionPerUser);
		Assert.False(model.HideUsersOnLogon);
		Assert.Equal(RdpAuthenticationMode.NetworkLevelAuth, model.AuthenticationMode);
		Assert.Equal(ShadowPolicyMode.NotConfigured, model.ShadowMode);
	}

	[Fact]
	public void FromSnapshot_HideUsers_TrueWhenEitherFlagSet()
	{
		RdpConfigurationDto dtoA = new()
		{
			DontDisplayLastUserNameRaw = 1,
			DontEnumerateConnectedUsersRaw = 0,
		};
		RdpConfigurationDto dtoB = new()
		{
			DontDisplayLastUserNameRaw = 0,
			DontEnumerateConnectedUsersRaw = 1,
		};

		Assert.True(RdpConfigurationEditModel.FromSnapshot(dtoA).HideUsersOnLogon);
		Assert.True(RdpConfigurationEditModel.FromSnapshot(dtoB).HideUsersOnLogon);
	}

	[Theory]
	[InlineData(1, true)]
	[InlineData(3389, true)]
	[InlineData(65535, true)]
	[InlineData(0, false)]
	[InlineData(65536, false)]
	[InlineData(-1, false)]
	public void Validate_RejectsOutOfRangePort(int port, bool expectValid)
	{
		RdpConfigurationEditModel model = new() { Port = port };
		RdpConfigurationValidationResult result = model.Validate();
		Assert.Equal(expectValid, result.IsValid);
	}

	[Fact]
	public void Validate_RejectsUndefinedShadowEnumValue()
	{
		RdpConfigurationEditModel model = new() { ShadowMode = (ShadowPolicyMode)17 };
		RdpConfigurationValidationResult result = model.Validate();
		Assert.False(result.IsValid);
		Assert.Contains(result.Errors, e => e.Contains("Session shadowing", System.StringComparison.Ordinal));
	}

	[Fact]
	public void Validate_RejectsUndefinedAuthEnumValue()
	{
		RdpConfigurationEditModel model = new() { AuthenticationMode = (RdpAuthenticationMode)42 };
		Assert.False(model.Validate().IsValid);
	}

	[Fact]
	public void AuthModeToRegistry_NlaUsesUserAuth1_AndSslTls()
	{
		(int auth, int sec) = RdpConfigurationEditModel.AuthModeToRegistry(RdpAuthenticationMode.NetworkLevelAuth);
		Assert.Equal(1, auth);
		Assert.Equal((int)RdpSecurityLayerMode.SslTls, sec);
	}

	[Fact]
	public void AuthModeToRegistry_NegotiateUsesUserAuth0_AndNegotiate()
	{
		(int auth, int sec) = RdpConfigurationEditModel.AuthModeToRegistry(RdpAuthenticationMode.NegotiateNoNla);
		Assert.Equal(0, auth);
		Assert.Equal((int)RdpSecurityLayerMode.Negotiate, sec);
	}

	[Fact]
	public void AuthModeToRegistry_LegacyRdpUsesUserAuth0_AndRdpSecurity()
	{
		(int auth, int sec) = RdpConfigurationEditModel.AuthModeToRegistry(RdpAuthenticationMode.RdpSecurityLayer);
		Assert.Equal(0, auth);
		Assert.Equal((int)RdpSecurityLayerMode.RdpSecurity, sec);
	}

	[Fact]
	public void ComputeChanges_ReturnsEmptyWhenNothingChanged()
	{
		RdpConfigurationDto dto = new()
		{
			RdpEnabled = true,
			ConfiguredPort = 3389,
			SingleSessionPerUserRaw = 1,
			DontDisplayLastUserNameRaw = 1,
			DontEnumerateConnectedUsersRaw = 1,
			UserAuthenticationRaw = 1,
			SecurityLayerRaw = 2,
			ShadowModeRaw = -1,
		};
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(dto);

		RdpConfigurationChangeSet changes = model.ComputeChanges(dto);
		Assert.False(changes.HasChanges);
		Assert.Empty(changes.Writes);
	}

	[Fact]
	public void ComputeChanges_EmitsPortWrite_WhenPortChanges()
	{
		RdpConfigurationDto baseline = new() { ConfiguredPort = 3389, RdpEnabled = true };
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(baseline);
		model.Port = 40000;

		RdpConfigurationChangeSet changes = model.ComputeChanges(baseline);
		Assert.Contains(changes.Writes, w =>
			w.KeyPath == RdpConfigurationModel.RdpTcpListenerKey
			&& w.ValueName == RdpConfigurationModel.PortNumberValueName
			&& w.Value == 40000);
	}

	[Fact]
	public void ComputeChanges_EmitsBothHideUserValues_AsAtomicPair()
	{
		RdpConfigurationDto baseline = new()
		{
			DontDisplayLastUserNameRaw = 0,
			DontEnumerateConnectedUsersRaw = 0,
		};
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(baseline);
		model.HideUsersOnLogon = true;

		RdpConfigurationChangeSet changes = model.ComputeChanges(baseline);
		Assert.Contains(changes.Writes, w =>
			w.KeyPath == RdpConfigurationModel.SystemPolicyKey
			&& w.ValueName == RdpConfigurationModel.DontDisplayLastUserNameValueName
			&& w.Value == 1);
		Assert.Contains(changes.Writes, w =>
			w.KeyPath == RdpConfigurationModel.SystemPolicyKey
			&& w.ValueName == RdpConfigurationModel.DontEnumerateConnectedUsersValueName
			&& w.Value == 1);
	}

	[Fact]
	public void ComputeChanges_EmitsBothAuthValues_AsAtomicPair()
	{
		RdpConfigurationDto baseline = new()
		{
			UserAuthenticationRaw = 0,
			SecurityLayerRaw = 1,
		};
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(baseline);
		model.AuthenticationMode = RdpAuthenticationMode.NetworkLevelAuth;

		RdpConfigurationChangeSet changes = model.ComputeChanges(baseline);
		Assert.Contains(changes.Writes, w =>
			w.KeyPath == RdpConfigurationModel.RdpTcpListenerKey
			&& w.ValueName == RdpConfigurationModel.UserAuthenticationValueName
			&& w.Value == 1);
		Assert.Contains(changes.Writes, w =>
			w.KeyPath == RdpConfigurationModel.RdpTcpListenerKey
			&& w.ValueName == RdpConfigurationModel.SecurityLayerValueName
			&& w.Value == (int)RdpSecurityLayerMode.SslTls);
	}

	[Fact]
	public void ComputeChanges_DenyTSConnectionsInverseOfEnabled()
	{
		RdpConfigurationDto baseline = new() { RdpEnabled = true };
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(baseline);
		model.RdpEnabled = false;

		RdpConfigurationChangeSet changes = model.ComputeChanges(baseline);
		Assert.Contains(changes.Writes, w =>
			w.KeyPath == RdpConfigurationModel.TerminalServerKey
			&& w.ValueName == RdpConfigurationModel.DenyTsConnectionsValueName
			&& w.Value == 1);
	}

	[Fact]
	public void ComputeChanges_RemovesShadowValue_WhenSwitchedToNotConfigured()
	{
		RdpConfigurationDto baseline = new() { ShadowModeRaw = 2 };
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(baseline);
		model.ShadowMode = ShadowPolicyMode.NotConfigured;

		RdpConfigurationChangeSet changes = model.ComputeChanges(baseline);
		Assert.Contains(changes.Writes, w =>
			w.KeyPath == ShadowPolicyModel.TerminalServicesPolicyKey
			&& w.ValueName == ShadowPolicyModel.ShadowValueName
			&& w.Value is null);
	}

	[Fact]
	public void FromSnapshot_AlwaysPromptForPassword_PolicyWinsOverListener()
	{
		RdpConfigurationDto dto = new()
		{
			PromptForPasswordPolicyRaw = 1,
			PromptForPasswordListenerRaw = 0,
		};

		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(dto);
		Assert.True(model.AlwaysPromptForPassword);
	}

	[Fact]
	public void FromSnapshot_AlwaysPromptForPassword_FallsBackToListenerWhenPolicyAbsent()
	{
		RdpConfigurationDto dto = new()
		{
			PromptForPasswordPolicyRaw = null,
			PromptForPasswordListenerRaw = 1,
		};

		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(dto);
		Assert.True(model.AlwaysPromptForPassword);
	}

	[Fact]
	public void FromSnapshot_AlwaysPromptForPassword_DefaultsFalseWhenBothAbsent()
	{
		RdpConfigurationDto dto = new()
		{
			PromptForPasswordPolicyRaw = null,
			PromptForPasswordListenerRaw = null,
		};

		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(dto);
		Assert.False(model.AlwaysPromptForPassword);
	}

	[Fact]
	public void ComputeChanges_EmitsPolicyWrite_WhenAlwaysPromptToggledOn()
	{
		RdpConfigurationDto baseline = new()
		{
			PromptForPasswordPolicyRaw = null,
			PromptForPasswordListenerRaw = null,
		};
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(baseline);
		model.AlwaysPromptForPassword = true;

		RdpConfigurationChangeSet changes = model.ComputeChanges(baseline);
		Assert.Contains(changes.Writes, w =>
			w.KeyPath == RdpConfigurationModel.TerminalServicesPolicyKey
			&& w.ValueName == RdpConfigurationModel.PromptForPasswordValueName
			&& w.Value == 1);
	}

	[Fact]
	public void ComputeChanges_EmitsPolicyWriteZero_WhenAlwaysPromptToggledOff()
	{
		RdpConfigurationDto baseline = new()
		{
			PromptForPasswordPolicyRaw = 1,
			PromptForPasswordListenerRaw = 1,
		};
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(baseline);
		Assert.True(model.AlwaysPromptForPassword);
		model.AlwaysPromptForPassword = false;

		RdpConfigurationChangeSet changes = model.ComputeChanges(baseline);
		Assert.Contains(changes.Writes, w =>
			w.KeyPath == RdpConfigurationModel.TerminalServicesPolicyKey
			&& w.ValueName == RdpConfigurationModel.PromptForPasswordValueName
			&& w.Value == 0);
	}

	[Fact]
	public void ComputeChanges_AlwaysPromptForPassword_NoWrite_WhenEffectiveStateMatches()
	{
		RdpConfigurationDto baseline = new()
		{
			PromptForPasswordPolicyRaw = 1,
			PromptForPasswordListenerRaw = 0,
		};
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(baseline);
		Assert.True(model.AlwaysPromptForPassword);

		RdpConfigurationChangeSet changes = model.ComputeChanges(baseline);
		Assert.DoesNotContain(changes.Writes, w =>
			w.ValueName == RdpConfigurationModel.PromptForPasswordValueName);
	}

	[Fact]
	public void ComputeChanges_AlwaysPromptForPassword_WritesPolicyKey_NotListener()
	{
		RdpConfigurationDto baseline = new()
		{
			PromptForPasswordPolicyRaw = null,
			PromptForPasswordListenerRaw = null,
		};
		RdpConfigurationEditModel model = RdpConfigurationEditModel.FromSnapshot(baseline);
		model.AlwaysPromptForPassword = true;

		RdpConfigurationChangeSet changes = model.ComputeChanges(baseline);

		// Should target the Terminal Services group policy key, NOT the per-listener RDP-Tcp key.
		Assert.Contains(changes.Writes, w =>
			w.ValueName == RdpConfigurationModel.PromptForPasswordValueName
			&& w.KeyPath == RdpConfigurationModel.TerminalServicesPolicyKey);
		Assert.DoesNotContain(changes.Writes, w =>
			w.ValueName == RdpConfigurationModel.PromptForPasswordValueName
			&& w.KeyPath == RdpConfigurationModel.RdpTcpListenerKey);
	}
}
