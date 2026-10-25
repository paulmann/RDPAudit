// File:    tests/RdpAudit.Core.Tests/SessionConsoleCommandFactoryTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the parse-stable English console spawn factory. The factory must emit
//          the exact "cmd.exe /d /c \"chcp 437 >nul & tool\"" shape for every trusted tool —
//          this is the technique that pins the active code page so qwinsta and quser produce
//          English STATE tokens regardless of UI culture. The arguments string is composed
//          entirely from constants in the factory, so shell injection from operator input
//          is impossible by construction.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class SessionConsoleCommandFactoryTests
{
	[Fact]
	public void Build_Qwinsta_EmitsExpectedShape()
	{
		SessionConsoleSpawn spawn = SessionConsoleCommandFactory.Build(TrustedSessionTool.Qwinsta);

		Assert.Equal(437, spawn.CodePage);
		Assert.Contains("cmd.exe", spawn.Executable, System.StringComparison.OrdinalIgnoreCase);
		Assert.Equal("/d /c \"chcp 437 >nul & qwinsta.exe\"", spawn.Arguments);
	}

	[Fact]
	public void Build_Quser_EmitsExpectedShape()
	{
		SessionConsoleSpawn spawn = SessionConsoleCommandFactory.Build(TrustedSessionTool.Quser);

		Assert.Equal(437, spawn.CodePage);
		Assert.Equal("/d /c \"chcp 437 >nul & quser.exe\"", spawn.Arguments);
	}

	[Fact]
	public void Build_UnknownTool_Throws()
	{
		Assert.Throws<System.ArgumentOutOfRangeException>(
			() => SessionConsoleCommandFactory.Build((TrustedSessionTool)999));
	}

	[Fact]
	public void Arguments_HaveNoOperatorInjectionSurface()
	{
		// Both spawns must consist only of the documented constants; there is no parameter
		// path through which operator input could be appended.
		SessionConsoleSpawn qw = SessionConsoleCommandFactory.Build(TrustedSessionTool.Qwinsta);
		SessionConsoleSpawn qu = SessionConsoleCommandFactory.Build(TrustedSessionTool.Quser);

		Assert.StartsWith("/d /c \"chcp 437 >nul & ", qw.Arguments, System.StringComparison.Ordinal);
		Assert.EndsWith(".exe\"", qw.Arguments, System.StringComparison.Ordinal);
		Assert.StartsWith("/d /c \"chcp 437 >nul & ", qu.Arguments, System.StringComparison.Ordinal);
		Assert.EndsWith(".exe\"", qu.Arguments, System.StringComparison.Ordinal);
	}
}
