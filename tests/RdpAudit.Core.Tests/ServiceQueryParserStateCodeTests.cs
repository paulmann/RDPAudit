// File:    tests/RdpAudit.Core.Tests/ServiceQueryParserStateCodeTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 4 — locks the locale-stable numeric state-code path used by the
//          Service tab to decide whether the Windows service is running. Localized
//          versions of "sc.exe queryex" rewrite the textual STATE token ("RUNNING"
//          becomes "РАБОТАЕТ" on Russian Windows, "EN COURS D'EXÉCUTION" on French
//          Windows, an ideographic phrase on Chinese Windows). The numeric code on
//          the same STATE line stays at 4 (SERVICE_RUNNING) regardless. These tests
//          assert that ServiceQueryParser extracts the numeric STATE code for each
//          of those locales and that ServiceQueryResult.IsRunning fires off the
//          numeric code rather than the textual name.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ServiceQueryParserStateCodeTests
{
	// Localized samples below mimic the shape the user reports on each locale. The numeric
	// STATE code never changes — it is the locale-independent signal the Configurator must
	// use to decide Start vs Stop button enablement.
	private const string RussianRunning =
		"\r\nSERVICE_NAME: RdpAuditService\r\n"
		+ "        TYPE               : 10  WIN32_OWN_PROCESS\r\n"
		+ "        STATE              : 4  РАБОТАЕТ\r\n"
		+ "                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\r\n"
		+ "        WIN32_EXIT_CODE    : 0  (0x0)\r\n"
		+ "        SERVICE_EXIT_CODE  : 0  (0x0)\r\n"
		+ "        CHECKPOINT         : 0x0\r\n"
		+ "        WAIT_HINT          : 0x0\r\n"
		+ "        PID                : 4321\r\n"
		+ "        FLAGS              :\r\n";

	private const string FrenchRunning =
		"\r\nSERVICE_NAME: RdpAuditService\r\n"
		+ "        TYPE               : 10  WIN32_OWN_PROCESS\r\n"
		+ "        STATE              : 4  EN_COURS_D_EXECUTION\r\n"
		+ "        WIN32_EXIT_CODE    : 0  (0x0)\r\n"
		+ "        PID                : 1010\r\n";

	private const string ChineseRunning =
		"\r\nSERVICE_NAME: RdpAuditService\r\n"
		+ "        STATE              : 4  RUNNING_LOCALIZED\r\n"
		+ "        PID                : 5555\r\n";

	private const string RussianStopped =
		"\r\nSERVICE_NAME: RdpAuditService\r\n"
		+ "        STATE              : 1  ОСТАНОВЛЕНА\r\n"
		+ "        PID                : 0\r\n";

	[Fact]
	public void Parse_RussianRunningSample_ReportsNumericCodeAndIsRunning()
	{
		ServiceQueryResult result = ServiceQueryParser.Parse(RussianRunning);

		Assert.True(result.Installed);
		Assert.Equal(ServiceStateCode.Running, result.StateCode);
		Assert.Equal(4321, result.ProcessId);
		Assert.True(result.IsRunning);
	}

	[Fact]
	public void Parse_FrenchRunningSample_ReportsNumericCodeAndIsRunning()
	{
		ServiceQueryResult result = ServiceQueryParser.Parse(FrenchRunning);

		Assert.True(result.Installed);
		Assert.Equal(ServiceStateCode.Running, result.StateCode);
		Assert.True(result.IsRunning);
	}

	[Fact]
	public void Parse_ChineseRunningSample_ReportsNumericCodeAndIsRunning()
	{
		ServiceQueryResult result = ServiceQueryParser.Parse(ChineseRunning);

		Assert.True(result.Installed);
		Assert.Equal(ServiceStateCode.Running, result.StateCode);
		Assert.True(result.IsRunning);
	}

	[Fact]
	public void Parse_RussianStoppedSample_NumericCodeIsStopped()
	{
		ServiceQueryResult result = ServiceQueryParser.Parse(RussianStopped);

		Assert.True(result.Installed);
		Assert.Equal(ServiceStateCode.Stopped, result.StateCode);
		Assert.Null(result.ProcessId);
		Assert.False(result.IsRunning);
	}

	[Fact]
	public void StateCodeConstants_AreLocaleStable()
	{
		// Defensive: pin the well-known Windows SCM dwCurrentState values so a refactor of
		// ServiceStateCode cannot silently change the running detection used by the UI.
		Assert.Equal(1, ServiceStateCode.Stopped);
		Assert.Equal(2, ServiceStateCode.StartPending);
		Assert.Equal(3, ServiceStateCode.StopPending);
		Assert.Equal(4, ServiceStateCode.Running);
		Assert.Equal(5, ServiceStateCode.ContinuePending);
		Assert.Equal(6, ServiceStateCode.PausePending);
		Assert.Equal(7, ServiceStateCode.Paused);
	}
}
