// File:    tests/RdpAudit.Core.Tests/ServiceQueryParserTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies the textual output parser used by the Configurator's Service tab
//          to extract the running service's STATE (name + numeric code) and PID from
//          "sc.exe queryex". The parser must tolerate locale-specific whitespace and
//          gracefully report "not installed" when sc.exe prints error 1060.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit tests for <see cref="ServiceQueryParser"/>.</summary>
public class ServiceQueryParserTests
{
	private const string RunningOutput =
		"\r\nSERVICE_NAME: RdpAuditService\r\n"
		+ "        TYPE               : 10  WIN32_OWN_PROCESS\r\n"
		+ "        STATE              : 4  RUNNING\r\n"
		+ "                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\r\n"
		+ "        WIN32_EXIT_CODE    : 0  (0x0)\r\n"
		+ "        SERVICE_EXIT_CODE  : 0  (0x0)\r\n"
		+ "        CHECKPOINT         : 0x0\r\n"
		+ "        WAIT_HINT          : 0x0\r\n"
		+ "        PID                : 1234\r\n"
		+ "        FLAGS              :\r\n";

	private const string StoppedOutput =
		"\r\nSERVICE_NAME: RdpAuditService\r\n"
		+ "        TYPE               : 10  WIN32_OWN_PROCESS\r\n"
		+ "        STATE              : 1  STOPPED\r\n"
		+ "        WIN32_EXIT_CODE    : 0  (0x0)\r\n"
		+ "        SERVICE_EXIT_CODE  : 0  (0x0)\r\n"
		+ "        CHECKPOINT         : 0x0\r\n"
		+ "        WAIT_HINT          : 0x0\r\n"
		+ "        PID                : 0\r\n"
		+ "        FLAGS              :\r\n";

	private const string NotInstalledErr =
		"[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\r\n\r\n"
		+ "The specified service does not exist as an installed service.\r\n";

	[Fact]
	public void Parse_RunningOutput_ExtractsStateAndPid()
	{
		ServiceQueryResult result = ServiceQueryParser.Parse(RunningOutput);

		Assert.True(result.Installed);
		Assert.Equal(4, result.StateCode);
		Assert.Equal("RUNNING", result.StateName);
		Assert.Equal(1234, result.ProcessId);
		Assert.True(result.IsRunning);
	}

	[Fact]
	public void Parse_StoppedOutput_ReturnsNoPid()
	{
		ServiceQueryResult result = ServiceQueryParser.Parse(StoppedOutput);

		Assert.True(result.Installed);
		Assert.Equal(1, result.StateCode);
		Assert.Equal("STOPPED", result.StateName);
		Assert.Null(result.ProcessId);
		Assert.False(result.IsRunning);
	}

	[Fact]
	public void Parse_NotInstalled_ReturnsInstalledFalse()
	{
		ServiceQueryResult result = ServiceQueryParser.Parse(stdOut: string.Empty, stdErr: NotInstalledErr);

		Assert.False(result.Installed);
		Assert.Null(result.StateCode);
		Assert.Null(result.StateName);
		Assert.Null(result.ProcessId);
		Assert.False(result.IsRunning);
	}

	[Fact]
	public void Parse_EmptyOutput_TreatedAsNotInstalled()
	{
		ServiceQueryResult result = ServiceQueryParser.Parse(stdOut: string.Empty, stdErr: string.Empty);

		Assert.False(result.Installed);
		Assert.Null(result.ProcessId);
	}

	[Fact]
	public void Parse_PidZero_IsTreatedAsNotRunning()
	{
		const string output =
			"SERVICE_NAME: Svc\r\n"
			+ "        STATE              : 1  STOPPED\r\n"
			+ "        PID                : 0\r\n";

		ServiceQueryResult result = ServiceQueryParser.Parse(output);

		Assert.True(result.Installed);
		Assert.Null(result.ProcessId);
		Assert.False(result.IsRunning);
	}

	[Fact]
	public void Parse_PendingStateCodes_ReportedAsNumeric()
	{
		const string output =
			"SERVICE_NAME: Svc\r\n"
			+ "        STATE              : 2  START_PENDING\r\n"
			+ "        PID                : 7777\r\n";

		ServiceQueryResult result = ServiceQueryParser.Parse(output);

		Assert.True(result.Installed);
		Assert.Equal(2, result.StateCode);
		Assert.Equal("START_PENDING", result.StateName);
		Assert.Equal(7777, result.ProcessId);
		Assert.False(result.IsRunning);
	}

	[Fact]
	public void Parse_IsRunning_UsesStateCodeWhenNameMissing()
	{
		// Defensive: if sc.exe ever omits the textual name, the numeric STATE 4 still wins.
		const string output =
			"SERVICE_NAME: Svc\r\n"
			+ "        STATE              : 4\r\n"
			+ "        PID                : 42\r\n";

		ServiceQueryResult result = ServiceQueryParser.Parse(output);

		Assert.True(result.IsRunning);
		Assert.Equal(42, result.ProcessId);
	}

	[Fact]
	public void BuildQueryExtended_ReturnsExpectedArgs()
	{
		System.Collections.Generic.IReadOnlyList<string> args = ScCommandBuilder.BuildQueryExtended("RdpAuditService");
		Assert.Equal(new[] { "queryex", "RdpAuditService" }, args);
	}
}
