// File:    tests/RdpAudit.Core.Tests/Stage2EnumStabilityTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the ordinal values of Stage 2 enums (BlocklistSource, ActiveBlockStatus). These
//          ordinals are persisted to SQLite and must never be reused or reordered; the tests fail
//          if a future change reassigns existing values.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Validates ordinal stability for Stage 2 enums persisted to SQLite.</summary>
public class Stage2EnumStabilityTests
{
	[Fact]
	public void BlocklistSource_OrdinalsAreStable()
	{
		Assert.Equal(0, (int)BlocklistSource.Unknown);
		Assert.Equal(1, (int)BlocklistSource.Manual);
		Assert.Equal(2, (int)BlocklistSource.Auto);
		Assert.Equal(3, (int)BlocklistSource.Firewall);
		Assert.Equal(4, (int)BlocklistSource.AbuseIpDb);
		Assert.Equal(5, (int)BlocklistSource.MikroTik);
		Assert.Equal(6, (int)BlocklistSource.LiveEvents);
	}

	[Fact]
	public void ActiveBlockStatus_OrdinalsAreStable()
	{
		Assert.Equal(0, (int)ActiveBlockStatus.Pending);
		Assert.Equal(1, (int)ActiveBlockStatus.Active);
		Assert.Equal(2, (int)ActiveBlockStatus.Failed);
		Assert.Equal(3, (int)ActiveBlockStatus.Removed);
		Assert.Equal(4, (int)ActiveBlockStatus.AuditOnly);
	}
}
