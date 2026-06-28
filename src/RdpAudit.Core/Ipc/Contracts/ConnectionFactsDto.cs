// File:    src/RdpAudit.Core/Ipc/Contracts/ConnectionFactsDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Response shapes for ListConnectionFacts (recent + filtered list) and
//          GetConnectionFactsForIp (per-IP detail summary). Both responses carry a bounded fact
//          collection plus aggregate counters useful for the Configurator's Attack Statistics
//          augmentation and the per-IP export header. MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Response payload for <c>ListConnectionFacts</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ConnectionFactsDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC timestamp at which the snapshot was produced.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Total number of facts matching the filter, before the limit was applied.</summary>
	[Key(2)]
	public int TotalMatching { get; set; }

	/// <summary>Limit the server clamped the response to (also equals <c>Facts.Count</c>).</summary>
	[Key(3)]
	public int AppliedLimit { get; set; }

	/// <summary>Bounded facts collection, ordered LastSeenUtc descending.</summary>
	[Key(4)]
	public List<ConnectionFactDto> Facts { get; set; } = new();

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(5)]
	public string? Message { get; set; }
}

/// <summary>Response payload for <c>GetConnectionFactsForIp</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ConnectionFactsForIpDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Canonical IP literal echoed from the request.</summary>
	[Key(1)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>UTC timestamp at which the snapshot was produced.</summary>
	[Key(2)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Total facts associated with the IP across the full table, before the limit was applied.</summary>
	[Key(3)]
	public int TotalMatching { get; set; }

	/// <summary>Limit the server clamped the response to (also equals <c>Facts.Count</c>).</summary>
	[Key(4)]
	public int AppliedLimit { get; set; }

	/// <summary>Earliest <c>FirstSeenUtc</c> across the IP's facts; null when none exist.</summary>
	[Key(5)]
	public DateTime? FirstSeenUtc { get; set; }

	/// <summary>Latest <c>LastSeenUtc</c> across the IP's facts; null when none exist.</summary>
	[Key(6)]
	public DateTime? LastSeenUtc { get; set; }

	/// <summary>Sum of <c>FailedLogons</c> counters across the IP's facts.</summary>
	[Key(7)]
	public long FailedLogons { get; set; }

	/// <summary>Sum of <c>SuccessfulLogons</c> counters across the IP's facts.</summary>
	[Key(8)]
	public long SuccessfulLogons { get; set; }

	/// <summary>True when any fact for this IP is currently active.</summary>
	[Key(9)]
	public bool HasActiveFact { get; set; }

	/// <summary>Bounded facts collection ordered LastSeenUtc descending. Excludes raw XML.</summary>
	[Key(10)]
	public List<ConnectionFactDto> Facts { get; set; } = new();

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(11)]
	public string? Message { get; set; }
}
