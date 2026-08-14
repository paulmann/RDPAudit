/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : IpEventSummary.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Stores durable per-IP event totals and first/last event evidence for efficient IP investigation.
// Depends: (none)
// Extends: Add only append-only IP summary fields and mirror them in IpEventSummaryConfiguration.

namespace RdpAudit.Core.Models;

/// <summary>Durable aggregate for all events attributed to one canonical source IP.</summary>
public sealed class IpEventSummary
{
	/// <summary>Canonical 16-byte IPv6-mapped binary IP key.</summary>
	public byte[] IpBinary16 { get; set; } = [];
	/// <summary>Canonical textual IP representation.</summary>
	public string IpText { get; set; } = string.Empty;
	/// <summary>Address family: 4 for IPv4-mapped and 6 for native IPv6.</summary>
	public int AddressFamily { get; set; }
	/// <summary>UTC ticks of the first event, which is never overwritten.</summary>
	public long FirstEventUtc { get; set; }
	/// <summary>Identifier of the first event, which is never overwritten.</summary>
	public int FirstEventId { get; set; }
	/// <summary>Ingestion sequence of the first event, which is never overwritten.</summary>
	public long FirstEventSequence { get; set; }
	/// <summary>Forensic snapshot of the first event, which is never overwritten.</summary>
	public byte[] FirstEventSnapshot { get; set; } = [];
	/// <summary>UTC ticks of the latest event.</summary>
	public long LastEventUtc { get; set; }
	/// <summary>Identifier of the latest event.</summary>
	public int LastEventId { get; set; }
	/// <summary>Ingestion sequence of the latest event.</summary>
	public long LastEventSequence { get; set; }
	/// <summary>Forensic snapshot of the latest event.</summary>
	public byte[] LastEventSnapshot { get; set; } = [];
	/// <summary>Total number of observed events, including records no longer present in shards.</summary>
	public long TotalEventCount { get; set; }
	/// <summary>Number of successful authentication events.</summary>
	public long SuccessCount { get; set; }
	/// <summary>Number of failed authentication events.</summary>
	public long FailureCount { get; set; }
	// ── Shard metadata ───────────────────────────────────────────────────────────
	// Every field below is null until a shard file actually exists on disk for this
	// IP. Nothing writes them yet: ShardWriter is implemented and unit-tested but is
	// not connected to the ingestion path, so no shard is ever created. They stay
	// null rather than carrying zeros or an empty path, because an analyst reading a
	// non-null ShardRelativePath during an incident will try to open that file. Null
	// means "no shard"; a value means "a shard exists and these numbers describe it".

	/// <summary>Relative path of the IP shard, or <see langword="null"/> when no shard file exists.</summary>
	public string? ShardRelativePath { get; set; }
	/// <summary>Number of records currently retained by the shard, or <see langword="null"/> when no shard file exists.</summary>
	public long? ShardRecordCount { get; set; }
	/// <summary>Size of the shard file in bytes, or <see langword="null"/> when no shard file exists.</summary>
	public long? ShardBytes { get; set; }
	/// <summary>Binary format version of the shard, or <see langword="null"/> when no shard file exists.</summary>
	public int? ShardFormatVersion { get; set; }
	/// <summary>Number of records evicted from the shard, or <see langword="null"/> when no shard file exists.</summary>
	public long? ShardEvictedCount { get; set; }
	/// <summary>UTC ticks of the oldest record retained by the shard, or <see langword="null"/> when no shard file exists.</summary>
	public long? ShardOldestRetainedUtc { get; set; }
	/// <summary>Indicates whether a shard file backs this summary row.</summary>
	public bool HasShard => ShardRelativePath is not null;
	/// <summary>Indicates that this row represents an aggregate subnet rather than one host.</summary>
	public bool IsSubnetAggregate { get; set; }
	/// <summary>Reserved bit flags for future aggregate state.</summary>
	public int Flags { get; set; }
}
