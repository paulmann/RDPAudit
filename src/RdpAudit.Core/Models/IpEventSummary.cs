/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3
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
	// Every field below remains null until ShardIngestionSink observes a real shard file.
	// It is the sole writer and takes values only from a shard header or actual file length.
	// An analyst can therefore rely on a non-null ShardRelativePath as a confirmed artifact;
	// null means no shard is confirmed or the corresponding fact is unknown.

	/// <summary>Relative path of the IP shard, or <see langword="null"/> when no shard file exists.</summary>
	public string? ShardRelativePath { get; set; }
	/// <summary>Number of records currently retained by the shard, or <see langword="null"/> when no shard file exists.</summary>
	public long? ShardRecordCount { get; set; }
	/// <summary>
	/// On-disk length of the shard file in bytes, or <see langword="null"/> when no shard file exists.
	/// A shard is pre-allocated to its full ring capacity, so this is the space the file occupies, not
	/// the volume of retained evidence. Use <see cref="ShardRecordCount"/> for the number of records.
	/// </summary>
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
