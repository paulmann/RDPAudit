/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardingOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Configures optional durable per-IP forensic shard files.
// Depends: System.Environment, ShardPath
// Extends: Add cardinality-protection settings when subnet aggregation is implemented.

using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Config;

/// <summary>Settings for optional per-IP forensic shard storage.</summary>
public sealed class ShardingOptions
{
	/// <summary>
	/// Gets or sets whether shard writing is enabled. Defaults to false deliberately: until a
	/// cardinality guard aggregates distributed source addresses, enabling it is safe only for
	/// environments with a bounded, trusted source-IP population and adequate disk monitoring.
	/// </summary>
	public bool Enabled { get; set; }

	/// <summary>Configured absolute actions root, or empty to use ProgramData.</summary>
	public string ActionsRoot { get; set; } = string.Empty;

	/// <summary>Maximum number of fixed-size records retained by one shard ring.</summary>
	public int ShardCapacityRecords { get; set; } = 1024;

	/// <summary>Maximum number of cached open shard writers after a batch commit.</summary>
	public int MaxOpenWriters { get; set; } = 128;

	/// <summary>Maximum number of shard files that may be created by this service instance.</summary>
	public int MaxShardFiles { get; set; } = 4096;

	/// <summary>Returns the configured actions root or the default ProgramData location.</summary>
	public string ResolveActionsRoot()
	{
		if (!string.IsNullOrWhiteSpace(ActionsRoot))
		{
			return ActionsRoot;
		}

		return RdpAuditPaths.Default.ActionsRootDirectory;
	}
}
