/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageBenchmarkUnit.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: The units a storage benchmark metric can be quoted in. A number without its unit is not a
//          measurement, so the unit is part of the metric's identity and is carried into the report's
//          value column, its JSON and every recommendation rationale that consumes the metric.
// Depends: System.Globalization
// Extends: Add a unit here when a new metric is measured in something else; never render a bare
//          number in a report table.

namespace RdpAudit.Core.Diagnostics;

/// <summary>Units used by the storage benchmark report.</summary>
public static class StorageBenchmarkUnit
{
	/// <summary>Rows per second.</summary>
	public const string RowsPerSecond = "rows/s";

	/// <summary>Rows.</summary>
	public const string Rows = "rows";

	/// <summary>Seconds.</summary>
	public const string Seconds = "s";

	/// <summary>Milliseconds.</summary>
	public const string Milliseconds = "ms";

	/// <summary>Bytes.</summary>
	public const string Bytes = "bytes";

	/// <summary>Bytes per second.</summary>
	public const string BytesPerSecond = "bytes/s";

	/// <summary>Mebibytes per second (1 MiB = 1 048 576 bytes).</summary>
	public const string MebibytesPerSecond = "MiB/s";

	/// <summary>Chained ledger entries per second.</summary>
	public const string EntriesPerSecond = "entries/s";

	/// <summary>Flushed write operations per second.</summary>
	public const string OperationsPerSecond = "ops/s";

	/// <summary>A count of things (batches, files, pages).</summary>
	public const string Count = "count";

	/// <summary>A dimensionless ratio.</summary>
	public const string Ratio = "ratio";
}
