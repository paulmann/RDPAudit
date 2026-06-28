// File:    src/RdpAudit.Core/Config/LogsOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Operation-log viewing depth and retention settings. Bounds how far back the Logs tab
//          queries by default and how long durable operation-log rows are kept, so a long-lived
//          deployment does not let the operation-log table grow without bound or make the Logs tab
//          slow to open on a large database.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Operation-log viewing depth and retention settings.</summary>
public sealed class LogsOptions
{
	/// <summary>Smallest accepted value for <see cref="ViewDepthDays"/> and
	/// <see cref="RetentionDays"/>. One day keeps the setting meaningful while still allowing an
	/// operator to aggressively bound a fast-growing table.</summary>
	public const int MinDepthDays = 1;

	/// <summary>Largest accepted value for <see cref="ViewDepthDays"/> and
	/// <see cref="RetentionDays"/>. Roughly ten years, after which "retain everything" is the more
	/// honest description and an unbounded table is the operator's explicit choice elsewhere.</summary>
	public const int MaxDepthDays = 3650;

	/// <summary>Default viewing / retention depth in days. Sixty days keeps the Logs tab responsive
	/// on a busy host and prevents the operation-log table from growing without bound, while still
	/// covering the typical "what happened over the last two months" investigation window.</summary>
	public const int DefaultDepthDays = 60;

	/// <summary>How many days of operation logs the Logs tab shows by default. Queries older than
	/// this cutoff are excluded unless the operator widens the range explicitly. Clamped to
	/// [<see cref="MinDepthDays"/>, <see cref="MaxDepthDays"/>] when consumed.</summary>
	public int ViewDepthDays { get; set; } = DefaultDepthDays;

	/// <summary>How many days of operation logs the maintenance retention pass keeps. Rows older
	/// than this cutoff are deleted in bounded batches. Defaults to the same value as
	/// <see cref="ViewDepthDays"/> so "what I can view" and "what is kept" stay aligned unless the
	/// operator intentionally diverges them. Clamped to [<see cref="MinDepthDays"/>,
	/// <see cref="MaxDepthDays"/>] when consumed.</summary>
	public int RetentionDays { get; set; } = DefaultDepthDays;

	/// <summary>Default page size for a single Logs-tab query. Bounds how many rows are serialized
	/// across IPC per request so the grid never binds the whole table.</summary>
	public int DefaultPageSize { get; set; } = 500;

	/// <summary>Hard upper bound on a single Logs-tab page, regardless of what the client requests.
	/// Keeps one IPC round-trip from serializing an unbounded slice of the table.</summary>
	public const int MaxPageSize = 1000;

	/// <summary>Returns <see cref="DefaultPageSize"/> clamped to a sane lower bound and
	/// <see cref="MaxPageSize"/>.</summary>
	public int ResolveDefaultPageSize() => ClampPageSize(DefaultPageSize);

	/// <summary>Clamps an arbitrary requested page size to [1, <see cref="MaxPageSize"/>], falling
	/// back to <see cref="DefaultPageSize"/> when the request is non-positive.</summary>
	public int ResolvePageSize(int requested)
		=> requested <= 0 ? ClampPageSize(DefaultPageSize) : ClampPageSize(requested);

	private static int ClampPageSize(int value)
	{
		if (value < 1)
		{
			return 1;
		}

		return value > MaxPageSize ? MaxPageSize : value;
	}

	/// <summary>Returns <see cref="ViewDepthDays"/> clamped to the supported range.</summary>
	public int ResolveViewDepthDays() => ClampDepth(ViewDepthDays);

	/// <summary>Returns <see cref="RetentionDays"/> clamped to the supported range.</summary>
	public int ResolveRetentionDays() => ClampDepth(RetentionDays);

	/// <summary>Returns true when <paramref name="value"/> is a valid depth (inclusive bounds).</summary>
	public static bool IsValidDepth(int value) => value is >= MinDepthDays and <= MaxDepthDays;

	private static int ClampDepth(int value)
	{
		if (value < MinDepthDays)
		{
			return MinDepthDays;
		}

		return value > MaxDepthDays ? MaxDepthDays : value;
	}
}
