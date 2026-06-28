// File:    src/RdpAudit.Core/Diagnostics/OverviewProgressState.cs
// Module:  RdpAudit.Core.Diagnostics
// Purpose: Thread-safe, in-memory holder for the live state of the long-running historical
//          analysis / backfill / indexing job. A background worker publishes progress here as it
//          works through a large historical backlog; the GetOverviewProgress IPC handler reads a
//          consistent snapshot so the Configurator's Overview tab can render a progress bar without
//          blocking on a full historical scan. Kept in Core (not Service) so both the worker and the
//          IPC handler can depend on it without a project cycle.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Diagnostics;

/// <summary>An immutable snapshot of the historical-analysis job's progress.</summary>
public sealed record OverviewProgressSnapshot
{
	public bool IsRunning { get; init; }

	public string Stage { get; init; } = "Idle";

	public long ProcessedRows { get; init; }

	public long TotalRows { get; init; }

	public double Percent { get; init; }

	public DateTime? StartedUtc { get; init; }

	public DateTime LastUpdatedUtc { get; init; }

	public string? CurrentChannel { get; init; }

	public DateTime? LastEventUtc { get; init; }

	public long Errors { get; init; }

	public string? Message { get; init; }
}

/// <summary>Thread-safe holder for the live historical-analysis progress. Registered as a singleton;
/// the indexing worker mutates it and the IPC handler reads a snapshot.</summary>
public sealed class OverviewProgressState
{
	private readonly object _gate = new();
	private OverviewProgressSnapshot _current = new() { LastUpdatedUtc = DateTime.UtcNow };

	/// <summary>Returns a consistent snapshot of the current progress state.</summary>
	public OverviewProgressSnapshot Snapshot()
	{
		lock (_gate)
		{
			return _current;
		}
	}

	/// <summary>Marks a new pass as started, resetting counters.</summary>
	public void BeginPass(string stage, long totalRows, string? currentChannel = null)
	{
		DateTime now = DateTime.UtcNow;
		lock (_gate)
		{
			_current = _current with
			{
				IsRunning = true,
				Stage = stage,
				ProcessedRows = 0,
				TotalRows = totalRows < 0 ? 0 : totalRows,
				Percent = 0,
				StartedUtc = now,
				LastUpdatedUtc = now,
				CurrentChannel = currentChannel,
				Errors = 0,
				Message = null,
			};
		}
	}

	/// <summary>Updates progress within the current pass. <paramref name="processedRows"/> is the
	/// absolute count processed so far; percentage is derived from the known total.</summary>
	public void Report(long processedRows, string? stage = null, string? currentChannel = null, DateTime? lastEventUtc = null, string? message = null)
	{
		DateTime now = DateTime.UtcNow;
		lock (_gate)
		{
			long total = _current.TotalRows;
			double pct = total > 0 ? Math.Clamp(processedRows * 100.0 / total, 0, 100) : 0;
			_current = _current with
			{
				IsRunning = true,
				Stage = stage ?? _current.Stage,
				ProcessedRows = processedRows < 0 ? 0 : processedRows,
				Percent = pct,
				LastUpdatedUtc = now,
				CurrentChannel = currentChannel ?? _current.CurrentChannel,
				LastEventUtc = lastEventUtc ?? _current.LastEventUtc,
				Message = message ?? _current.Message,
			};
		}
	}

	/// <summary>Increments the non-fatal error counter for the current pass.</summary>
	public void ReportError(string? message = null)
	{
		DateTime now = DateTime.UtcNow;
		lock (_gate)
		{
			_current = _current with
			{
				Errors = _current.Errors + 1,
				LastUpdatedUtc = now,
				Message = message ?? _current.Message,
			};
		}
	}

	/// <summary>Marks the current pass complete (or idle), leaving the last counters visible.</summary>
	public void Complete(string stage = "Idle", string? message = null)
	{
		DateTime now = DateTime.UtcNow;
		lock (_gate)
		{
			_current = _current with
			{
				IsRunning = false,
				Stage = stage,
				Percent = _current.TotalRows > 0 ? 100 : _current.Percent,
				LastUpdatedUtc = now,
				CurrentChannel = null,
				Message = message ?? _current.Message,
			};
		}
	}
}
