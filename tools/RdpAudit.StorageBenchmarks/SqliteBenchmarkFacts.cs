/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : SqliteBenchmarkFacts.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: The small set of raw SQLite reads a storage benchmark needs and the timing helper every
//          probe uses. Pooling is off on purpose: this tool opens a handful of connections, renames and
//          copies database files, and a pooled connection would keep a handle on a file the probe is
//          about to move. Freelist accounting is exposed separately from file length because deleting
//          rows in SQLite does not shrink the file - it returns pages to the freelist - and a report that
//          conflated the two would claim a reclaim that did not happen.
// Depends: Microsoft.Data.Sqlite
// Extends: Add a read here when a probe needs one; never inline a PRAGMA in a probe that another probe
//          might need to read identically.

using System.Diagnostics;
using Microsoft.Data.Sqlite;

namespace RdpAudit.StorageBenchmarks;

/// <summary>Raw SQLite reads and timing helpers shared by the probes.</summary>
internal static class SqliteBenchmarkFacts
{
	/// <summary>Opens a NON-POOLED connection to a database file. Non-pooled so a probe that renames,
	/// copies or deletes the file afterwards cannot be defeated by a lingering handle.</summary>
	public static SqliteConnection Open(string databasePath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
		SqliteConnectionStringBuilder builder = new() { DataSource = databasePath, Pooling = false };
		SqliteConnection connection = new(builder.ToString());
		connection.Open();
		return connection;
	}

	/// <summary>Reads the first column of the first row as a <see cref="long"/>.</summary>
	public static long ReadLong(SqliteConnection connection, string sql)
	{
		ArgumentNullException.ThrowIfNull(connection);
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = sql;
		object? value = command.ExecuteScalar();
		return value is long number ? number : Convert.ToInt64(value ?? 0L, System.Globalization.CultureInfo.InvariantCulture);
	}

	/// <summary>Reads the first column of the first row as text, or the empty string when there is no row.</summary>
	public static string ReadText(SqliteConnection connection, string sql)
	{
		ArgumentNullException.ThrowIfNull(connection);
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = sql;
		return Convert.ToString(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
	}

	/// <summary>Length of the main database file; zero when it does not exist.</summary>
	public static long DatabaseFileBytes(string databasePath)
	{
		FileInfo info = new(databasePath);
		return info.Exists ? info.Length : 0L;
	}

	/// <summary>Combined length of the database file, its write-ahead log and its shared-memory file.</summary>
	public static long FamilyBytes(string databasePath)
		=> DatabaseFileBytes(databasePath)
			+ DatabaseFileBytes(databasePath + "-wal")
			+ DatabaseFileBytes(databasePath + "-shm");

	/// <summary>Bytes currently sitting on the freelist: <c>freelist_count * page_size</c>.</summary>
	public static long FreelistBytes(SqliteConnection connection)
	{
		ArgumentNullException.ThrowIfNull(connection);
		long pageSize = ReadLong(connection, "PRAGMA page_size;");
		long freelistCount = ReadLong(connection, "PRAGMA freelist_count;");
		return pageSize * freelistCount;
	}

	/// <summary>
	/// Releases every pooled SQLite connection so the file handles on the benchmark stores are closed.
	/// This is not optional hygiene: the store handles are opened through EF, which pools connections, and
	/// a pooled connection keeps a Win32 handle on the database file after its context is disposed. Without
	/// this call a probe cannot delete the copy it just measured, and the run leaves hundreds of megabytes
	/// of copies behind on the volume it is supposed to be characterising.
	/// </summary>
	public static void ClearPools() => SqliteConnection.ClearAllPools();

	/// <summary>Runs an action and returns its elapsed milliseconds.</summary>
	public static double Timed(Action action)
	{
		ArgumentNullException.ThrowIfNull(action);
		Stopwatch watch = Stopwatch.StartNew();
		action();
		watch.Stop();
		return watch.Elapsed.TotalMilliseconds;
	}

	/// <summary>Runs an asynchronous action and returns its elapsed milliseconds.</summary>
	public static async Task<double> TimedAsync(Func<Task> action)
	{
		ArgumentNullException.ThrowIfNull(action);
		Stopwatch watch = Stopwatch.StartNew();
		await action().ConfigureAwait(false);
		watch.Stop();
		return watch.Elapsed.TotalMilliseconds;
	}

	/// <summary>Runs an asynchronous function and returns its result together with the elapsed milliseconds.</summary>
	public static async Task<(TResult Result, double ElapsedMs)> TimedAsync<TResult>(Func<Task<TResult>> action)
	{
		ArgumentNullException.ThrowIfNull(action);
		Stopwatch watch = Stopwatch.StartNew();
		TResult result = await action().ConfigureAwait(false);
		watch.Stop();
		return (result, watch.Elapsed.TotalMilliseconds);
	}

	/// <summary>Converts milliseconds to seconds.</summary>
	public static double ToSeconds(double milliseconds) => milliseconds / 1000d;

	/// <summary>Converts bytes and a duration in milliseconds into mebibytes per second; zero when the
	/// duration is not positive.</summary>
	public static double MebibytesPerSecond(long bytes, double milliseconds)
		=> milliseconds > 0d ? bytes / 1048576d / (milliseconds / 1000d) : 0d;
}
