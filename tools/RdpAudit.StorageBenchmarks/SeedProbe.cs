/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : SeedProbe.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: Fills a fresh store with synthetic raw events and times the fill. This is the only probe
//          whose input is not a product service: it reproduces the schema through the product's own EF
//          migrations, then bulk-loads rows it generated. It is therefore reported for what it is - a
//          BULK LOAD through one transaction, not the service's per-event ingestion path - and the report
//          says so, because the two numbers answer different questions.
//          The seed deliberately leaves the store in the state a maintained production store is in:
//          the write-ahead log is checkpointed into the main file and ANALYZE has run, so the planner
//          that the retention statistics query exercises has statistics to work from.
// Depends: BenchmarkStore, SqliteBenchmarkFacts, RdpAudit.Core.Diagnostics
// Extends: Add a seeded column by extending the INSERT here and the generator above it; keep the row
//          shape identical to the product's RawEvent columns.

using System.Globalization;
using System.Net;
using Microsoft.Data.Sqlite;
using RdpAudit.Core.Diagnostics;

namespace RdpAudit.StorageBenchmarks;

/// <summary>What one seed produced.</summary>
internal sealed record SeedOutcome
{
	/// <summary>Measurements the seed contributed.</summary>
	public required List<BenchmarkMeasurement> Measurements { get; init; }

	/// <summary>Rows actually written.</summary>
	public required int RowsWritten { get; init; }

	/// <summary>Distinct codes the rows were spread over.</summary>
	public required int CodesUsed { get; init; }

	/// <summary>Length of the main database file after the seed.</summary>
	public required long DatabaseBytes { get; init; }

	/// <summary>The failure that stopped the seed, or null.</summary>
	public string? Error { get; init; }
}

/// <summary>Creates and fills the synthetic store.</summary>
internal static class SeedProbe
{
	/// <summary>Rows per timed chunk. A chunk is the unit the "seconds per 100 000 rows" metric is
	/// measured in, so it is a named constant rather than a magic number.</summary>
	public const int ChunkRows = 100_000;

	/// <summary>Days the synthetic timestamps span, ending at the run's start. Longer than the policy's
	/// age floor, so a realistic share of the rows is old enough for the retention engine to consider.</summary>
	public const int SpanDays = 45;

	/// <summary>Size of the synthetic source-address pool. Enough distinct sources to look like a real
	/// per-IP workload without turning the seed into a cardinality test.</summary>
	public const int SourceIpPoolSize = 64;

	/// <summary>Event ids and channels the synthetic rows use. None of them is a protected event id, so
	/// the retention engine treats every code as eligible and the measurement is not distorted by a
	/// protection rule the operator may or may not have configured.</summary>
	private static readonly (int EventId, string Channel)[] BaseCodes =
	[
		(4624, "Security"),
		(4625, "Security"),
		(4634, "Security"),
		(4647, "Security"),
		(4688, "Security"),
		(4776, "Security"),
		(4778, "Security"),
		(4779, "Security"),
		(5152, "Security"),
		(5156, "Security"),
		(21, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
		(22, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
		(23, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
		(24, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
		(25, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
		(1149, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"),
		(102, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"),
		(200, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"),
		(226, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"),
		(131, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"),
	];

	/// <summary>
	/// Creates the schema and fills it with <paramref name="rows"/> synthetic raw events spread over
	/// <paramref name="codes"/> distinct codes.
	/// </summary>
	public static async Task<SeedOutcome> RunAsync(
		BenchmarkStore store,
		int rows,
		int codes,
		DateTime nowUtc,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(store);
		ArgumentNullException.ThrowIfNull(log);

		List<BenchmarkMeasurement> measurements = [];
		(int EventId, string Channel)[] codeTable = BuildCodeTable(codes);

		log("  applying the product's EF migrations to a fresh store");
		await store.MigrateAsync(cancellationToken).ConfigureAwait(false);

		// Read the auto-vacuum mode the product's own initialization left behind, before this probe writes
		// anything: `PRAGMA incremental_vacuum` is a no-op unless the mode is incremental, so where the mode
		// comes from has to be attributable to the product and not to this tool.
		string autoVacuumMode;
		using (SqliteConnection observer = SqliteBenchmarkFacts.Open(store.DatabasePath))
		{
			autoVacuumMode = SqliteBenchmarkFacts.ReadText(observer, "PRAGMA auto_vacuum;");
		}

		log(string.Format(CultureInfo.InvariantCulture, "  the product's migrations left PRAGMA auto_vacuum = {0}", autoVacuumMode));

		List<double> chunkSeconds = [];
		List<double> chunkRowsPerSecond = [];

		try
		{
			using SqliteConnection connection = SqliteBenchmarkFacts.Open(store.DatabasePath);
			ApplyProductPragmas(connection);

			using SqliteTransaction transaction = connection.BeginTransaction();
			using SqliteCommand command = connection.CreateCommand();
			command.Transaction = transaction;
			command.CommandText =
				"INSERT INTO \"RawEvents\" (\"EventId\", \"Channel\", \"TimeUtc\", \"IngestionSequence\", \"SourceIpBinary\", \"SourceIp\", \"Processed\", \"EventLayer\", \"SourceIpDerived\", \"SourceIpUnresolved\") " +
				"VALUES ($eventId, $channel, $timeUtc, $sequence, $ipBinary, $ipText, 1, 0, 0, 0);";
			SqliteParameter eventId = command.Parameters.Add("$eventId", SqliteType.Integer);
			SqliteParameter channel = command.Parameters.Add("$channel", SqliteType.Text);
			SqliteParameter timeUtc = command.Parameters.Add("$timeUtc", SqliteType.Text);
			SqliteParameter sequence = command.Parameters.Add("$sequence", SqliteType.Integer);
			SqliteParameter ipBinary = command.Parameters.Add("$ipBinary", SqliteType.Blob);
			SqliteParameter ipText = command.Parameters.Add("$ipText", SqliteType.Text);

			int written = 0;
			while (written < rows)
			{
				cancellationToken.ThrowIfCancellationRequested();
				int chunk = Math.Min(ChunkRows, rows - written);
				double elapsedMs = SqliteBenchmarkFacts.Timed(() =>
				{
					for (int index = 0; index < chunk; index++)
					{
						int position = written + index;
						(int eventIdValue, string channelValue) = codeTable[position % codeTable.Length];
						(byte[] ipBytes, string ipString) = BuildSourceIp(position);
						eventId.Value = eventIdValue;
						channel.Value = channelValue;
						timeUtc.Value = BuildTimestamp(nowUtc, position, rows);
						sequence.Value = (long)position + 1L;
						ipBinary.Value = ipBytes;
						ipText.Value = ipString;
						command.ExecuteNonQuery();
					}
				});

				written += chunk;
				double seconds = SqliteBenchmarkFacts.ToSeconds(elapsedMs);
				if (chunk == ChunkRows)
				{
					chunkSeconds.Add(seconds);
					chunkRowsPerSecond.Add(chunk / seconds);
				}

				log(string.Format(
					CultureInfo.InvariantCulture,
					"    seeded {0}/{1} rows in {2:0.###} s",
					written,
					rows,
					seconds));
			}

			transaction.Commit();
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			return new SeedOutcome
			{
				Measurements =
				[
					BenchmarkMeasurement.Failed(StorageBenchmarkMetric.SeedRowsPerSecond, StorageBenchmarkUnit.RowsPerSecond, BenchmarkSampleRecorder.Describe(ex)),
				],
				RowsWritten = 0,
				CodesUsed = codeTable.Length,
				DatabaseBytes = SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath),
				Error = BenchmarkSampleRecorder.Describe(ex),
			};
		}

		using (SqliteConnection connection = SqliteBenchmarkFacts.Open(store.DatabasePath))
		{
			ApplyProductPragmas(connection);
			using SqliteCommand settle = connection.CreateCommand();
			// Checkpoint the log into the main file, then give the planner statistics: a maintained
			// production store has both, and the retention statistics query reads what the planner chose.
			settle.CommandText = "PRAGMA wal_checkpoint(TRUNCATE); ANALYZE;";
			settle.ExecuteNonQuery();
		}

		long databaseBytes = SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath);
		long familyBytes = SqliteBenchmarkFacts.FamilyBytes(store.DatabasePath);

		measurements.Add(chunkRowsPerSecond.Count > 0
			? BenchmarkMeasurement.FromSamples(
				StorageBenchmarkMetric.SeedRowsPerSecond,
				StorageBenchmarkUnit.RowsPerSecond,
				BenchmarkSampleSet.FromValues(chunkRowsPerSecond),
				"one sample per completed 100 000-row chunk")
			: BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.SeedRowsPerSecond,
				StorageBenchmarkUnit.RowsPerSecond,
				"the run seeded fewer than one full 100 000-row chunk"));

		measurements.Add(chunkSeconds.Count > 0
			? BenchmarkMeasurement.FromSamples(
				StorageBenchmarkMetric.SeedSecondsPer100kRows,
				StorageBenchmarkUnit.Seconds,
				BenchmarkSampleSet.FromValues(chunkSeconds),
				"one sample per 100 000-row chunk")
			: BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.SeedSecondsPer100kRows,
				StorageBenchmarkUnit.Seconds,
				"the run seeded fewer than one full 100 000-row chunk"));

		// A million-row timing is only reported when a million rows were actually written: an
		// extrapolation from a smaller store is an estimate and this report does not carry estimates in
		// a measurement column. Ten complete chunks are summed, which is exactly one million rows.
		if (chunkSeconds.Count >= 10)
		{
			double millionSeconds = 0d;
			for (int index = 0; index < 10; index++)
			{
				millionSeconds += chunkSeconds[index];
			}

			measurements.Add(BenchmarkMeasurement.Scalar(
				StorageBenchmarkMetric.SeedSecondsPerMillionRows,
				StorageBenchmarkUnit.Seconds,
				millionSeconds,
				note: "sum of the first ten 100 000-row chunks"));
		}
		else
		{
			measurements.Add(BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.SeedSecondsPerMillionRows,
				StorageBenchmarkUnit.Seconds,
				string.Format(
					CultureInfo.InvariantCulture,
					"the run seeded {0} rows, fewer than the million a measured million-row timing requires",
					rows)));
		}

		measurements.Add(BenchmarkMeasurement.Scalar(
			StorageBenchmarkMetric.SeedStoreBytes,
			StorageBenchmarkUnit.Bytes,
			databaseBytes,
			note: string.Format(
				CultureInfo.InvariantCulture,
				"PRAGMA auto_vacuum = {0} after the product's migrations and the bulk load (2 = incremental)",
				autoVacuumMode)));
		measurements.Add(BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.SeedStoreFamilyBytes, StorageBenchmarkUnit.Bytes, familyBytes));

		return new SeedOutcome
		{
			Measurements = measurements,
			RowsWritten = rows,
			CodesUsed = codeTable.Length,
			DatabaseBytes = databaseBytes,
		};
	}

	/// <summary>Applies the same pragmas the product's SqlitePragmaInterceptor applies on every open, so
	/// the seed connection writes under production's durability and cache settings.</summary>
	private static void ApplyProductPragmas(SqliteConnection connection)
	{
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText =
			"PRAGMA journal_mode = WAL;" +
			"PRAGMA synchronous  = NORMAL;" +
			"PRAGMA cache_size   = -32000;" +
			"PRAGMA temp_store   = MEMORY;";
		command.ExecuteNonQuery();
	}

	/// <summary>Builds the code table, synthesizing extra channels when more codes are requested than the
	/// realistic base list holds.</summary>
	private static (int EventId, string Channel)[] BuildCodeTable(int codes)
	{
		(int EventId, string Channel)[] table = new (int, string)[codes];
		for (int index = 0; index < codes; index++)
		{
			table[index] = index < BaseCodes.Length
				? BaseCodes[index]
				: (5000 + index, string.Format(CultureInfo.InvariantCulture, "RdpAudit-Benchmark/Channel{0}", index));
		}

		return table;
	}

	/// <summary>Places row <paramref name="position"/> on a timeline of <see cref="SpanDays"/> days ending
	/// at <paramref name="nowUtc"/>, so the newest rows are the ones the retention age floor protects.</summary>
	private static string BuildTimestamp(DateTime nowUtc, int position, int rows)
	{
		double fraction = rows <= 1 ? 0d : (double)position / rows;
		DateTime timestamp = nowUtc.AddDays(-SpanDays * (1d - fraction));
		return timestamp.ToString("yyyy-MM-dd HH:mm:ss.FFFFFFF", CultureInfo.InvariantCulture);
	}

	/// <summary>Builds a source address: a 16-byte column value and its textual form.</summary>
	private static (byte[] Binary, string Text) BuildSourceIp(int position)
	{
		int slot = position % SourceIpPoolSize;
		string text = string.Format(
			CultureInfo.InvariantCulture,
			"203.0.{0}.{1}",
			113 + (slot / 256),
			slot % 256);
		byte[] address = IPAddress.Parse(text).GetAddressBytes();
		byte[] binary = new byte[16];
		Array.Copy(address, binary, address.Length);
		return (binary, text);
	}
}
