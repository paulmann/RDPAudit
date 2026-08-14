/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3
// File   : ShardWriterTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Sharding)
// Purpose: Verifies shard persistence, eviction, torn-header recovery, and append allocation behavior.
// Depends: ShardWriter, ShardReader, ShardHeader, ShardRecord, Crc32C, xUnit
// Extends: Extend record comparisons and known CRC vectors when the shard format changes.

using RdpAudit.Core.Events;
using RdpAudit.Core.Storage.Sharding;
using Xunit;

namespace RdpAudit.Core.Tests.Sharding;

public sealed class ShardWriterTests : IDisposable
{
	private readonly string _directory = Path.Combine(Path.GetTempPath(), "rdpaudit-sharding-" + Guid.NewGuid().ToString("N"));

	public ShardWriterTests()
	{
		Directory.CreateDirectory(_directory);
	}

	[Fact]
	public void AppendThenRead_RoundTripsEveryRecordByte()
	{
		string path = CreatePath("round-trip");
		ShardRecord[] expected = [CreateRecord(1), CreateRecord(2), CreateRecord(3)];

		using (ShardWriter writer = ShardWriter.OpenOrCreate(path, expected.Length))
		{
			foreach (ShardRecord record in expected)
			{
				writer.Append(in record, out bool evicted);
				Assert.False(evicted);
			}
			writer.Commit();
		}

		using ShardReader reader = Assert.IsType<ShardReader>(ShardReader.Open(path));
		ShardRecord[] actual = reader.ReadAll().ToArray();
		Assert.Equal(expected.Length, actual.Length);
		for (int index = 0; index < expected.Length; index++)
		{
			Assert.True(ShardRecord.AsBytes(in expected[index]).SequenceEqual(ShardRecord.AsBytes(in actual[index])));
		}
	}

	[Fact]
	public void RingEviction_KeepsNewestRecordsAndConsistentHeaderCounters()
	{
		const int capacity = 4;
		string path = CreatePath("eviction");

		using (ShardWriter writer = ShardWriter.OpenOrCreate(path, capacity))
		{
			for (long sequence = 1; sequence <= capacity * 2; sequence++)
			{
				ShardRecord record = CreateRecord(sequence);
				writer.Append(in record, out bool evicted);
				Assert.Equal(sequence > capacity, evicted);
			}
			Assert.Equal((uint)capacity, writer.Count);
			Assert.Equal((ulong)(capacity * 2), writer.TotalIngested);
			Assert.Equal((ulong)capacity, writer.TotalEvicted);
			writer.Commit();
		}

		using ShardReader reader = Assert.IsType<ShardReader>(ShardReader.Open(path));
		ShardRecord[] records = reader.ReadAll().ToArray();
		Assert.Equal(new long[] { 5L, 6L, 7L, 8L }, records.Select(record => record.Sequence));
		Assert.Equal((uint)capacity, reader.Snapshot.Count);
		Assert.Equal((uint)0, reader.Snapshot.Head);
		Assert.Equal((uint)0, reader.Snapshot.Tail);
		Assert.Equal((ulong)8, reader.Snapshot.TotalIngested);
		Assert.Equal((ulong)4, reader.Snapshot.TotalEvicted);
	}

	[Fact]
	public void HeaderDoubleBuffer_RecoversWhenOneHeaderCopyIsCorrupted()
	{
		string path = CreatePath("torn-header");
		using (ShardWriter writer = ShardWriter.OpenOrCreate(path, 4))
		{
			for (long sequence = 1; sequence <= 3; sequence++)
			{
				ShardRecord record = CreateRecord(sequence);
				writer.Append(in record, out _);
			}
			writer.Commit();
			writer.Commit();
		}

		CorruptHeaderCopy(path, copyOffset: 0);

		using ShardReader reader = Assert.IsType<ShardReader>(ShardReader.Open(path));
		Assert.Equal((uint)3, reader.Snapshot.Count);
		Assert.Equal((ulong)3, reader.Snapshot.TotalIngested);
		Assert.Equal(new long[] { 1L, 2L, 3L }, reader.ReadAll().Select(record => record.Sequence));
	}

	[Fact]
	public void Append_AllocatesNoManagedMemoryAcrossTenThousandOperations()
	{
		string path = CreatePath("allocation");
		ShardRecord record = CreateRecord(1);
		using ShardWriter writer = ShardWriter.OpenOrCreate(path, 16_384);
		writer.Append(in record, out _);
		writer.Commit();

		long before = GC.GetAllocatedBytesForCurrentThread();
		for (int index = 0; index < 10_000; index++)
		{
			writer.Append(in record, out _);
		}
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		Assert.Equal(0L, allocated);
	}

	[Fact]
	public void Crc32C_MatchesKnownCastagnoliVectorsAndSoftwareReference()
	{
		Assert.Equal(0x00000000u, Crc32C.HashToUInt32(ReadOnlySpan<byte>.Empty));
		byte[] digits = "123456789"u8.ToArray();
		Assert.Equal(0xE3069283u, Crc32C.HashToUInt32(digits));

		byte[] payload = new byte[257];
		for (int index = 0; index < payload.Length; index++)
		{
			payload[index] = (byte)index;
		}
		Assert.Equal(ComputeSoftwareCrc32C(payload), Crc32C.HashToUInt32(payload));

		uint running = Crc32C.Append(Crc32C.InitialValue, payload.AsSpan(0, 100));
		running = Crc32C.Append(running, payload.AsSpan(100));
		Assert.Equal(Crc32C.HashToUInt32(payload), Crc32C.Finalize(running));
	}

	public void Dispose()
	{
		try
		{
			Directory.Delete(_directory, recursive: true);
		}
		catch (IOException)
		{
			// A transient file handle must not conceal the behavior covered by the test.
		}
		catch (UnauthorizedAccessException)
		{
			// The operating system may postpone deletion of a recently closed mapped file.
		}
	}

	private string CreatePath(string name) => Path.Combine(_directory, name + ".rds");

	private static ShardRecord CreateRecord(long sequence)
	{
		ShardRecord incomplete = new(
			sequence,
			new DateTime(2026, 8, 14, 0, 0, 0, DateTimeKind.Utc).AddSeconds(sequence).Ticks,
			4625,
			(ushort)ChannelCode.Security,
			(byte)EventLayer.Authentication,
			100,
			10,
			0x25,
			0xc000,
			7,
			0x1234_0000 + sequence,
			-1,
			-1,
			-1,
			-1,
			-1,
			1,
			0);
		uint crc = Crc32C.HashToUInt32(ShardRecord.AsBytes(in incomplete).Slice(0, ShardRecord.Crc32COffset));
		return new ShardRecord(
			sequence,
			incomplete.TimeUtcTicks,
			incomplete.EventId,
			incomplete.ChannelCode,
			incomplete.EventLayer,
			incomplete.SourceIpConfidence,
			incomplete.LogonType,
			incomplete.SubStatusLow,
			incomplete.StatusHigh,
			incomplete.SessionId,
			incomplete.LogonId,
			incomplete.UserNameHeapOffset,
			incomplete.WorkstationNameHeapOffset,
			incomplete.ProcessNameHeapOffset,
			incomplete.DomainNameHeapOffset,
			incomplete.ActivityIdHeapOffset,
			incomplete.Flags,
			crc);
	}

	private static void CorruptHeaderCopy(string path, long copyOffset)
	{
		using FileStream stream = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
		stream.Position = copyOffset + 60;
		int original = stream.ReadByte();
		Assert.NotEqual(-1, original);
		stream.Position = copyOffset + 60;
		stream.WriteByte((byte)(original ^ 0xff));
		stream.Flush(flushToDisk: true);
	}

	private static uint ComputeSoftwareCrc32C(ReadOnlySpan<byte> source)
	{
		uint crc = 0xffffffffu;
		foreach (byte value in source)
		{
			crc ^= value;
			for (int bit = 0; bit < 8; bit++)
			{
				crc = (crc & 1u) == 0u ? crc >> 1 : (crc >> 1) ^ 0x82f63b78u;
			}
		}
		return ~crc;
	}
}
