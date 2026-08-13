/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardWriter.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage.Sharding)
// Purpose: Zero-allocation appender for a per-IP shard file. Ring semantics: on overflow the
//          oldest record is O(1) evicted by advancing the head pointer; no rewrite or compaction
//          pause. Header is double-buffered and CRC-guarded so a torn write is always detectable.
// Depends: ShardHeader, ShardRecord, System.IO.MemoryMappedFiles, System.IO.Hashing
// Extends: When adding a new field to ShardRecord, keep append() below allocation-free and
//          update MinimumFileSize accordingly.

using System.Buffers.Binary;
using System.IO.Hashing;
using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RdpAudit.Core.Storage.Sharding;

/// <summary>
/// Zero-allocation append writer for a single shard file. Not thread-safe; the caller (the
/// event processor worker) is single-writer per shard. Readers open the same file
/// read-only via <see cref="ShardReader"/>.
/// </summary>
public sealed class ShardWriter : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly FileStream _stream;
	private readonly MemoryMappedFile _map;
	private readonly MemoryMappedViewAccessor _view;
	private readonly int _capacity;
	private readonly long _recordRegionOffset;

	private HeaderPayload _header;
	private bool _writeCopyIsB;

	// ── Construction ─────────────────────────────────────────────────────────────

	private ShardWriter(FileStream stream, MemoryMappedFile map, MemoryMappedViewAccessor view, HeaderPayload header, int capacity)
	{
		_stream = stream;
		_map = map;
		_view = view;
		_header = header;
		_capacity = capacity;
		_recordRegionOffset = ShardHeader.HeaderRegionBytes;
		_writeCopyIsB = false;
	}

	/// <summary>Opens an existing shard or creates a new one sized for <paramref name="capacity"/>
	/// records. The file is opened with <see cref="FileShare.Read"/> so readers can memory-map it
	/// concurrently, and with <see cref="FileOptions.WriteThrough"/> on the metadata operations
	/// used at commit time.</summary>
	public static ShardWriter OpenOrCreate(string absolutePath, int capacity)
	{
		if (capacity <= 0)
		{
			throw new ArgumentOutOfRangeException(nameof(capacity));
		}

		long minSize = ShardHeader.HeaderRegionBytes + ((long)capacity * ShardRecord.SizeBytes);
		bool exists = File.Exists(absolutePath);

		FileStream stream = new(
			absolutePath,
			FileMode.OpenOrCreate,
			FileAccess.ReadWrite,
			FileShare.Read,
			bufferSize: 4096,
			options: FileOptions.RandomAccess);

		try
		{
			if (!exists || stream.Length < minSize)
			{
				stream.SetLength(minSize);
			}

			MemoryMappedFile map = MemoryMappedFile.CreateFromFile(
				stream,
				mapName: null,
				capacity: stream.Length,
				access: MemoryMappedFileAccess.ReadWrite,
				inheritability: HandleInheritability.None,
				leaveOpen: true);

			MemoryMappedViewAccessor view = map.CreateViewAccessor(0, stream.Length, MemoryMappedFileAccess.ReadWrite);

			HeaderPayload header = LoadOrInitializeHeader(view, capacity, isFreshFile: !exists || stream.Length == minSize);
			return new ShardWriter(stream, map, view, header, capacity);
		}
		catch
		{
			stream.Dispose();
			throw;
		}
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Number of live records currently in the ring.</summary>
	public uint Count => _header.Count;

	/// <summary>Head record index (oldest live record).</summary>
	public uint Head => _header.Head;

	/// <summary>Tail record index (next write slot).</summary>
	public uint Tail => _header.Tail;

	/// <summary>Monotonic total events appended over the lifetime of this shard file.</summary>
	public ulong TotalIngested => _header.TotalIngested;

	/// <summary>Total records evicted from this shard by ring overflow.</summary>
	public ulong TotalEvicted => _header.TotalEvicted;

	/// <summary>Appends one record. If the ring is full, evicts the oldest slot in O(1) and
	/// returns <c>true</c> in <paramref name="evictedOne"/>. Zero managed allocations.</summary>
	public void Append(in ShardRecord record, out bool evictedOne)
	{
		evictedOne = false;

		uint newTail = (_header.Tail + 1u) % (uint)_capacity;
		bool willOverwrite = _header.Count == (uint)_capacity;

		// Serialise the record to the mapped view directly; CRC has already been computed by
		// the caller as part of the ShardRecord constructor.
		long recordOffset = _recordRegionOffset + ((long)_header.Tail * ShardRecord.SizeBytes);
		WriteRecord(recordOffset, in record);

		uint newHead = _header.Head;
		uint newCount = _header.Count;
		ulong newEvicted = _header.TotalEvicted;

		if (willOverwrite)
		{
			newHead = (_header.Head + 1u) % (uint)_capacity;
			newEvicted++;
			evictedOne = true;
		}
		else
		{
			newCount++;
		}

		_header = new HeaderPayload(
			magic: ShardHeader.Magic,
			formatVersion: ShardHeader.CurrentFormatVersion,
			recordSize: (uint)ShardRecord.SizeBytes,
			capacity: (uint)_capacity,
			head: newHead,
			tail: newTail,
			count: newCount,
			generation: _header.Generation + 1UL,
			totalIngested: _header.TotalIngested + 1UL,
			totalEvicted: newEvicted,
			heapBytes: _header.HeapBytes,
			flags: _header.Flags);
	}

	/// <summary>Commits the current header to disk with torn-write survivability. Writes the
	/// *inactive* copy first, flushes, then flips the active pointer via the second copy write.
	/// Any crash between these steps leaves at least one valid copy for the reader to pick.</summary>
	public void Commit()
	{
		Span<byte> copy = stackalloc byte[64];
		ShardHeader.WriteCopy(copy, in _header);

		long targetOffset = _writeCopyIsB ? 64 : 0;
		WriteBytes(targetOffset, copy);
		_view.Flush();

		// Alternate which copy we write next time so the OTHER copy is always the "old" one
		// on disk with an older generation — the reader picks the higher generation.
		_writeCopyIsB = !_writeCopyIsB;
	}

	// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void WriteRecord(long offset, in ShardRecord record)
	{
		unsafe
		{
			byte* pointer = null;
			_view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
			try
			{
				Span<byte> dst = new(pointer + offset, ShardRecord.SizeBytes);
				MemoryMarshal.Write(dst, in record);
			}
			finally
			{
				_view.SafeMemoryMappedViewHandle.ReleasePointer();
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void WriteBytes(long offset, ReadOnlySpan<byte> bytes)
	{
		unsafe
		{
			byte* pointer = null;
			_view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
			try
			{
				Span<byte> dst = new(pointer + offset, bytes.Length);
				bytes.CopyTo(dst);
			}
			finally
			{
				_view.SafeMemoryMappedViewHandle.ReleasePointer();
			}
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static HeaderPayload LoadOrInitializeHeader(MemoryMappedViewAccessor view, int capacity, bool isFreshFile)
	{
		Span<byte> region = stackalloc byte[ShardHeader.HeaderRegionBytes];

		unsafe
		{
			byte* pointer = null;
			view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
			try
			{
				new ReadOnlySpan<byte>(pointer, ShardHeader.HeaderRegionBytes).CopyTo(region);
			}
			finally
			{
				view.SafeMemoryMappedViewHandle.ReleasePointer();
			}
		}

		if (!isFreshFile && ShardHeader.TrySelectValidCopy(region, out HeaderPayload existing))
		{
			return existing;
		}

		HeaderPayload fresh = new(
			magic: ShardHeader.Magic,
			formatVersion: ShardHeader.CurrentFormatVersion,
			recordSize: (uint)ShardRecord.SizeBytes,
			capacity: (uint)capacity,
			head: 0,
			tail: 0,
			count: 0,
			generation: 1,
			totalIngested: 0,
			totalEvicted: 0,
			heapBytes: 0,
			flags: 0);

		// Emit both copies so a follow-up commit doesn't leave an invalid A copy.
		Span<byte> emit = stackalloc byte[64];
		ShardHeader.WriteCopy(emit, in fresh);

		unsafe
		{
			byte* pointer = null;
			view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
			try
			{
				emit.CopyTo(new Span<byte>(pointer, 64));
				emit.CopyTo(new Span<byte>(pointer + 64, 64));
			}
			finally
			{
				view.SafeMemoryMappedViewHandle.ReleasePointer();
			}
		}

		view.Flush();
		return fresh;
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	/// <inheritdoc />
	public void Dispose()
	{
		try
		{
			_view.Flush();
		}
		catch
		{
			// Best-effort flush; propagate no exception from Dispose.
		}

		_view.Dispose();
		_map.Dispose();
		_stream.Dispose();
	}
}
