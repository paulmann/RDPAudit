/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardReader.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage.Sharding)
// Purpose: Read-only, memory-mapped, zero-copy iterator over a shard file's live records.
//          Detects header generation change and re-snapshots so a concurrent Commit() from
//          the writer never produces a torn view.
// Depends: ShardHeader, ShardRecord, System.IO.MemoryMappedFiles, System.IO.Hashing
// Extends: When adding new fields, add helper accessors here rather than mutating the layout.

using System.IO.Hashing;
using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RdpAudit.Core.Storage.Sharding;

/// <summary>Read-only memory-mapped view over a shard file. Not thread-safe: intended for one
/// reader at a time (e.g. the query service worker) with the pool caching multiple readers.</summary>
public sealed class ShardReader : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly MemoryMappedFile _map;
	private readonly MemoryMappedViewAccessor _view;
	private readonly long _viewLength;

	private HeaderPayload _snapshot;

	// ── Construction ─────────────────────────────────────────────────────────────

	private ShardReader(MemoryMappedFile map, MemoryMappedViewAccessor view, long viewLength, HeaderPayload snapshot)
	{
		_map = map;
		_view = view;
		_viewLength = viewLength;
		_snapshot = snapshot;
	}

	/// <summary>Opens a shard file read-only. Returns <c>null</c> if the file is empty or has
	/// no valid header copy (in which case the caller may quarantine it).</summary>
	public static ShardReader? Open(string absolutePath)
	{
		if (!File.Exists(absolutePath))
		{
			return null;
		}

		FileInfo info = new(absolutePath);
		if (info.Length < ShardHeader.HeaderRegionBytes)
		{
			return null;
		}

		FileStream stream = new(
			absolutePath,
			FileMode.Open,
			FileAccess.Read,
			FileShare.ReadWrite | FileShare.Delete,
			bufferSize: 4096,
			options: FileOptions.RandomAccess);

		try
		{
			MemoryMappedFile map = MemoryMappedFile.CreateFromFile(
				stream,
				mapName: null,
				capacity: info.Length,
				access: MemoryMappedFileAccess.Read,
				inheritability: HandleInheritability.None,
				leaveOpen: false);

			MemoryMappedViewAccessor view = map.CreateViewAccessor(0, info.Length, MemoryMappedFileAccess.Read);

			if (!TrySnapshotHeader(view, out HeaderPayload snapshot))
			{
				view.Dispose();
				map.Dispose();
				return null;
			}

			return new ShardReader(map, view, info.Length, snapshot);
		}
		catch
		{
			stream.Dispose();
			throw;
		}
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Current header snapshot. Refresh with <see cref="TryRefreshSnapshot"/>.</summary>
	public HeaderPayload Snapshot => _snapshot;

	/// <summary>Detects a header generation change and re-snapshots. Returns <c>true</c> when
	/// the reader's view of head/tail/count has advanced.</summary>
	public bool TryRefreshSnapshot()
	{
		if (!TrySnapshotHeader(_view, out HeaderPayload updated))
		{
			return false;
		}

		if (updated.Generation == _snapshot.Generation)
		{
			return false;
		}

		_snapshot = updated;
		return true;
	}

	/// <summary>Enumerates live records from oldest to newest. Records with a CRC mismatch
	/// (torn write) are skipped and reported via <paramref name="onCrcFailure"/>.</summary>
	public IEnumerable<ShardRecord> ReadAll(Action<int>? onCrcFailure = null)
	{
		HeaderPayload snap = _snapshot;
		uint capacity = snap.Capacity;
		if (capacity == 0 || snap.Count == 0)
		{
			yield break;
		}

		uint remaining = snap.Count;
		uint index = snap.Head;

		while (remaining > 0)
		{
			long offset = ShardHeader.HeaderRegionBytes + ((long)index * ShardRecord.SizeBytes);
			if (offset + ShardRecord.SizeBytes > _viewLength)
			{
				yield break;
			}

			if (TryReadRecord(offset, out ShardRecord record))
			{
				yield return record;
			}
			else
			{
				onCrcFailure?.Invoke((int)index);
			}

			index = (index + 1u) % capacity;
			remaining--;
		}
	}

	// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private bool TryReadRecord(long offset, out ShardRecord record)
	{
		record = default;

		unsafe
		{
			byte* pointer = null;
			_view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
			try
			{
				ReadOnlySpan<byte> src = new(pointer + offset, ShardRecord.SizeBytes);
				ReadOnlySpan<byte> forCrc = src.Slice(0, ShardRecord.Crc32COffset);
				uint expectedCrc = Crc32C.HashToUInt32(forCrc);
				uint storedCrc = MemoryMarshal.Read<uint>(src.Slice(ShardRecord.Crc32COffset, 4));
				if (expectedCrc != storedCrc)
				{
					return false;
				}

				record = MemoryMarshal.Read<ShardRecord>(src);
				return true;
			}
			finally
			{
				_view.SafeMemoryMappedViewHandle.ReleasePointer();
			}
		}
	}

	private static bool TrySnapshotHeader(MemoryMappedViewAccessor view, out HeaderPayload snapshot)
	{
		snapshot = default;
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

		return ShardHeader.TrySelectValidCopy(region, out snapshot);
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	/// <inheritdoc />
	public void Dispose()
	{
		_view.Dispose();
		_map.Dispose();
	}
}
