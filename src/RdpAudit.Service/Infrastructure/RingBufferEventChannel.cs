/* Project: RDPAudit 2.0 | Module: RdpAudit.Service.Infrastructure | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// Drop-in replacement for System.Threading.Channels.
/// Implements safe DropOldest policy by explicitly reading and discarding the oldest slot 
/// before writing the new one, preventing Torn Read race conditions in the underlying SPSC buffer.
/// Tracks overflow count at this policy layer.
/// </summary>
public sealed class RingBufferEventChannel : IDisposable
{
    private readonly UnmanagedSpscRingBuffer _ringBuffer;
    private long _overflowCount;
    private bool _disposed;

    public int Capacity => (int)_ringBuffer.Capacity;
    public long OverflowCount => Interlocked.Read(ref _overflowCount);

    public RingBufferEventChannel(int capacity = 1024)
    {
        _ringBuffer = new UnmanagedSpscRingBuffer(capacity);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryWrite(RawEventDto dto)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        ReadOnlySpan<byte> payload = MemoryMarshal.AsBytes(
            MemoryMarshal.CreateReadOnlySpan(ref slot, 1));

        if (_ringBuffer.TryWrite(payload))
        {
            return true;
        }

        // SAFE DROP-OLDEST POLICY:
        Span<byte> discard = stackalloc byte[UnmanagedSpscRingBuffer.SlotSize];
        _ringBuffer.TryRead(discard); 
        _ringBuffer.TryWrite(payload);
        
        Interlocked.Increment(ref _overflowCount);
        return false; 
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryRead(out RawEventDto dto)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        RawEventSlot slot = default;
        Span<byte> destination = MemoryMarshal.AsBytes(
            MemoryMarshal.CreateSpan(ref slot, 1));

        if (_ringBuffer.TryRead(destination))
        {
            dto = RawEventSerializer.Deserialize(slot);
            return true;
        }

        dto = default!;
        return false;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _ringBuffer.Dispose();
            _disposed = true;
        }
    }
}