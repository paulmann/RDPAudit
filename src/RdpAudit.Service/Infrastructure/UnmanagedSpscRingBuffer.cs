/* Project: RDPAudit 2.0 | Module: RdpAudit.Service.Infrastructure | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.6

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

#pragma warning disable CS0169 
#pragma warning disable CA1823 

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// Production-grade, lock-free Single-Producer Single-Consumer (SPSC) ring buffer.
/// Strictly FIFO: returns false when full. Does NOT track overflow internally —
/// the caller (RingBufferEventChannel) is responsible for DropOldest policy.
/// </summary>
public sealed class UnmanagedSpscRingBuffer : IDisposable
{
    public const int SlotSize = 4096;

    private long _head;
    private long _p1_1, _p1_2, _p1_3, _p1_4, _p1_5, _p1_6, _p1_7;

    private long _tail;
    private long _p2_1, _p2_2, _p2_3, _p2_4, _p2_5, _p2_6, _p2_7;

    private readonly long _capacity;
    private readonly long _mask;
    private readonly nint _buffer;
    private long _p3_1, _p3_2, _p3_3, _p3_4, _p3_5, _p3_6, _p3_7, _p3_8;

    private bool _disposed;

    public long Capacity => _capacity;

    public UnmanagedSpscRingBuffer(int capacity)
    {
        if (capacity <= 0 || (capacity & (capacity - 1)) != 0)
            throw new ArgumentException("Capacity must be a strictly positive power of 2.", nameof(capacity));

        _capacity = capacity;
        _mask = capacity - 1;
        
        nuint totalSize = (nuint)(capacity * SlotSize);
        
        unsafe 
        {
            _buffer = (nint)NativeMemory.Alloc(totalSize);
            NativeMemory.Clear((void*)_buffer, totalSize);
        }
    }

    /// <summary>
    /// Attempts to write payload. Returns false ONLY if buffer is full.
    /// Does NOT increment any overflow counter — caller manages DropOldest policy.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryWrite(ReadOnlySpan<byte> payload)
    {
        if (payload.Length > SlotSize) ThrowPayloadTooLarge();

        long currentTail = Volatile.Read(ref _tail);
        long currentHead = _head; 

        // Strict FIFO: If full, return false immediately. No overwrite.
        if (currentHead - currentTail >= _capacity)
        {
            return false; 
        }

        long index = currentHead & _mask;
        nint slotPtr = _buffer + (nint)(index * SlotSize);

        unsafe 
        {
            payload.CopyTo(new Span<byte>((void*)slotPtr, SlotSize));
        }

        Volatile.Write(ref _head, currentHead + 1);
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryRead(Span<byte> destination)
    {
        if (destination.Length < SlotSize) ThrowDestinationTooSmall();

        long currentHead = Volatile.Read(ref _head);
        long currentTail = _tail; 

        if (currentTail >= currentHead) return false;

        long index = currentTail & _mask;
        nint slotPtr = _buffer + (nint)(index * SlotSize);

        unsafe 
        {
            new Span<byte>((void*)slotPtr, SlotSize).CopyTo(destination);
        }

        Volatile.Write(ref _tail, currentTail + 1);
        return true;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_buffer != nint.Zero)
            {
                unsafe { NativeMemory.Free((void*)_buffer); }
            }
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    ~UnmanagedSpscRingBuffer() => Dispose();

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowPayloadTooLarge() => throw new ArgumentException($"Payload exceeds {SlotSize} bytes.");

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowDestinationTooSmall() => throw new ArgumentException($"Destination must be >= {SlotSize} bytes.");
}