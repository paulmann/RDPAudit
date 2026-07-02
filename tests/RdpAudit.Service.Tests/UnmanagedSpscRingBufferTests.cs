/* Project: RDPAudit 2.0 | Module: RdpAudit.Service.Tests.Infrastructure | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.5

// File:    tests/RdpAudit.Service.Tests/UnmanagedSpscRingBufferTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Validates the low-level UnmanagedSpscRingBuffer strict FIFO semantics, 
//          memory safety, cache-line padding, and concurrent monotonic ordering.

using System;
using System.Threading;
using System.Threading.Tasks;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>
/// Unit tests for the lock-free SPSC Ring Buffer low-level memory operations.
/// </summary>
public sealed class UnmanagedSpscRingBufferTests : IDisposable
{
    private readonly UnmanagedSpscRingBuffer _buffer;

    public UnmanagedSpscRingBufferTests() => _buffer = new UnmanagedSpscRingBuffer(1024);
    
    public void Dispose() => _buffer?.Dispose();

    [Fact]
    public void Constructor_WithNonPowerOfTwo_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new UnmanagedSpscRingBuffer(1000));
        Assert.Throws<ArgumentException>(() => new UnmanagedSpscRingBuffer(3));
    }

    [Fact]
    public void Constructor_WithZeroOrNegative_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new UnmanagedSpscRingBuffer(0));
        Assert.Throws<ArgumentException>(() => new UnmanagedSpscRingBuffer(-1024));
    }

    [Fact]
    public void TryRead_OnEmptyBuffer_ReturnsFalse()
    {
        // FIX: Replaced stackalloc with managed array to avoid CS8175 in xUnit wrappers
        byte[] dest = new byte[UnmanagedSpscRingBuffer.SlotSize];
        Assert.False(_buffer.TryRead(dest));
    }

    [Fact]
    public void TryWrite_And_TryRead_PreservesData()
    {
        byte[] payload = new byte[UnmanagedSpscRingBuffer.SlotSize];
        payload[0] = 0xAA;
        payload[100] = 0xCC;
        payload[4095] = 0xBB;

        Assert.True(_buffer.TryWrite(payload));

        byte[] dest = new byte[UnmanagedSpscRingBuffer.SlotSize];
        Assert.True(_buffer.TryRead(dest));
        
        Assert.Equal(0xAA, dest[0]);
        Assert.Equal(0xCC, dest[100]);
        Assert.Equal(0xBB, dest[4095]);
    }

    [Fact]
    public void TryWrite_PayloadTooLarge_ThrowsArgumentException()
    {
        byte[] payload = new byte[UnmanagedSpscRingBuffer.SlotSize + 1];
        Assert.Throws<ArgumentException>(() => _buffer.TryWrite(payload));
    }

    [Fact]
    public void TryRead_DestinationTooSmall_ThrowsArgumentException()
    {
        byte[] dest = new byte[UnmanagedSpscRingBuffer.SlotSize - 1];
        Assert.Throws<ArgumentException>(() => _buffer.TryRead(dest));
    }

    [Fact]
    public void TryWrite_WhenFull_ReturnsFalse_StrictFIFO()
    {
        using var smallBuffer = new UnmanagedSpscRingBuffer(4);
        
        // FIX: Managed array instead of stackalloc to prevent CS8175
        byte[] payload = new byte[UnmanagedSpscRingBuffer.SlotSize];
        
        // Fill the buffer completely
        for (int i = 0; i < 4; i++) 
        { 
            payload[0] = (byte)i; 
            Assert.True(smallBuffer.TryWrite(payload)); 
        }

        // Attempt to write a 5th item
        payload[0] = 99;
        bool result = smallBuffer.TryWrite(payload); 
        
        // Must return false (strict FIFO, no silent overwrite)
        Assert.False(result, "Full buffer must reject writes in strict FIFO mode.");

        // Verify oldest item (0) is STILL THERE and was not overwritten
        byte[] dest = new byte[UnmanagedSpscRingBuffer.SlotSize];
        Assert.True(smallBuffer.TryRead(dest)); 
        Assert.Equal(0, dest[0]); 
    }

    [Fact]
    public async Task SPSC_Concurrent_ReadWrite_MaintainsMonotonicOrder()
    {
        using var buffer = new UnmanagedSpscRingBuffer(4096); 
        int totalEvents = 100_000;
        int lastRead = -1;
        bool orderViolated = false;
        
        byte[] payloadArray = new byte[UnmanagedSpscRingBuffer.SlotSize];
        
        Task producer = Task.Run(() =>
        {
            for (int i = 0; i < totalEvents; i++)
            {
                BitConverter.TryWriteBytes(payloadArray, i);
                while (!buffer.TryWrite(payloadArray)) 
                { 
                    Thread.SpinWait(1); 
                }
            }
        });

        Task consumer = Task.Run(() =>
        {
            byte[] destArray = new byte[UnmanagedSpscRingBuffer.SlotSize];
            int readCount = 0;
            
            while (readCount < totalEvents)
            {
                if (buffer.TryRead(destArray))
                {
                    int val = BitConverter.ToInt32(destArray, 0);
                    if (val <= lastRead) 
                    { 
                        orderViolated = true; 
                        break; 
                    }
                    lastRead = val;
                    readCount++;
                }
                else 
                { 
                    Thread.SpinWait(10); 
                }
            }
        });

        await Task.WhenAll(producer, consumer);
        Assert.False(orderViolated, "Torn read or out-of-order delivery detected.");
    }

    [Fact]
    public void Capacity_ReturnsCorrectConfiguredValue()
    {
        Assert.Equal(1024, _buffer.Capacity);
    }
}