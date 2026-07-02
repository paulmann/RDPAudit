# RDPAudit 2.0: Memory Layout Specification

**Author:** Mikhail Deynekin  
**Site:** [Deynekin.com](https://Deynekin.com)  
**Email:** [Mikhail@Deynekin.com](mailto:Mikhail@Deynekin.com)  
**Version:** 2.0.0  
**Status:** Production-Ready  

---

## 1. Overview

The RDPAudit 2.0 Lock-Free SPSC Ring Buffer relies on strict, explicit memory layouts to achieve zero-allocation hot-path execution, eliminate Garbage Collection (GC) pressure, and prevent CPU cache false sharing. 

This document defines the exact byte-level memory layout of the `RawEventSlot` struct and the `UnmanagedSpscRingBuffer` control structures. Adherence to these layouts is critical for Native AOT compatibility, SIMD-accelerated serialization, and cross-platform memory safety.

---

## 2. RawEventSlot Memory Layout (The 4096-Byte Constraint)

The `RawEventSlot` is a fixed-size, unmanaged struct strictly constrained to **4096 bytes**. This size was chosen to align perfectly with standard OS memory page boundaries (4KB) and ensure predictable cache-line fetching.

To maintain the exact 4096-byte limit, the XML payload capacity was mathematically adjusted from the initial 1960-character design target to **1910 characters**.

### 2.1. Byte-Level Offset Map

| Offset (Bytes) | Size (Bytes) | Type | Field Name | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0` - `3` | 4 | `uint32` | `SequenceNumber` | Monotonic counter for strict ordering and gap detection. |
| `4` - `7` | 4 | `uint32` | `PayloadLength` | Actual character count of the XML payload. |
| `8` - `15` | 8 | `int64` | `TimestampTicks` | UTC timestamp mapped to `DateTime.Ticks` to avoid `DateTime` struct padding quirks. |
| `16` - `19` | 4 | `int32` | `EventId` | Windows Event Log Event ID (e.g., 4625, 4624). |
| `20` - `275` | 256 | `char[128]` | `ChannelName` | Fixed-size UTF-16 buffer for the Event Log Channel name. |
| `276` - `4095`| 3820 | `char[1910]` | `XmlPayload` | Fixed-size UTF-16 buffer for the raw XML event data. |
| **Total** | **4096** | | | **Strictly enforced via `[StructLayout(LayoutKind.Explicit, Size = 4096)]`** |

### 2.2. The 1910-Character Mathematical Proof

The original architectural prompt requested 1960 characters for the XML payload. However, .NET `char` is a 2-byte UTF-16 code unit. 

* **Header Size:** 20 bytes
* **Channel Name Size:** 128 chars × 2 bytes = 256 bytes
* **Remaining Budget:** 4096 - 20 - 256 = **3820 bytes**
* **Max XML Characters:** 3820 bytes / 2 bytes per char = **1910 characters**

Attempting to allocate 1960 characters would require 3920 bytes, resulting in a total struct size of 4196 bytes. This would violate the 4096-byte page alignment constraint, cause `ArgumentOutOfRangeException` during `Span<T>` memory mapping, and trigger compiler errors due to explicit field offset overlaps.

---

## 3. UnmanagedSpscRingBuffer Layout (Cache-Line Isolation)

Modern CPUs fetch memory from RAM in 64-byte chunks known as **Cache Lines**. If the Producer thread updates the `Head` counter and the Consumer thread updates the `Tail` counter, and both counters reside on the same 64-byte cache line, the CPU cores will constantly invalidate each other's L1/L2 caches via the MESI protocol. This phenomenon is known as **False Sharing** and destroys multi-core throughput.

RDPAudit 2.0 explicitly pads the control counters to isolate them on separate cache lines.

### 3.1. Control Structure Layout

```csharp
// =====================================================================
// CACHE LINE 0: Head Counter (Producer writes, Consumer reads)
// =====================================================================
private long _head;                  // 8 bytes
private long _p1_1, _p1_2, _p1_3,    // 48 bytes padding
             _p1_4, _p1_5, _p1_6, 
             _p1_7;                  // Total: 64 bytes

// =====================================================================
// CACHE LINE 1: Tail Counter (Consumer writes, Producer reads)
// =====================================================================
private long _tail;                  // 8 bytes
private long _p2_1, _p2_2, _p2_3,    // 48 bytes padding
             _p2_4, _p2_5, _p2_6, 
             _p2_7;                  // Total: 64 bytes

// =====================================================================
// CACHE LINE 2+: Immutable Config & Unmanaged Pointer
// =====================================================================
private readonly long _capacity;     // 8 bytes
private readonly long _mask;         // 8 bytes
private readonly nint _buffer;       // 8 bytes (Pointer to NativeMemory)
// ... remaining config and overflow metrics
```

### 3.2. The Unmanaged Slot Array

The actual event data is stored in a contiguous block of unmanaged memory allocated via `NativeMemory.AllocAligned`. 

* **Base Address:** 64-byte aligned.
* **Slot Stride:** Exactly 4096 bytes.
* **Index Calculation:** `nint slotPtr = _buffer + (index * 4096);`

Because the base pointer is 64-byte aligned and the slot size (4096) is a perfect multiple of 64, **every single slot in the ring buffer is guaranteed to be perfectly aligned to a cache-line boundary**, preventing cross-cache-line memory fetches during `Span<T>` copy operations.

---

## 4. Memory Alignment & Allocation

### 4.1. NativeMemory.AllocAligned
Standard `malloc` or `new byte[]` does not guarantee 64-byte alignment. RDPAudit 2.0 utilizes the .NET 8 `NativeMemory.AllocAligned` API:

```csharp
nuint totalSize = (nuint)(capacity * 4096);
_buffer = (nint)NativeMemory.AllocAligned(totalSize, 64);
```

### 4.2. Zero-Initialization (Security Requirement)
To prevent information leakage from stale process memory (e.g., reading remnants of cryptographic keys or passwords from previously freed RAM), the unmanaged buffer is explicitly zeroed immediately upon allocation:

```csharp
NativeMemory.Clear((void*)_buffer, totalSize);
```

---

## 5. Concurrency & Memory Barriers

The SPSC pattern relies on explicit memory ordering rather than heavy `lock` or `Monitor` primitives. RDPAudit 2.0 utilizes `Volatile.Read` and `Volatile.Write` to enforce **Acquire/Release** semantics, preventing the JIT compiler and CPU out-of-order execution (OoO) from reordering memory operations.

### 5.1. Producer Write Sequence (Release Semantics)
1. Payload data is written into the slot via `Span.CopyTo`.
2. **Release Fence:** `Volatile.Write(ref _head, currentHead + 1)` is executed.
3. *Hardware Guarantee:* The CPU will not publish the updated `Head` index to the Consumer's cache until the payload data is fully flushed to main memory.

### 5.2. Consumer Read Sequence (Acquire Semantics)
1. **Acquire Fence:** `Volatile.Read(ref _head)` is executed.
2. *Hardware Guarantee:* The Consumer sees the latest `Head` value and all preceding memory writes (the payload) made by the Producer.
3. Payload data is read from the slot.
4. **Release Fence:** `Volatile.Write(ref _tail, currentTail + 1)` frees the slot for the Producer.

---

## 6. Bitmask Modulo Arithmetic

To achieve O(1) index wrapping without the severe CPU pipeline stall caused by the hardware `DIV` instruction (modulo operator `%`), the ring buffer capacity is strictly enforced as a **power of 2**.

### 6.1. The Bitwise AND Trick
For any power of 2 capacity $C$, the modulo operation $X \pmod C$ is mathematically identical to the bitwise AND operation $X \ \& \ (C - 1)$.

```csharp
// Initialization
_mask = capacity - 1; 

// Hot-Path Index Calculation (1 CPU Cycle)
long index = currentHead & _mask;
```

This reduces the index calculation from a ~20-cycle division operation to a single-cycle bitwise AND, drastically reducing producer latency.

---

## 7. Safety & DropOldest Policy

### 7.1. Overflow Handling
If the Producer detects that the buffer is full (`currentHead - currentTail >= _capacity`), it does not block or spin. Instead, it implements a strict **DropOldest** policy to protect the Windows `EventLogWatcher` callback thread from stalling:

1. The Producer advances the `Tail` counter (`Volatile.Write(ref _tail, currentTail + 1)`).
2. The Producer increments the `_overflowCount` metric.
3. The Producer overwrites the oldest slot with the new event.
4. The method returns `false` to signal the overflow to `ServiceMetrics`.

### 7.2. Memory Corruption Clamps
During deserialization, `RawEventSerializer.Deserialize` applies defensive clamps to the `PayloadLength` field. If unmanaged memory is ever corrupted or read out of bounds, the serializer clamps the length to `MaxXmlPayloadChars` (1910) to prevent `ArgumentOutOfRangeException` crashes in the consumer thread.
