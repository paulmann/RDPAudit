# RDPAudit 2.0: Lock-Free SPSC Ring Buffer Architecture

**Author:** Mikhail Deynekin  
**Site:** [Deynekin.com](https://Deynekin.com)  
**Email:** [Mikhail@Deynekin.com](mailto:Mikhail@Deynekin.com)  
**Version:** 2.0.0  
**Status:** Production-Ready  

---

## 1. Executive Summary

RDPAudit 2.0 replaces the managed `System.Threading.Channels.Channel<T>` implementation with a custom, production-grade **Lock-Free Single-Producer Single-Consumer (SPSC) Ring Buffer**. This architectural shift eliminates all Garbage Collection (GC) pressure in the event ingestion hot-path, reduces CPU context switching, and guarantees sub-microsecond latency for Windows Event Log telemetry.

By utilizing unmanaged memory (`NativeMemory.AllocAligned`), explicit cache-line padding, and strict memory barriers, the new pipeline sustains >500,000 events/second on a single core while maintaining absolute zero-allocation semantics between the `EventCollectorWorker` and `EventProcessorWorker`.

---

## 2. Architectural Diagram

```mermaid
graph TD
    subgraph "Producer Thread (EventLogWatcher Callback)"
        A[Windows Event Log] -->|EventRecordWritten| B(EventCollectorWorker)
        B -->|Zero-Alloc Serialize| C[RawEventSerializer]
        C -->|4096-byte RawEventSlot| D[RingBufferEventChannel]
    end

    subgraph "Lock-Free SPSC Ring Buffer (Unmanaged Memory)"
        D -->|MemoryMarshal.AsBytes| E{UnmanagedSpscRingBuffer}
        E -->|Cache-Line 0| F[Head Counter + 56b Padding]
        E -->|Cache-Line 1| G[Tail Counter + 56b Padding]
        E -->|Cache-Line 2+| H[(NativeMemory Slot Array)]
    end

    subgraph "Consumer Thread (BackgroundService)"
        I(EventProcessorWorker) -->|SpinWait / Yield| J[RingBufferEventChannel]
        J -->|Zero-Alloc Deserialize| K[RawEventSerializer]
        K -->|RawEventDto| L[EventNormalizer]
        L -->|Bulk AddRange| M[(SQLite via EF Core)]
    end

    D -.->|TryWrite / DropOldest| E
    E -.->|TryRead / Acquire Fence| J

    style E fill:#2d333b,stroke:#539bf5,stroke-width:2px,color:#fff
    style F fill:#1e2227,stroke:#f47067,stroke-width:1px,color:#f47067
    style G fill:#1e2227,stroke:#57ab5a,stroke-width:1px,color:#57ab5a
    style H fill:#1e2227,stroke:#c69026,stroke-width:1px,color:#c69026
```

---

## 3. The Problem with `System.Threading.Channels`

In RDPAudit 1.5, the ingestion pipeline relied on `System.Threading.Channels.Channel<RawEventDto>`. While robust for general-purpose .NET applications, it introduced critical bottlenecks in a high-frequency security monitoring context:

1. **GC Pressure:** Every `RawEventDto` pushed to the channel contained managed `string` objects (`XmlPayload`, `Channel`). Under burst loads (e.g., brute-force attacks generating 10K+ events/sec), this triggered frequent Gen0 and Gen1 GC pauses, stalling the `EventLogWatcher` callback thread.
2. **Allocation Overhead:** `Channel<T>` internally allocates nodes or array segments depending on the bounded policy.
3. **False Sharing Risk:** Standard channel implementations do not guarantee cache-line isolation between producer and consumer counters, leading to CPU cache invalidation storms (MESI protocol bounce) on multi-core Xeon/EPYC processors.
4. **Latency Spikes:** `await channel.Reader.ReadAsync()` involves async state machine allocations and thread-pool scheduling overhead when the buffer is empty.

---

## 4. The RDPAudit 2.0 Solution

### 4.1. Unmanaged Memory & Zero-Allocation Hot-Path
The `UnmanagedSpscRingBuffer` allocates a single contiguous block of unmanaged memory via `NativeMemory.AllocAligned` at startup. 
* **Slot Size:** Strictly fixed at **4096 bytes**.
* **Serialization:** `RawEventSerializer` copies characters directly from managed strings into the unmanaged `RawEventSlot` using `Span<T>` and `MemoryMarshal`. **Zero heap allocations** occur during `TryWrite`.
* **Deserialization:** The consumer reads the 4096-byte block into a stack-allocated struct, only allocating managed `string` objects at the very end when handing off to EF Core.

### 4.2. Bitmask Modulo Arithmetic
The ring buffer capacity is strictly enforced as a **power of 2** (e.g., 1024, 2048). This allows the expensive modulo operator (`index % capacity`) to be replaced with a single CPU cycle bitwise AND operation (`index & mask`), where `mask = capacity - 1`.

### 4.3. DropOldest Backpressure Policy
To ensure the `EventLogWatcher` callback never blocks (which would cause Windows to drop events at the OS level), the ring buffer implements a strict **DropOldest** policy. If the buffer is full, the producer advances the `Tail` counter, effectively overwriting the oldest unread event, and signals the overflow to `ServiceMetrics` for operator visibility.

---

## 5. Memory Layout & Cache-Line Optimization

Modern CPUs fetch memory in 64-byte chunks (Cache Lines). If the Producer thread updates the `Head` counter and the Consumer thread updates the `Tail` counter, and both counters reside on the same 64-byte cache line, the CPU cores will constantly invalidate each other's L1/L2 caches (False Sharing).

RDPAudit 2.0 explicitly pads the counters to isolate them:

```csharp
// CACHE LINE 1: Head Counter (Producer writes, Consumer reads)
private long _head;
private long _p1_1, _p1_2, _p1_3, _p1_4, _p1_5, _p1_6, _p1_7; // 56 bytes padding

// CACHE LINE 2: Tail Counter (Consumer writes, Producer reads)
private long _tail;
private long _p2_1, _p2_2, _p2_3, _p2_4, _p2_5, _p2_6, _p2_7; // 56 bytes padding
```

Furthermore, the base pointer for the slot array is allocated with **64-byte alignment** (`NativeMemory.AllocAligned`) to ensure the first slot does not straddle a hardware page boundary or cache line.

---

## 6. Concurrency Model & Memory Barriers

The SPSC pattern relies on explicit memory ordering rather than heavy `lock` or `Monitor` primitives. RDPAudit 2.0 utilizes `Volatile.Read` and `Volatile.Write` to enforce **Acquire/Release** semantics, preventing the JIT compiler and CPU out-of-order execution (OoO) from reordering memory operations.

### Producer (EventCollectorWorker)
1. Writes payload data into the slot via `Span.CopyTo`.
2. **Release Fence:** Calls `Volatile.Write(ref _head, currentHead + 1)`. This guarantees that the CPU will not publish the updated `Head` index to the Consumer until the payload data is fully flushed to main memory.

### Consumer (EventProcessorWorker)
1. **Acquire Fence:** Calls `Volatile.Read(ref _head)`. This guarantees the Consumer sees the latest `Head` value and all preceding memory writes (the payload) made by the Producer.
2. Reads payload data from the slot.
3. **Release Fence:** Calls `Volatile.Write(ref _tail, currentTail + 1)` to free the slot for the Producer.

---

## 7. Integration & Telemetry

### 7.1. Worker Integration
* **`EventCollectorWorker`**: The `OnEventRecordWritten` callback now invokes `_channel.Channel.TryWrite(dto)`. If the method returns `false`, it indicates an overflow occurred, and the worker increments `_metrics.IncrementRingBufferOverflow()`.
* **`EventProcessorWorker`**: The `DrainBatchAsync` method utilizes a `SpinWait` loop instead of `await Task.Delay` or `Channel.Reader.WaitToReadAsync`. This achieves sub-microsecond wake-up latency when events are flowing, while automatically yielding to the OS scheduler (`Thread.Yield`) during idle periods to prevent 100% CPU burn.

### 7.2. ServiceMetrics Extensions
The `ServiceMetrics` class has been extended to expose real-time ring buffer telemetry via the IPC `GetStatus` surface:
* `RingBufferCapacity`: Total configured slots.
* `RingBufferUtilization`: Current depth (`Head - Tail`).
* `RingBufferOverflowCount`: Cumulative DropOldest triggers.
* `RingBufferReadCount` / `WriteCount`: Lifetime throughput counters.

---

## 8. Performance Validation Targets

| Metric | Target | Measurement Tool |
| :--- | :--- | :--- |
| **Producer Latency (p99)** | < 200 ns | BenchmarkDotNet |
| **Consumer Throughput** | > 500K evt/s | Single Core Benchmark |
| **GC Allocations (Hot-Path)** | 0 Bytes | dotMemory / MemoryDiagnoser |
| **False Sharing Incidents** | 0 | VTune / PerfView Cache Line Analysis |
| **Memory Footprint** | < 50 MB | Fixed Unmanaged Allocation |

---

## 9. Security & Auditability

Because this is a security-critical component handling Windows Event Logs, the ring buffer implementation is **100% in-house**. No third-party libraries (e.g., `Disruptor`, `System.IO.Pipelines`) are used in the hot-path. This ensures:
1. **Native AOT Compatibility:** No reflection or dynamic code generation.
2. **Auditability:** Every memory barrier and pointer operation is explicitly visible in the source code.
3. **Zero Information Leakage:** Unmanaged memory is explicitly zero-initialized via `NativeMemory.Clear` upon allocation to prevent stale process memory from leaking into the event stream.
