# RDPAudit 2.0: Memory Layout Specification

**Author:** Mikhail Deynekin
**Site:** [Deynekin.com](https://Deynekin.com)
**Email:** [Mikhail@Deynekin.com](mailto:Mikhail@Deynekin.com)
**Version:** 2.1.0
**Status:** Production-Ready

---

## 1. Overview

This document defines the exact byte-level memory layout of the `RawEventSlot` struct and the
`UnmanagedSpscRingBuffer` / `UnmanagedMpmcRingBuffer` control structures. Adherence to these
layouts is critical for Native AOT compatibility, SIMD-accelerated serialization, and
cross-platform memory safety.

The slot is **8192 bytes**. It was raised from 4096 in the Stage 20 change because a realistic
Security 4624/4625 XML payload is ~1.7-2.2 KB, and the old 4096-byte slot capped the XML at
1910 characters, silently dropping the trailing `EventData` fields, including `IpAddress`.
The default ring capacity was lowered from 50,000 (rounded to 65,536) to 32,768 to keep the
ring at roughly the same memory footprint.

---

## 2. RawEventSlot Memory Layout (8 KB)

The `RawEventSlot` is a fixed-size, unmanaged struct strictly constrained to **8192 bytes**.
`[StructLayout(LayoutKind.Explicit, Size = 8192)]` enforces the size.

### 2.1 Field table

| Offset | Size (bytes) | Type | Field | Notes |
|---|---|---|---|---|
| `0` | 8 | `long` | `SequenceNumber` | 64-bit monotonic ingestion sequence (ring-side). |
| `8` | 4 | `uint` | `PayloadLength` | Payload char count in bits 0-30; bit 31 (`TruncatedFlag`) marks a truncated payload. |
| `16` | 8 | `long` | `TimestampTicks` | Event `TimeUtc` ticks. |
| `12` | 4 | `int` | `EventId` | Windows event id. |
| `24` | 256 | `char[128]` | `ChannelName` | NUL-terminated channel name. |
| `280` | 8 | `long` | `RecordId` | Windows event-log RecordId (0 = none, e.g. ETW). |
| `288` | 7904 | `char[3952]` | `XmlPayload` | Fixed-size UTF-16 buffer for the raw XML event data. |
| **Total** | **8192** | | | Strictly enforced via `[StructLayout(LayoutKind.Explicit, Size = 8192)]`. |

### 2.2 The 3952-character mathematics

* Header: `8 + 4 + 4 + 8 = 24 bytes`.
* Channel name: `128 chars * 2 bytes = 256 bytes`, ending at offset `280`.
* RecordId: `8 bytes`, ending at offset `288`.
* Remaining budget: `8192 - 288 = 7904 bytes`.
* Max XML characters: `7904 / 2 = 3952 characters`.

### 2.3 PayloadLength flag

`PayloadLength` is a 32-bit value; bits 0-30 hold the number of payload characters and bit 31
(`RawEventSlot.TruncatedFlag = 0x8000_0000`) says the source XML was longer than the slot and
was cut. `RawEventSlot.PayloadCharCount` and `RawEventSlot.IsTruncated` decode it. The consumer
surfaces the flag as `RawEventDto.XmlTruncated`, and `EventNormalizer` then marks a row whose
source IP could not be resolved as `SourceIpUnresolved`, so a truncation loss is visible instead
of silent.

---

## 3. Ring Buffer Control Structures

The unmanaged ring buffers store a fixed-size sequence header plus the slot payload.

### 3.1 SPSC (`UnmanagedSpscRingBuffer`)

* **Slot Size:** 8192 bytes (`UnmanagedSpscRingBuffer.SlotSize`).
* **Index Calculation:** `nint slotPtr = _buffer + (index * 8192);`
* **Allocation:** `capacity * 8192` bytes, aligned.

### 3.2 MPMC (`UnmanagedMpmcRingBuffer`)

* **Slot Size:** 8192 bytes (`UnmanagedMpmcRingBuffer.SlotSize`).
* **Slot Stride:** `64 (sequence header) + 8192 = 8256` bytes per slot.
* **Index Calculation:** the buffer is allocated as one AoS block; every slot begins with an
  8-byte sequence field padded out to a full 64-byte cache line, then the 8192-byte payload.
* Because the stride (8256) is a multiple of 64, every slot payload is cache-line aligned,
  preventing cross-cache-line fetches during `Span<T>` copies.

### 3.3 Capacity and memory

`EventChannel` rounds `Monitoring.ChannelCapacity` up to a power of two and enforces a minimum
of 1000. The shipped default is **32,768** slots. At ~8256 bytes per MPMC slot that is about
270 MB, the same order as the former 65,536 x 4160 layout, while carrying twice the XML.

---

## 4. Serialization invariants

* `RawEventSerializer.Serialize` copies characters directly from the managed `RawEventDto`
  strings into the unmanaged slot via `Span<T>`; no heap allocation occurs on the hot path.
  Channel names longer than 128 chars and XML payloads longer than 3952 chars are clipped, and
  the XML clip sets the truncation flag.
* `RawEventSerializer.Deserialize` clamps a corrupted `PayloadLength` to `MaxXmlPayloadChars`
  (3952) and masks off the truncation bit before allocating the managed string, so corrupted
  unmanaged memory can never cause an `ArgumentOutOfRangeException` in the consumer thread.
* `RecordId` is carried through the ring (0 means "no Windows RecordId") so persistence can
  deduplicate an event forwarded by both the live watcher and a backfill worker.

