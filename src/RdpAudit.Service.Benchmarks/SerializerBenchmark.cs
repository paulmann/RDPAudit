/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0

using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;

namespace RdpAudit.Service.Benchmarks;

/// <summary>
/// BenchmarkDotNet suite measuring the latency and GC allocation overhead 
/// of the zero-allocation RawEventSerializer.
/// Validates that Serialize() produces 0 bytes allocated on the heap, 
/// and Deserialize() allocates ONLY the unavoidable string objects for EF Core persistence.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, invocationCount: 100_000, warmupCount: 1, targetCount: 3)]
public class SerializerBenchmark
{
    private RawEventDto _sampleDto = null!;
    private RawEventSlot _sampleSlot;

    [GlobalSetup]
    public void Setup()
    {
        // Realistic Security 4625 Event XML payload (~800 chars)
        string xmlPayload = @"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}' />
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime='2026-07-02T10:15:30.1234567Z' />
    <EventRecordID>123456789</EventRecordID>
    <Correlation />
    <Execution ProcessID='654' ThreadID='700' />
    <Channel>Security</Channel>
    <Computer>DC01.corp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-18</Data>
    <Data Name='SubjectUserName'>DC01$</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
    <Data Name='TargetUserName'>Administrator</Data>
    <Data Name='TargetDomainName'>CORP</Data>
    <Data Name='Status'>0xc000006d</Data>
    <Data Name='FailureReason'>%%2313</Data>
    <Data Name='SubStatus'>0xc000006a</Data>
    <Data Name='IpAddress'>192.168.1.100</Data>
    <Data Name='IpPort'>49832</Data>
  </EventData>
</Event>";

        _sampleDto = new RawEventDto
        {
            SequenceNumber = 123456,
            // Architect Note: If your core RawEventDto uses `TimeUtc` (DateTime), 
            // ensure RawEventSerializer maps `dto.TimeUtc.Ticks` to `slot.TimestampTicks`.
            TimestampTicks = DateTime.UtcNow.Ticks, 
            EventId = 4625,
            Channel = "Security",
            XmlPayload = xmlPayload
        };

        // Pre-serialize to have a valid slot for the Deserialize benchmark
        _sampleSlot = RawEventSerializer.Serialize(_sampleDto);
    }

    [Benchmark(Description = "Serialize (Zero-Alloc)")]
    public RawEventSlot Serialize()
    {
        return RawEventSerializer.Serialize(_sampleDto);
    }

    [Benchmark(Description = "Deserialize (String Allocs Only)")]
    public RawEventDto Deserialize()
    {
        return RawEventSerializer.Deserialize(in _sampleSlot);
    }

    [Benchmark(Description = "Full Round-Trip")]
    public void RoundTrip()
    {
        RawEventSlot slot = RawEventSerializer.Serialize(_sampleDto);
        _ = RawEventSerializer.Deserialize(in slot);
    }
}