/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : SerializerBenchmark.cs
// Project: RdpAudit.Benchmarks (RdpAudit.Benchmarks)
// Purpose: Latency and allocation benchmark for RawEventSerializer.Serialize / Deserialize.
//          Serialize must remain 0-alloc; Deserialize allocates only the two unavoidable
//          strings (channel name + XML payload) required by EF Core persistence.
// Depends: BenchmarkDotNet, RawEventSerializer, RawEventDto, RawEventSlot
// Extends: Add a new [Benchmark] for any new serializer path (e.g. batch encode) and keep
//          the sample DTO identical so numbers stay comparable across releases.

using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;

namespace RdpAudit.Benchmarks;

/// <summary>
/// Measures Serialize (DTO -> Slot, must be zero-alloc) and Deserialize (Slot -> DTO,
/// only the two required strings should be allocated).
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, warmupCount: 2, iterationCount: 5, invocationCount: 100_000)]
public class SerializerBenchmark
{
	private RawEventDto _sampleDto = null!;
	private RawEventSlot _sampleSlot;

	[GlobalSetup]
	public void Setup()
	{
		// Realistic Security 4625 payload (~800 chars). Big enough to force the payload
		// span copy through UnmanagedMemory but well under RawEventSlot.MaxXmlPayloadChars.
		string xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			"<System>" +
			"<Provider Name='Microsoft-Windows-Security-Auditing'/>" +
			"<EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task>" +
			"<TimeCreated SystemTime='2026-07-02T10:15:30.1234567Z'/>" +
			"<EventRecordID>123456789</EventRecordID>" +
			"<Execution ProcessID='654' ThreadID='700'/>" +
			"<Channel>Security</Channel><Computer>DC01.corp.local</Computer>" +
			"</System>" +
			"<EventData>" +
			"<Data Name='SubjectUserSid'>S-1-5-18</Data>" +
			"<Data Name='SubjectUserName'>DC01$</Data>" +
			"<Data Name='SubjectDomainName'>CORP</Data>" +
			"<Data Name='TargetUserName'>Administrator</Data>" +
			"<Data Name='TargetDomainName'>CORP</Data>" +
			"<Data Name='Status'>0xc000006d</Data>" +
			"<Data Name='FailureReason'>%%2313</Data>" +
			"<Data Name='SubStatus'>0xc000006a</Data>" +
			"<Data Name='IpAddress'>192.168.1.100</Data>" +
			"<Data Name='IpPort'>49832</Data>" +
			"</EventData></Event>";

		_sampleDto = new RawEventDto
		{
			EventId    = 4625,
			Channel    = "Security",
			TimeUtc    = DateTime.UtcNow,
			XmlPayload = xml,
		};

		// Warm the sample slot so the Deserialize benchmark has a valid payload to read.
		_sampleSlot = RawEventSerializer.Serialize(_sampleDto);
	}

	[Benchmark(Description = "Serialize (zero-alloc)")]
	public RawEventSlot Serialize()
	{
		return RawEventSerializer.Serialize(_sampleDto);
	}

	[Benchmark(Description = "Deserialize (2 string allocs)")]
	public RawEventDto Deserialize()
	{
		return RawEventSerializer.Deserialize(in _sampleSlot);
	}

	[Benchmark(Description = "RoundTrip")]
	public RawEventDto RoundTrip()
	{
		RawEventSlot slot = RawEventSerializer.Serialize(_sampleDto);
		return RawEventSerializer.Deserialize(in slot);
	}
}
