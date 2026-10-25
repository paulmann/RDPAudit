// File:    tests/RdpAudit.Service.Tests/FakeNetshRunner.cs
// Module:  RdpAudit.Service.Tests
// Purpose: In-memory implementation of INetshRunner used by Stage 3 firewall tests. Records
//          every argument vector and lets tests script the netsh result for each invocation.
// Extends: RdpAudit.Service.Firewall.INetshRunner
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Firewall;

namespace RdpAudit.Service.Tests;

internal sealed class FakeNetshRunner : INetshRunner
{
	public List<IReadOnlyList<string>> Calls { get; } = new();

	public Queue<NetshResult> Responses { get; } = new();

	public NetshResult DefaultResponse { get; set; } = new(0, string.Empty, string.Empty);

	public Task<NetshResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
	{
		Calls.Add(args.ToArray());
		NetshResult res = Responses.Count > 0 ? Responses.Dequeue() : DefaultResponse;
		return Task.FromResult(res);
	}
}
