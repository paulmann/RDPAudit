// File:    src/RdpAudit.Core/Ipc/Contracts/AttackStatsDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetAttackStats. Carries both a window summary (Stage 1 reservation) and,
//          as of Stage 6, the per-IP entries collection that drives the Attack Statistics tab.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>GetAttackStats</c> summarising recent attack-related metrics.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AttackStatsDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public DateTime WindowStartUtc { get; set; }

	[Key(2)]
	public DateTime WindowEndUtc { get; set; }

	[Key(3)]
	public long FailedLogons { get; set; }

	[Key(4)]
	public long SuccessfulLogons { get; set; }

	[Key(5)]
	public long DistinctSourceIps { get; set; }

	[Key(6)]
	public long AlertsRaised { get; set; }

	[Key(7)]
	public long AddressesAutoBlocked { get; set; }

	[Key(8)]
	public string? Message { get; set; }

	// --- Stage 6 additions (append-only — new keys must land at the end). ---

	/// <summary>Per-IP rows materialised by the Attack Statistics worker, filtered by the request.</summary>
	[Key(9)]
	public List<AttackStatEntryDto> Entries { get; set; } = new();

	/// <summary>Total number of rows in the AttackStats table after the filter is applied, before the limit is taken.</summary>
	[Key(10)]
	public int TotalMatching { get; set; }

	/// <summary>Limit the server clamped the response to (number of rows in <see cref="Entries"/>).</summary>
	[Key(11)]
	public int AppliedLimit { get; set; }

	// --- Req 12 additions (append-only). Surface the unresolved-IP slice as its own debug counter so
	// operators can see brute-force pressure that arrived without a usable source address, separate
	// from the real-attacker IP population in DistinctSourceIps. ---

	/// <summary>Count of failed / denied attempts in the window whose source IP could not be resolved
	/// (NLA stripped the address). These are aggregated under the sentinel row, never as a real IP.</summary>
	[Key(12)]
	public long UnresolvedFailedLogons { get; set; }

	/// <summary>Distinct count of genuinely resolved source IPs in the window — i.e.
	/// <see cref="DistinctSourceIps"/> minus the unresolved sentinel, when present.</summary>
	[Key(13)]
	public long DistinctResolvedSourceIps { get; set; }
}
