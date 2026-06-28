// File:    src/RdpAudit.Core/Ipc/Contracts/AddressListEntryDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO entry for whitelist / blocklist / active-block listings returned over IPC.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO entry for whitelist / blocklist / active-block listings.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AddressListEntryDto
{
	[Key(0)]
	public string Address { get; set; } = string.Empty;

	[Key(1)]
	public string? Note { get; set; }

	[Key(2)]
	public DateTime? AddedUtc { get; set; }

	[Key(3)]
	public DateTime? ExpiresUtc { get; set; }

	/// <summary>Origin of the entry (e.g. "Configurator", "AutoBlock", "Config:Blacklist").</summary>
	[Key(4)]
	public string? Source { get; set; }

	/// <summary>
	/// Stable surrogate row key for the underlying table (BlocklistEntry.Id / WhitelistEntry.Id).
	/// Zero when the producing list has no surrogate key. Carried so mutation commands can target a
	/// specific row deterministically instead of matching by address text alone.
	/// </summary>
	[Key(5)]
	public long Id { get; set; }

	/// <summary>True when the underlying row is enabled. Blocklist listings include disabled rows so the
	/// operator can see (and target by Id) a soft-disabled duplicate; defaults true for lists that have
	/// no enabled/disabled distinction (e.g. whitelist).</summary>
	[Key(6)]
	public bool IsEnabled { get; set; } = true;
}
