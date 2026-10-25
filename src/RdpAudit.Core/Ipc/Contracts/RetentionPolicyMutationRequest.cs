/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionPolicyMutationRequest.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Mutation payload for SaveRetentionPolicy, shaped like EventCollectionMutationRequest:
//          a partial document plus an explicit replacement mode for the per-event list. Every
//          section is optional; a null section means "leave what is on disk unchanged", so a
//          client can save only what the operator actually touched.
// Depends: MessagePack, RetentionPolicyValuesDto, RetentionWindowsDto, EventRetentionWindowDto
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for saving retention settings.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RetentionPolicyMutationRequest
{
	/// <summary>Information-density policy values to persist. Null leaves the
	/// <c>Storage.RetentionPolicy</c> section untouched.</summary>
	[Key(0)]
	public RetentionPolicyValuesDto? Policy { get; set; }

	/// <summary>Global retention windows to persist. Null leaves the corresponding
	/// <c>Storage</c> fields untouched.</summary>
	[Key(1)]
	public RetentionWindowsDto? GlobalWindows { get; set; }

	/// <summary>Per-event-code overrides to upsert. When
	/// <see cref="EventWindowsReplaceAll"/> is false these rows are merged into the existing set;
	/// when it is true the supplied list becomes the complete set and every other stored override
	/// is removed.</summary>
	[Key(2)]
	public List<EventRetentionWindowDto> EventWindows { get; set; } = new();

	/// <summary>True when <see cref="EventWindows"/> is the complete desired override set.</summary>
	[Key(3)]
	public bool EventWindowsReplaceAll { get; set; }
}
