/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : EditionInfoDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Read-only description of the running build: edition, ordinal, product version, licence, the
//          capability matrix as this build sees it, and the cross-host host budget. Backs the
//          GetEditionInfo IPC command (ordinal 102), so an operator can tell a Community binary from a
//          Pro one without reading the executable's file properties.
// Depends: MessagePack
// Extends: Append new members at the END with the next free MessagePack key; never renumber.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Edition, licence and capability matrix of the running build.</summary>
/// <remarks>MessagePack keys are append-only: add new members at the end with the next free key.</remarks>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class EditionInfoDto
{
	/// <summary>Outcome discriminator for the read itself.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Edition name of this build ("Community", "Pro", "Enterprise").</summary>
	[Key(1)]
	public string Edition { get; set; } = string.Empty;

	/// <summary>Edition ordinal (append-only; see <c>ProductEdition</c>).</summary>
	[Key(2)]
	public int EditionOrdinal { get; set; }

	/// <summary>Informational product version of this build, including the build SHA when present.</summary>
	[Key(3)]
	public string ProductVersion { get; set; } = string.Empty;

	/// <summary>Licence the build is distributed under.</summary>
	[Key(4)]
	public string License { get; set; } = string.Empty;

	/// <summary>Every capability the product knows, with the minimum edition and its availability here.</summary>
	[Key(5)]
	public List<EditionFeatureDto> Features { get; set; } = new();

	/// <summary>Maximum number of cross-host correlation hosts this build may poll; zero means the
	/// feature is absent from the build.</summary>
	[Key(6)]
	public int MaxCrossHostHosts { get; set; }

	/// <summary>Operator-facing summary line.</summary>
	[Key(7)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Name of the compilation constant that produced this build, so a mislabelled package is
	/// visible instead of assumed.</summary>
	[Key(8)]
	public string BuildConstant { get; set; } = string.Empty;
}

/// <summary>One row of the capability matrix as the running build reports it.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class EditionFeatureDto
{
	/// <summary>Feature name (enum member name).</summary>
	[Key(0)]
	public string Feature { get; set; } = string.Empty;

	/// <summary>Lowest edition that contains the feature.</summary>
	[Key(1)]
	public string MinimumEdition { get; set; } = string.Empty;

	/// <summary>True when this build contains the feature.</summary>
	[Key(2)]
	public bool Available { get; set; }
}
