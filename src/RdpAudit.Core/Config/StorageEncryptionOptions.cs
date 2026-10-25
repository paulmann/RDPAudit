/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StorageEncryptionOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: The configuration seam for encryption at rest: the option exists, is validated, and fails closed,
//          but NO data is encrypted in this iteration. The decision record is
//          docs/89-encryption-at-rest-decision.md; this file holds only what the runtime needs to behave
//          honestly in the meantime.
//          "Honest" means two things here. First, the default is None, so an existing installation behaves
//          exactly as before. Second, selecting an encryption mode that is not implemented REFUSES TO START
//          with an actionable message instead of starting up with plain-text files under a setting that says
//          the store is encrypted - a silent downgrade on a setting named "encryption" is the worst possible
//          failure mode for this particular option.
// Depends: none
// Extends: When an implementation lands, add its mode here, implement it in the database/shape layer, and
//          keep the fail-closed check for every mode that is still unimplemented.

using System.Globalization;

namespace RdpAudit.Core.Config;

/// <summary>How the evidence store is protected at rest.</summary>
public enum StorageEncryptionMode
{
	/// <summary>No encryption. Today's behaviour and the default: the database, its WAL/SHM sidecars and the
	/// shard tree are plain files protected by file ACLs only.</summary>
	None = 0,

	/// <summary>Encryption provided by the volume (BitLocker / a hardware-encrypted volume). The product
	/// needs no key handling of its own; the operational consequence is that the protection disappears
	/// whenever the volume is mounted unlocked, which the decision record states explicitly.</summary>
	VolumeManaged = 1,

	/// <summary>Page-level encryption by SQLCipher, keyed through the existing <c>ISecretProtector</c>
	/// abstraction (DPAPI machine scope / TPM). NOT IMPLEMENTED YET: selecting it refuses to start.</summary>
	SqlCipher = 2,
}

/// <summary>Encryption-at-rest configuration seam. No encryption is performed in this iteration.</summary>
public sealed class StorageEncryptionOptions
{
	/// <summary>Requested mode. Defaults to <see cref="StorageEncryptionMode.None"/>.</summary>
	public StorageEncryptionMode Mode { get; set; } = StorageEncryptionMode.None;

	/// <summary>Name of the secret (in the existing secret store) that would hold the database key. Empty
	/// means "not configured". No key material ever lives in appsettings.json: this is a NAME, resolved
	/// through <c>ISecretProtector</c>/DPAPI machine scope at start-up, exactly like the API keys.</summary>
	public string KeySecretName { get; set; } = string.Empty;

	/// <summary>Requested key-rotation interval in days; zero means "no scheduled rotation". Recorded in the
	/// decision record as the rotation plan; unused until a mode is implemented.</summary>
	public int KeyRotationDays { get; set; }

	/// <summary>True when the configured mode encrypts nothing, i.e. the store is plain text.</summary>
	public bool IsEffectivelyUnencrypted => ResolveMode() == StorageEncryptionMode.None;

	/// <summary>Returns <see cref="Mode"/>, falling back to <see cref="StorageEncryptionMode.None"/> only for
	/// a value that is not a defined member - and the guard below refuses anything that is not None, so an
	/// out-of-range numeric override cannot silently select "no encryption".</summary>
	public StorageEncryptionMode ResolveMode() => Enum.IsDefined(Mode) ? Mode : (StorageEncryptionMode)(-1);

	/// <summary>Human-readable summary for operator logs. Never contains key material.</summary>
	public string Describe()
		=> string.Create(
			CultureInfo.InvariantCulture,
			$"Mode={Mode} KeyConfigured={!string.IsNullOrWhiteSpace(KeySecretName)} KeyRotationDays={KeyRotationDays}");
}
