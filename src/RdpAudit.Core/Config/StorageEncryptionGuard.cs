/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StorageEncryptionGuard.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Fail-closed start-up validation for the encryption-at-rest setting. Its only job is to make it
//          impossible for the service to run with a configuration that CLAIMS the store is encrypted while
//          the store is plain text: the operator gets an explicit refusal naming the mode, the reason and the
//          decision record, instead of a running service with a false assurance in its own settings file.
//          The guard is deliberately dumb and total - a switch over every defined mode, so adding a mode
//          without deciding how it is enforced is a compile-time prompt rather than a silent gap.
// Depends: StorageEncryptionOptions
// Extends: When a mode becomes implemented, change its case here in the same commit that implements it.

using System.Globalization;

namespace RdpAudit.Core.Config;

/// <summary>Thrown when the configured encryption-at-rest mode cannot be honoured by this build.</summary>
public sealed class StorageEncryptionNotSupportedException : Exception
{
	/// <summary>Creates the exception for the refused mode.</summary>
	public StorageEncryptionNotSupportedException(StorageEncryptionMode mode, string message)
		: base(message)
		=> Mode = mode;

	/// <summary>The mode that was refused.</summary>
	public StorageEncryptionMode Mode { get; }
}

/// <summary>Refuses to start a configuration whose encryption-at-rest claim this build cannot honour.</summary>
public static class StorageEncryptionGuard
{
	/// <summary>Verifies the requested mode. Returns a warning string when the mode is honoured but carries a
	/// consequence the operator should see; throws
	/// <see cref="StorageEncryptionNotSupportedException"/> when it cannot be honoured.</summary>
	public static string? AssertSupported(StorageEncryptionOptions? options)
	{
		if (options is null)
		{
			return null;
		}

		StorageEncryptionMode mode = options.ResolveMode();
		switch (mode)
		{
			case StorageEncryptionMode.None:
				return null;

			case StorageEncryptionMode.VolumeManaged:
				// Honoured by definition - the volume does the work - but the product cannot verify that the
				// volume is actually encrypted, so the honest statement is a warning, not a confirmation.
				return
					"Storage:Encryption:Mode=VolumeManaged: the product performs no encryption of its own and "
					+ "cannot verify the volume's state. Confirm out of band that the volume holding the database "
					+ "and the actions folder is genuinely encrypted (BitLocker / hardware), because this setting "
					+ "is an operator assertion, not a guarantee. See docs/89-encryption-at-rest-decision.md.";

			case StorageEncryptionMode.SqlCipher:
				throw new StorageEncryptionNotSupportedException(
					StorageEncryptionMode.SqlCipher,
					"Storage:Encryption:Mode=SqlCipher is not implemented in this build, so the service refuses "
					+ "to start rather than run with plain-text files under a setting that says they are "
					+ "encrypted. Set the mode to None (default) or VolumeManaged, or deploy a build that "
					+ "implements SQLCipher. The decision record and the intended key handling are in "
					+ "docs/89-encryption-at-rest-decision.md.");

			default:
				throw new StorageEncryptionNotSupportedException(
					mode,
					string.Format(
						CultureInfo.InvariantCulture,
						"Storage:Encryption:Mode has the unknown value {0}. Refusing to start rather than guess "
							+ "whether the evidence store is encrypted. Valid values: None, VolumeManaged, SqlCipher.",
						(int)options.Mode));
		}
	}
}
