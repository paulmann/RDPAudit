/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : LedgerChainHasher.cs
// Project: RdpAudit.Core (RdpAudit.Core.Integrity)
// Purpose: The canonical, deterministic hash of one EventDeletionLedger row and of its link to the row
//          before it. It lives in Core as a pure function so the writer (Service) and the verifier
//          (Service, Configurator, tests) cannot disagree about what a row's hash is - a chain whose two
//          ends compute different hashes is worse than no chain, because it reports tampering that never
//          happened.
//          Two properties are load-bearing:
//          1. The hash covers the row's CONTENT plus the previous entry's hash, and NOT the row id, so a
//             hash can be computed before the row exists (SQLite assigns the id) while a reordered or
//             deleted row still breaks the chain, because the successor's stored PreviousHash no longer
//             matches the hash of its actual predecessor.
//          2. DateTimes are formatted WITHOUT any kind suffix. SQLite stores them as wall-clock text, so a
//             value written as Utc reads back as Unspecified; including the kind would make every stored
//             row fail verification after a restart.
//          Honest limitation, stated because it matters: this is an unkeyed hash chain. It detects
//          modification, deletion and reordering by anything that does not recompute the chain, which is
//          the realistic threat for an offline store. It does NOT resist an attacker who can rewrite the
//          whole chain, because the only place to keep a key on this host is the host itself.
// Depends: System.Security.Cryptography
// Extends: If a keyed variant is ever needed, add it as a NEW algorithm identifier rather than changing
//          this one, and record the identifier per row.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace RdpAudit.Core.Integrity;

/// <summary>The content of one ledger row, as the hash chain sees it. A struct rather than the entity so a
/// test can build the exact input without constructing an EF-tracked object.</summary>
public readonly record struct LedgerChainEntry(
	int EventCode,
	int Scope,
	byte[]? IpBinary16,
	DateTime WindowStartUtc,
	DateTime WindowEndUtc,
	long RowsDeleted,
	int Trigger,
	int RuleVersion,
	string Reason,
	string InitiatedBy,
	DateTime CreatedUtc);

/// <summary>Computes and validates the SHA-256 chain over <c>EventDeletionLedger</c> rows.</summary>
public static class LedgerChainHasher
{
	/// <summary>Length of a hash in hex characters (SHA-256).</summary>
	public const int HashHexLength = 64;

	/// <summary>The <c>PreviousHash</c> of the first chained entry: 64 zeros. A literal genesis value
	/// rather than an empty string keeps "the chain starts here" distinguishable from "the column was
	/// not filled in" (which is a null).</summary>
	public static readonly string GenesisPreviousHash = new('0', HashHexLength);

	/// <summary>Field separator. A unit separator cannot occur in a reason string typed by an operator
	/// without being escaped by every JSON/CSV layer, so it cannot be used to make two different rows
	/// hash to the same value by shifting a boundary between fields.</summary>
	private const char FieldSeparator = '\u001f';

	/// <summary>Formats a timestamp for hashing: wall-clock digits only, invariant, fixed width. See the
	/// file header for why the kind must not appear.</summary>
	public static string FormatTimestamp(DateTime value)
		=> value.ToString("yyyy-MM-ddTHH:mm:ss.FFFFFFF", CultureInfo.InvariantCulture);

	/// <summary>Returns the canonical text a row hashes over. Exposed for diagnostics and for tests that
	/// need to show exactly which bytes a mismatch covered.</summary>
	public static string Canonicalize(string previousHashHex, in LedgerChainEntry entry)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(previousHashHex);

		StringBuilder builder = new(256);
		builder.Append("RDPAUDIT-LEDGER-CHAIN-V1").Append(FieldSeparator);
		builder.Append(previousHashHex.ToLowerInvariant()).Append(FieldSeparator);
		builder.Append(entry.EventCode.ToString(CultureInfo.InvariantCulture)).Append(FieldSeparator);
		builder.Append(entry.Scope.ToString(CultureInfo.InvariantCulture)).Append(FieldSeparator);
		builder.Append(entry.IpBinary16 is { Length: > 0 } ? Convert.ToHexString(entry.IpBinary16).ToLowerInvariant() : "null")
			.Append(FieldSeparator);
		builder.Append(FormatTimestamp(entry.WindowStartUtc)).Append(FieldSeparator);
		builder.Append(FormatTimestamp(entry.WindowEndUtc)).Append(FieldSeparator);
		builder.Append(entry.RowsDeleted.ToString(CultureInfo.InvariantCulture)).Append(FieldSeparator);
		builder.Append(entry.Trigger.ToString(CultureInfo.InvariantCulture)).Append(FieldSeparator);
		builder.Append(entry.RuleVersion.ToString(CultureInfo.InvariantCulture)).Append(FieldSeparator);
		builder.Append(entry.Reason ?? string.Empty).Append(FieldSeparator);
		builder.Append(entry.InitiatedBy ?? string.Empty).Append(FieldSeparator);
		builder.Append(FormatTimestamp(entry.CreatedUtc));
		return builder.ToString();
	}

	/// <summary>Lower-case hex SHA-256 of <paramref name="previousHashHex"/> plus the row content.</summary>
	public static string ComputeEntryHash(string previousHashHex, in LedgerChainEntry entry)
	{
		string canonical = Canonicalize(previousHashHex, entry);
		byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
		return Convert.ToHexString(digest).ToLowerInvariant();
	}

	/// <summary>True when <paramref name="value"/> looks like a hash this class produced: 64 hex
	/// characters. Used by the verifier to tell a malformed link (an operator editing the column to
	/// something plausible) apart from a legitimate one.</summary>
	public static bool IsHashShaped(string? value)
	{
		if (value is not { Length: HashHexLength })
		{
			return false;
		}

		foreach (char character in value)
		{
			bool isHex = (character >= '0' && character <= '9')
				|| (character >= 'a' && character <= 'f')
				|| (character >= 'A' && character <= 'F');
			if (!isHex)
			{
				return false;
			}
		}

		return true;
	}
}
