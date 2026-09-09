/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : BlittableEquality.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage.Sharding)
// Purpose: Allocation-free structural equality and hashing for the packed, blittable shard
//          structs, so their on-disk representation is the single source of truth for equality.
// Depends: System.Runtime.InteropServices.MemoryMarshal, Crc32C
// Extends: Any new Pack=1 struct with no reference fields can opt in by implementing
//          IEquatable<T> in terms of Equals<T>/GetHashCode<T> below.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RdpAudit.Core.Storage.Sharding;

/// <summary>
/// Byte-wise equality helpers for the shard structs.
/// </summary>
/// <remarks>
/// <para>
/// Every struct that uses these helpers is declared <c>[StructLayout(Pack = 1, Size = N)]</c> and
/// contains only primitive fields. That matters: with <c>Pack = 1</c> there is no padding, so the
/// struct has no indeterminate bytes and two instances are equal exactly when their byte images
/// are equal. Comparing the raw bytes is therefore not a shortcut — it is the definition of
/// equality for a record whose identity is its on-disk form.
/// </para>
/// <para>
/// Do not use these helpers for a struct containing references, <c>bool</c>-adjacent padding, or
/// floating point fields: object identity, padding, and <c>NaN</c>/<c>-0.0</c> would all make the
/// byte image disagree with semantic equality.
/// </para>
/// </remarks>
internal static class BlittableEquality
{
	/// <summary>Compares two blittable values by their byte image.</summary>
	/// <typeparam name="T">A packed struct with no reference fields.</typeparam>
	/// <param name="left">First value.</param>
	/// <param name="right">Second value.</param>
	/// <returns><c>true</c> when the byte images are identical.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool Equals<T>(in T left, in T right)
		where T : unmanaged
		=> AsBytes(in left).SequenceEqual(AsBytes(in right));

	/// <summary>
	/// Hashes a blittable value over its byte image, consistent with <see cref="Equals{T}"/>.
	/// </summary>
	/// <typeparam name="T">A packed struct with no reference fields.</typeparam>
	/// <param name="value">Value to hash.</param>
	/// <returns>A hash code derived from the byte image.</returns>
	/// <remarks>
	/// Reuses the hardware CRC-32C path already required by the shard format instead of pulling
	/// in a second hash implementation. CRC is not a cryptographic hash, which is fine — these
	/// structs are never used as keys in an adversary-controlled dictionary.
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int GetHashCode<T>(in T value)
		where T : unmanaged
		=> unchecked((int)Crc32C.HashToUInt32(AsBytes(in value)));

	/// <summary>Reinterprets a value as its read-only byte image without copying.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ReadOnlySpan<byte> AsBytes<T>(in T value)
		where T : unmanaged
		=> MemoryMarshal.CreateReadOnlySpan(
			ref Unsafe.As<T, byte>(ref Unsafe.AsRef(in value)),
			Unsafe.SizeOf<T>());
}
