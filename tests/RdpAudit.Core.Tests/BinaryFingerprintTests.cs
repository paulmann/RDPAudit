// File:    tests/RdpAudit.Core.Tests/BinaryFingerprintTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 2 — locks the equality semantics of BinaryFingerprint, which the Service
//          tab uses to decide whether installed and distribution binaries are the same
//          content. Hash, length, file version, and product version must all match for the
//          fingerprints to be considered identical; last-write-time is informational only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class BinaryFingerprintTests
{
	private static BinaryFingerprint Make(
		string path = @"C:\test\RdpAudit.Service.exe",
		bool exists = true,
		string? fileVersion = "1.2.0.0",
		string? productVersion = "1.2.0",
		long length = 1024,
		string? sha = "DEADBEEFCAFEBABE",
		DateTime? lastWrite = null) =>
		new(
			Path: path,
			Exists: exists,
			FileVersion: exists ? fileVersion : null,
			ProductVersion: exists ? productVersion : null,
			Length: exists ? length : 0,
			LastWriteTimeUtc: exists ? (lastWrite ?? new DateTime(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc)) : null,
			Sha256: exists ? sha : null);

	[Fact]
	public void IdenticalFields_AreContentIdentical()
	{
		BinaryFingerprint a = Make();
		BinaryFingerprint b = Make(lastWrite: new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
		Assert.True(a.IsContentIdentical(b));
		Assert.True(b.IsContentIdentical(a));
	}

	[Fact]
	public void DifferentSha_IsNotIdentical()
	{
		BinaryFingerprint a = Make(sha: "AAAA");
		BinaryFingerprint b = Make(sha: "BBBB");
		Assert.False(a.IsContentIdentical(b));
	}

	[Fact]
	public void DifferentLength_IsNotIdentical()
	{
		BinaryFingerprint a = Make(length: 1024);
		BinaryFingerprint b = Make(length: 2048);
		Assert.False(a.IsContentIdentical(b));
	}

	[Fact]
	public void DifferentFileVersion_IsNotIdentical()
	{
		BinaryFingerprint a = Make(fileVersion: "1.0.0.0");
		BinaryFingerprint b = Make(fileVersion: "1.2.0.0");
		Assert.False(a.IsContentIdentical(b));
	}

	[Fact]
	public void DifferentProductVersion_IsNotIdentical()
	{
		BinaryFingerprint a = Make(productVersion: "1.0.0");
		BinaryFingerprint b = Make(productVersion: "1.2.0");
		Assert.False(a.IsContentIdentical(b));
	}

	[Fact]
	public void MissingFile_IsNeverIdentical()
	{
		BinaryFingerprint missing = Make(exists: false);
		BinaryFingerprint present = Make();
		Assert.False(missing.IsContentIdentical(present));
		Assert.False(present.IsContentIdentical(missing));
		Assert.False(missing.IsContentIdentical(missing));
	}

	[Fact]
	public void NullOther_IsNotIdentical()
	{
		Assert.False(Make().IsContentIdentical(null));
	}
}
