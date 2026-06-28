// File:    tests/RdpAudit.Core.Tests/BackupMetadataTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Round-trip serialization tests for BackupMetadata so future schema
//          additions cannot break existing snapshots silently.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Backup;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Round-trip serialization tests for BackupMetadata.</summary>
public class BackupMetadataTests
{
	[Fact]
	public void ToJson_AndFromJson_PreservesAllFields()
	{
		BackupMetadata original = new()
		{
			SchemaVersion = 1,
			CreatedUtc = new DateTime(2026, 5, 19, 10, 30, 45, DateTimeKind.Utc),
			SnapshotId = "20260519-103045",
			MachineName = "TESTHOST",
			UserName = @"TESTHOST\admin",
			OsDescription = "Microsoft Windows 10.0.22631",
			ProductVersion = "1.2.3",
			Reason = "manual",
			IncludesAppSettings = true,
			IncludesAuditPolicy = true,
			IncludesRegistry = true,
			IncludesServiceConfig = false,
			Redactions = new[] { "no secrets in current schema" },
			AuditPolicyGuids = new[] { "{0CCE9215-69AE-11D9-BED3-505054503030}" },
			RegistryKeys = new[] { @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa" },
		};

		string json = original.ToJson();
		Assert.Contains("20260519-103045", json, StringComparison.Ordinal);

		BackupMetadata copy = BackupMetadata.FromJson(json);
		Assert.Equal(original.SchemaVersion, copy.SchemaVersion);
		Assert.Equal(original.CreatedUtc, copy.CreatedUtc);
		Assert.Equal(original.SnapshotId, copy.SnapshotId);
		Assert.Equal(original.MachineName, copy.MachineName);
		Assert.Equal(original.UserName, copy.UserName);
		Assert.Equal(original.OsDescription, copy.OsDescription);
		Assert.Equal(original.ProductVersion, copy.ProductVersion);
		Assert.Equal(original.Reason, copy.Reason);
		Assert.Equal(original.IncludesAppSettings, copy.IncludesAppSettings);
		Assert.Equal(original.IncludesAuditPolicy, copy.IncludesAuditPolicy);
		Assert.Equal(original.IncludesRegistry, copy.IncludesRegistry);
		Assert.Equal(original.IncludesServiceConfig, copy.IncludesServiceConfig);
		Assert.Equal(original.Redactions, copy.Redactions);
		Assert.Equal(original.AuditPolicyGuids, copy.AuditPolicyGuids);
		Assert.Equal(original.RegistryKeys, copy.RegistryKeys);
	}

	[Fact]
	public void FromJson_NullOrEmpty_Throws()
	{
		Assert.Throws<ArgumentException>(() => BackupMetadata.FromJson(""));
	}
}
