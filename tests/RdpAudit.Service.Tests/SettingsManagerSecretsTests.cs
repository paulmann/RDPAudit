// File:    tests/RdpAudit.Service.Tests/SettingsManagerSecretsTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Tests that SettingsManager wraps secret fields (AbuseIpDb.ApiKey, MikroTik.Password) with
//          ISecretProtector before persistence. The plaintext value must never appear in the saved
//          appsettings.json document.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Security;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Tests that SettingsManager DPAPI-wraps secret fields before persisting appsettings.json.</summary>
public class SettingsManagerSecretsTests
{
	private static string CreateTempPath()
	{
		string dir = Path.Combine(Path.GetTempPath(), "RdpAuditSettingsTests", Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(dir);
		return Path.Combine(dir, "appsettings.json");
	}

	[Fact]
	public void Save_ProtectsAbuseIpDbApiKey_BeforePersistence()
	{
		string targetPath = CreateTempPath();
		string json = """
		{
			"RdpAudit": {
				"AbuseIpDb": { "Enabled": true, "ApiKey": "PLAINTEXT_KEY_VALUE_xyz_TEST" },
				"Storage": { "DatabasePath": "" }
			}
		}
		""";

		InMemorySecretProtector protector = new();
		SettingsManager mgr = new(NullLogger<SettingsManager>.Instance, protector, targetPath);

		try
		{
			mgr.Save(json);

			string persisted = File.ReadAllText(targetPath);
			Assert.DoesNotContain("PLAINTEXT_KEY_VALUE_xyz_TEST", persisted, StringComparison.Ordinal);
			Assert.Contains("$protected", persisted, StringComparison.Ordinal);
		}
		finally
		{
			try
			{
				string? dir = Path.GetDirectoryName(targetPath);
				if (dir is not null && Directory.Exists(dir))
				{
					Directory.Delete(dir, recursive: true);
				}
			}
			catch
			{
				// best effort.
			}
		}
	}

	[Fact]
	public void Save_DoesNotReWrapEnvelope()
	{
		InMemorySecretProtector protector = new();
		string envelope = protector.Protect("seed-secret");

		string envelopeAsJsonString = JsonSerializer.Serialize(envelope);
		string json = "{ \"RdpAudit\": { \"AbuseIpDb\": { \"Enabled\": true, \"ApiKey\": "
			+ envelopeAsJsonString + " } } }";

		string targetPath = CreateTempPath();
		SettingsManager mgr = new(NullLogger<SettingsManager>.Instance, protector, targetPath);

		try
		{
			mgr.Save(json);

			string persisted = File.ReadAllText(targetPath);
			Assert.Contains("$protected", persisted, StringComparison.Ordinal);

			// Extract the cipher base64 from the original envelope and confirm it is still present
			// once in the persisted document — i.e. the protector did NOT re-wrap an existing envelope.
			using JsonDocument origDoc = JsonDocument.Parse(envelope);
			string origCipher = origDoc.RootElement.GetProperty("$protected").GetString()!;
			Assert.Contains(origCipher, persisted, StringComparison.Ordinal);
			Assert.DoesNotContain("seed-secret", persisted, StringComparison.Ordinal);
		}
		finally
		{
			try
			{
				string? dir = Path.GetDirectoryName(targetPath);
				if (dir is not null && Directory.Exists(dir))
				{
					Directory.Delete(dir, recursive: true);
				}
			}
			catch
			{
				// best effort.
			}
		}
	}

	[Fact]
	public void Save_ProtectsMikroTikPassword_BeforePersistence()
	{
		string targetPath = CreateTempPath();
		string json = """
		{
			"RdpAudit": {
				"MikroTik": { "Enabled": true, "Host": "router.lab", "UserName": "u", "Password": "ROUTER_PLAINTEXT_xyz" }
			}
		}
		""";

		InMemorySecretProtector protector = new();
		SettingsManager mgr = new(NullLogger<SettingsManager>.Instance, protector, targetPath);

		try
		{
			mgr.Save(json);

			string persisted = File.ReadAllText(targetPath);
			Assert.DoesNotContain("ROUTER_PLAINTEXT_xyz", persisted, StringComparison.Ordinal);
			Assert.Contains("$protected", persisted, StringComparison.Ordinal);
		}
		finally
		{
			try
			{
				string? dir = Path.GetDirectoryName(targetPath);
				if (dir is not null && Directory.Exists(dir))
				{
					Directory.Delete(dir, recursive: true);
				}
			}
			catch
			{
				// best effort.
			}
		}
	}

	[Fact]
	public void Save_MaskPlaceholder_PreservesExistingEnvelope()
	{
		// First save wraps a real key; second save sends the mask sentinel ("***configured***"),
		// which must resolve back to the stored envelope rather than wipe or re-wrap it.
		string targetPath = CreateTempPath();
		InMemorySecretProtector protector = new();
		SettingsManager mgr = new(NullLogger<SettingsManager>.Instance, protector, targetPath);

		try
		{
			string first = """
			{
				"RdpAudit": {
					"AbuseIpDb": { "Enabled": true, "ApiKey": "REAL_KEY_TO_PRESERVE" }
				}
			}
			""";
			mgr.Save(first);

			using JsonDocument afterFirst = JsonDocument.Parse(File.ReadAllText(targetPath));
			string storedEnvelope = afterFirst.RootElement
				.GetProperty("RdpAudit").GetProperty("AbuseIpDb").GetProperty("ApiKey").GetString()!;
			Assert.Contains("$protected", storedEnvelope, StringComparison.Ordinal);

			string second = """
			{
				"RdpAudit": {
					"AbuseIpDb": { "Enabled": false, "ApiKey": "***configured***" }
				}
			}
			""";
			mgr.Save(second);

			string persisted = File.ReadAllText(targetPath);
			Assert.DoesNotContain("***configured***", persisted, StringComparison.Ordinal);
			Assert.DoesNotContain("REAL_KEY_TO_PRESERVE", persisted, StringComparison.Ordinal);

			using JsonDocument afterSecond = JsonDocument.Parse(persisted);
			string preserved = afterSecond.RootElement
				.GetProperty("RdpAudit").GetProperty("AbuseIpDb").GetProperty("ApiKey").GetString()!;
			Assert.Equal(storedEnvelope, preserved);
		}
		finally
		{
			TryCleanup(targetPath);
		}
	}

	[Fact]
	public void Save_EmptyApiKey_ClearsAndDoesNotPreserve()
	{
		// An explicit empty value is a deliberate "Clear key" — it must NOT resurrect the stored key.
		string targetPath = CreateTempPath();
		InMemorySecretProtector protector = new();
		SettingsManager mgr = new(NullLogger<SettingsManager>.Instance, protector, targetPath);

		try
		{
			mgr.Save("""
			{
				"RdpAudit": {
					"AbuseIpDb": { "Enabled": true, "ApiKey": "KEY_TO_BE_CLEARED" }
				}
			}
			""");

			mgr.Save("""
			{
				"RdpAudit": {
					"AbuseIpDb": { "Enabled": false, "ApiKey": "" }
				}
			}
			""");

			string persisted = File.ReadAllText(targetPath);
			Assert.DoesNotContain("KEY_TO_BE_CLEARED", persisted, StringComparison.Ordinal);

			using JsonDocument doc = JsonDocument.Parse(persisted);
			string cleared = doc.RootElement
				.GetProperty("RdpAudit").GetProperty("AbuseIpDb").GetProperty("ApiKey").GetString()!;
			Assert.Equal(string.Empty, cleared);
		}
		finally
		{
			TryCleanup(targetPath);
		}
	}

	private static void TryCleanup(string targetPath)
	{
		try
		{
			string? dir = Path.GetDirectoryName(targetPath);
			if (dir is not null && Directory.Exists(dir))
			{
				Directory.Delete(dir, recursive: true);
			}
		}
		catch
		{
			// best effort.
		}
	}

	[Fact]
	public void Save_NoSecretProtector_LeavesPlaintextWithWarning()
	{
		// Without an ISecretProtector, the manager should leave the field as-is (the operator was
		// warned at runtime). This is a degraded path for non-Windows CI hosts; the production
		// service registers DPAPI on Windows.
		string targetPath = CreateTempPath();
		string json = """
		{
			"RdpAudit": {
				"AbuseIpDb": { "Enabled": true, "ApiKey": "PLAINTEXT_FALLBACK" }
			}
		}
		""";

		SettingsManager mgr = new(NullLogger<SettingsManager>.Instance, protector: null, overridePath: targetPath);

		try
		{
			mgr.Save(json);

			string persisted = File.ReadAllText(targetPath);
			Assert.Contains("PLAINTEXT_FALLBACK", persisted, StringComparison.Ordinal);
		}
		finally
		{
			try
			{
				string? dir = Path.GetDirectoryName(targetPath);
				if (dir is not null && Directory.Exists(dir))
				{
					Directory.Delete(dir, recursive: true);
				}
			}
			catch
			{
				// best effort.
			}
		}
	}
}
