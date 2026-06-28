// File:    src/RdpAudit.Configurator/Services/ReadOnlyDb.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Optional read-only DB helper. The Configurator UI now reads events / alerts /
//          addresses / sessions over IPC; this helper remains for diagnostic tooling and
//          honours the configured Storage.DatabasePath (no hard-coded ProgramData path).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;

namespace RdpAudit.Configurator.Services;

/// <summary>Optional read-only DB helper that honours the service-configured database path.</summary>
public static class ReadOnlyDb
{
	public static AuditDbContext Open()
	{
		string dbPath = ResolveDatabasePath();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite($"Data Source={dbPath};Mode=ReadOnly;Cache=Shared")
			.Options;
		return new AuditDbContext(options);
	}

	public static string DatabasePath => ResolveDatabasePath();

	/// <summary>Honour Storage.DatabasePath from appsettings.json; fall back to the ProgramData default.</summary>
	private static string ResolveDatabasePath()
	{
		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string appsettings = Path.Combine(programData, "RdpAudit", "appsettings.json");
		string fallback = Path.Combine(programData, "RdpAudit", "rdpaudit.db");

		if (!File.Exists(appsettings))
		{
			return fallback;
		}

		try
		{
			using FileStream fs = File.OpenRead(appsettings);
			using JsonDocument doc = JsonDocument.Parse(fs);
			if (doc.RootElement.TryGetProperty(RdpAuditOptions.SectionName, out JsonElement section)
				&& section.TryGetProperty("Storage", out JsonElement storage)
				&& storage.TryGetProperty(nameof(StorageOptions.DatabasePath), out JsonElement v)
				&& v.ValueKind == JsonValueKind.String)
			{
				string? value = v.GetString();
				if (!string.IsNullOrWhiteSpace(value))
				{
					return value;
				}
			}
		}
		catch
		{
			// Best-effort — fallback to default.
		}

		return fallback;
	}
}
