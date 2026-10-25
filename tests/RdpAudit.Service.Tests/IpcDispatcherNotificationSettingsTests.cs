// File:    tests/RdpAudit.Service.Tests/IpcDispatcherNotificationSettingsTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Verifies Get/SaveNotificationSettings IPC 78/79: normalized defaults, clamping,
//          severity fallback, and merge-only persistence of the RdpAudit.Notifications section
//          while other sections stay untouched.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.IO;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcDispatcherNotificationSettingsTests
{
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options)
		{
			_options = options;
		}

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private static async Task<(IDbContextFactory<AuditDbContext> Factory, SqliteConnection Connection)> CreateDatabaseAsync()
	{
		SqliteConnection connection = new("DataSource=:memory:");
		await connection.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		await using (AuditDbContext db = new(options))
		{
			await db.Database.EnsureCreatedAsync();
		}

		return (new TestDbContextFactory(options), connection);
	}

	private static IpcDispatcher CreateDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		string settingsPath)
	{
		OptionsFactory<RdpAuditOptions> optionsFactory = new(
			Array.Empty<IConfigureOptions<RdpAuditOptions>>(),
			Array.Empty<IPostConfigureOptions<RdpAuditOptions>>(),
			Array.Empty<IValidateOptions<RdpAuditOptions>>());
		IOptionsMonitor<RdpAuditOptions> optionsMonitor = new OptionsMonitor<RdpAuditOptions>(
			optionsFactory,
			Array.Empty<IOptionsChangeTokenSource<RdpAuditOptions>>(),
			new OptionsCache<RdpAuditOptions>());
		return new IpcDispatcher(
			factory,
			new ServiceMetrics(),
			optionsMonitor,
			new SettingsManager(NullLogger<SettingsManager>.Instance, protector: null, overridePath: settingsPath),
			new FirewallManager(NullLogger<FirewallManager>.Instance),
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance);
	}

	private static async Task<NotificationSettingsDto> GetSettingsAsync(IpcDispatcher dispatcher)
	{
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetNotificationSettings },
			CancellationToken.None);

		Assert.True(response.Success);
		Assert.NotNull(response.Payload);
		return JsonSerializer.Deserialize<NotificationSettingsDto>(response.Payload, JsonOptions.Default)!;
	}

	private static async Task<NotificationSettingsDto> SaveAsync(
		IpcDispatcher dispatcher,
		NotificationSettingsDto request)
	{
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.SaveNotificationSettings,
				Payload = JsonSerializer.Serialize(request, JsonOptions.Default),
			},
			CancellationToken.None);

		Assert.True(response.Success);
		Assert.NotNull(response.Payload);
		return JsonSerializer.Deserialize<NotificationSettingsDto>(response.Payload, JsonOptions.Default)!;
	}

	[Fact]
	public async Task GetNotificationSettings_ReturnsDefaults()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDatabaseAsync();
		try
		{
			NotificationSettingsDto settings = await GetSettingsAsync(CreateDispatcher(factory, CreateTempPath()));

			Assert.True(settings.EnableTrayNotifier);
			Assert.True(settings.StartWithWindows);
			Assert.Equal(5, settings.PollIntervalSeconds);
			Assert.Equal("High", settings.MinimumSeverity);
			Assert.Equal(10, settings.MaxToastsPerMinute);
			Assert.False(settings.UseNativeToasts);
			Assert.Empty(settings.ShowAlerts);
			Assert.Empty(settings.ShowEvents);
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task SaveNotificationSettings_ClampsOutOfRangeValues()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDatabaseAsync();
		string path = CreateTempPath();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, path);
			NotificationSettingsDto saved = await SaveAsync(dispatcher, new NotificationSettingsDto
			{
				PollIntervalSeconds = 0,
				MaxToastsPerMinute = 999,
				MinimumSeverity = "Bogus",
			});

			Assert.Equal(NotificationOptions.MinPollIntervalSeconds, saved.PollIntervalSeconds);
			Assert.Equal(NotificationOptions.MaxMaxToastsPerMinute, saved.MaxToastsPerMinute);
			Assert.Equal("High", saved.MinimumSeverity);
		}
		finally
		{
			await connection.DisposeAsync();
			TryCleanup(path);
		}
	}

	[Fact]
	public async Task SaveNotificationSettings_RoundtripsThroughSettingsFile()
	{
		string path = CreateTempPath();
		Directory.CreateDirectory(Path.GetDirectoryName(path)!);
		File.WriteAllText(path, """
		{
			"RdpAudit": {
				"Storage": { "DatabasePath": "C:/Data/rdpaudit.db" },
				"AbuseIpDb": { "Enabled": false }
			}
		}
		""");

		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDatabaseAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, path);
			await SaveAsync(dispatcher, new NotificationSettingsDto
			{
				EnableTrayNotifier = false,
				PollIntervalSeconds = 7,
				MinimumSeverity = "Medium",
				MaxToastsPerMinute = 3,
				ShowAlerts = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
				{
					["BRUTE_FORCE"] = false,
				},
			});

			string persisted = File.ReadAllText(path);
			Assert.Contains("\"Notifications\"", persisted, StringComparison.Ordinal);
			Assert.Contains("\"DatabasePath\": \"C:/Data/rdpaudit.db\"", persisted, StringComparison.Ordinal);
			Assert.Contains("\"AbuseIpDb\"", persisted, StringComparison.Ordinal);
		}
		finally
		{
			await connection.DisposeAsync();
			TryCleanup(path);
		}
	}

	[Fact]
	public async Task SaveNotificationSettings_PreservesUnrelatedSections()
	{
		string path = CreateTempPath();
		Directory.CreateDirectory(Path.GetDirectoryName(path)!);
		File.WriteAllText(path, """
		{
			"RdpAudit": {
				"Storage": { "DatabasePath": "" },
				"MikroTik": { "Enabled": false },
				"Api": { "Port": 443 }
			}
		}
		""");

		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDatabaseAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, path);
			await SaveAsync(dispatcher, new NotificationSettingsDto { EnableTrayNotifier = false });

			string persisted = File.ReadAllText(path);
			Assert.Contains("\"MikroTik\"", persisted, StringComparison.Ordinal);
			Assert.Contains("\"Api\"", persisted, StringComparison.Ordinal);
			Assert.Contains("\"Port\": 443", persisted, StringComparison.Ordinal);
		}
		finally
		{
			await connection.DisposeAsync();
			TryCleanup(path);
		}
	}

	private static string CreateTempPath()
	{
		string dir = Path.Combine(Path.GetTempPath(), "RdpAuditNotificationSettingsTests", Guid.NewGuid().ToString("N"));
		return Path.Combine(dir, "appsettings.json");
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
}
