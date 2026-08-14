/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpcDispatcherEventCollectionTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Verifies catalog-backed Event Collection IPC reads, writes, presets, idempotency, and forever retention.
// Depends: IpcDispatcher, AuditDbContext, EventCatalog, SQLite, xUnit
// Extends: Add persisted setting assertions here when Event Collection IPC gains a new mutable catalog property.

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcDispatcherEventCollectionTests
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

	private static IpcDispatcher CreateDispatcher(IDbContextFactory<AuditDbContext> factory)
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
			new SettingsManager(NullLogger<SettingsManager>.Instance),
			new FirewallManager(NullLogger<FirewallManager>.Instance),
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance);
	}

	private static async Task<List<EventCollectionSettingsDto>> ReadSettingsAsync(IpcDispatcher dispatcher)
	{
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetEventCollectionSettings },
			CancellationToken.None);

		Assert.True(response.Success);
		Assert.NotNull(response.Payload);
		List<EventCollectionSettingsDto>? settings = JsonSerializer.Deserialize<List<EventCollectionSettingsDto>>(
			response.Payload,
			JsonOptions.Default);
		Assert.NotNull(settings);
		return settings;
	}

	private static async Task<List<EventCollectionSettingsDto>> SaveAsync(
		IpcDispatcher dispatcher,
		EventCollectionMutationRequest request)
	{
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.SaveEventCollectionSettings,
				Payload = JsonSerializer.Serialize(request, JsonOptions.Default),
			},
			CancellationToken.None);

		Assert.True(response.Success);
		Assert.NotNull(response.Payload);
		List<EventCollectionSettingsDto>? settings = JsonSerializer.Deserialize<List<EventCollectionSettingsDto>>(
			response.Payload,
			JsonOptions.Default);
		Assert.NotNull(settings);
		return settings;
	}

	[Fact]
	public async Task GetEventCollectionSettings_ReturnsEveryCatalogEventWithDefaults()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDatabaseAsync();
		try
		{
			List<EventCollectionSettingsDto> settings = await ReadSettingsAsync(CreateDispatcher(factory));

			Assert.Equal(EventCatalog.All.Count, settings.Count);
			EventDescriptor descriptor = EventCatalog.All[0];
			EventCollectionSettingsDto setting = Assert.Single(
				settings,
				row => row.EventId == descriptor.EventId);
			Assert.Equal(descriptor.Channel, setting.Channel);
			Assert.Equal(descriptor.Description, setting.DisplayName);
			Assert.Equal(descriptor.EffectivePurpose, setting.Description);
			Assert.Equal(descriptor.Criticality, setting.Criticality);
			Assert.Equal(descriptor.Layer, setting.Layer);
			Assert.Equal(descriptor.IsInPreset(EventPreset.Essential), setting.IsEnabled);
			Assert.Equal(descriptor.DefaultRetentionDays, setting.RetentionDays);
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task SaveEventCollectionSettings_PersistsEnablementAndRetention()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDatabaseAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory);
			List<EventCollectionSettingsDto> saved = await SaveAsync(
				dispatcher,
				new EventCollectionMutationRequest
				{
					Settings =
					[
						new EventCollectionSettingsDto
						{
							EventId = 4625,
							IsEnabled = false,
							RetentionDays = 91,
						},
					],
				});

			EventCollectionSettingsDto savedSetting = Assert.Single(saved, row => row.EventId == 4625);
			Assert.False(savedSetting.IsEnabled);
			Assert.Equal(91, savedSetting.RetentionDays);

			List<EventCollectionSettingsDto> reread = await ReadSettingsAsync(dispatcher);
			EventCollectionSettingsDto rereadSetting = Assert.Single(reread, row => row.EventId == 4625);
			Assert.False(rereadSetting.IsEnabled);
			Assert.Equal(91, rereadSetting.RetentionDays);
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task SaveEventCollectionSettings_RepeatedValuesAreIdempotent()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDatabaseAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory);
			EventCollectionMutationRequest request = new()
			{
				Settings =
				[
					new EventCollectionSettingsDto
					{
						EventId = 4624,
						IsEnabled = false,
						RetentionDays = 45,
					},
				],
			};

			await SaveAsync(dispatcher, request);
			long firstEnablementUpdateUtc;
			long firstRetentionUpdateUtc;
			await using (AuditDbContext firstRead = factory.CreateDbContext())
			{
				firstEnablementUpdateUtc = (await firstRead.EventEnablements.SingleAsync(row => row.EventId == 4624)).UpdatedUtc;
				firstRetentionUpdateUtc = (await firstRead.EventRetentions.SingleAsync(row => row.EventId == 4624)).UpdatedUtc;
			}

			await SaveAsync(dispatcher, request);
			await using (AuditDbContext secondRead = factory.CreateDbContext())
			{
				Assert.Equal(1, await secondRead.EventEnablements.CountAsync(row => row.EventId == 4624));
				Assert.Equal(1, await secondRead.EventRetentions.CountAsync(row => row.EventId == 4624));
				Assert.Equal(firstEnablementUpdateUtc, (await secondRead.EventEnablements.SingleAsync(row => row.EventId == 4624)).UpdatedUtc);
				Assert.Equal(firstRetentionUpdateUtc, (await secondRead.EventRetentions.SingleAsync(row => row.EventId == 4624)).UpdatedUtc);
			}
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task SaveEventCollectionSettings_PresetEnablesExpandedCatalogSet()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDatabaseAsync();
		try
		{
			List<EventCollectionSettingsDto> saved = await SaveAsync(
				CreateDispatcher(factory),
				new EventCollectionMutationRequest { Preset = EventPreset.Minimal });
			HashSet<int> expectedEnabled = new(EventCatalog.ExpandPreset(EventPreset.Minimal));

			foreach (EventCollectionSettingsDto setting in saved)
			{
				Assert.Equal(expectedEnabled.Contains(setting.EventId), setting.IsEnabled);
			}
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task SaveEventCollectionSettings_ZeroRetentionMeansRetainForever()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDatabaseAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory);
			List<EventCollectionSettingsDto> saved = await SaveAsync(
				dispatcher,
				new EventCollectionMutationRequest
				{
					Settings =
					[
						new EventCollectionSettingsDto
						{
							EventId = 4719,
							IsEnabled = true,
							RetentionDays = 0,
						},
					],
				});

			Assert.Equal(0, Assert.Single(saved, row => row.EventId == 4719).RetentionDays);
			await using AuditDbContext db = factory.CreateDbContext();
			EventRetention retention = await db.EventRetentions.SingleAsync(row => row.EventId == 4719);
			Assert.Equal(0, retention.RetentionDays);
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}
}
