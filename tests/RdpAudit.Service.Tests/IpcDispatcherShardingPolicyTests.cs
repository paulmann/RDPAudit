/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpcDispatcherShardingPolicyTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Verifies the Stage 4 shard-governance IPC surface (ordinals 91-92) through the real
//          dispatcher: SaveShardingPolicy validates and clamps the whole request before writing,
//          refuses a structurally invalid request without touching the settings document, reports the
//          effective policy back through the live options monitor and audits the change with the
//          invoking identity; CollectShardGarbage defaults to a dry run, deletes nothing on one, and on
//          an apply pass removes only the orphans it can prove and names every path it deleted.
// Depends: IpcDispatcher, ShardingPolicyService, ShardGarbageCollectorService, ShardInventoryService
// Extends: Add a case here for every new field or safety rule the two commands gain.

using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using RdpAudit.Service.Storage;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcDispatcherShardingPolicyTests : IDisposable
{
	private readonly SqliteConnection _connection = new("DataSource=:memory:");
	private readonly string _directory = Path.Combine(Path.GetTempPath(), "rdpaudit-shard-ipc-" + Guid.NewGuid().ToString("N"));
	private readonly string _settingsPath;
	private readonly string _actionsRoot;

	public IpcDispatcherShardingPolicyTests()
	{
		Directory.CreateDirectory(_directory);
		_actionsRoot = Path.Combine(_directory, ShardPath.ActionsRootFolder);
		Directory.CreateDirectory(_actionsRoot);
		_settingsPath = Path.Combine(_directory, "appsettings.json");
		File.WriteAllText(_settingsPath, $$"""
			{
				"RdpAudit": {
					"Storage": { "DatabasePath": "{{Path.Combine(_directory, "rdpaudit.db").Replace("\\", "\\\\")}}" },
					"Sharding": {
						"Enabled": false,
						"ActionsRoot": "{{_actionsRoot.Replace("\\", "\\\\")}}",
						"ShardCapacityRecords": 16,
						"MaxOpenWriters": 8,
						"MaxShardFiles": 64,
						"MaxShardBytes": 0,
						"MaxTotalShardBytes": 0,
						"MinFreeDiskBytes": 0,
						"OrphanGraceDays": 14,
						"SubnetAggregation": {
							"Enabled": false,
							"TotalFileThreshold": 4096,
							"NewFilesPerIntervalLimit": 64,
							"IntervalSeconds": 60,
							"MinSourceRowsPerInterval": 8
						}
					}
				}
			}
			""");

		_connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(_connection).Options;
		using AuditDbContext context = new(options);
		context.Database.EnsureCreated();
	}

	public void Dispose()
	{
		_connection.Dispose();
		SqliteConnection.ClearAllPools();
		try { Directory.Delete(_directory, recursive: true); }
		catch (IOException) { }
		catch (UnauthorizedAccessException) { }
	}

	// ── Reading the policy through the inventory ────────────────────────────────

	/// <summary>Given a shard tree, when the operator reads the inventory, then the effective shard
	/// policy and its bounds come back with it - no separate command is needed - and the live capacity
	/// state of the sink is reported alongside.</summary>
	[Fact]
	public async Task GetShardInventory_ReportsTheEffectivePolicyAndCapacityState()
	{
		ShardIngestionSink sink = CreateSink();
		IpcDispatcher dispatcher = CreateDispatcher(sink: sink);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetShardInventory },
			CancellationToken.None);

		Assert.True(response.Success, response.Error);
		ShardInventoryDto dto = Deserialize<ShardInventoryDto>(response);
		Assert.NotNull(dto.Policy);
		Assert.Equal(16, dto.Policy!.Policy.ShardCapacityRecords);
		Assert.Equal(16, dto.Policy.Policy.EffectiveRingCapacityRecords);
		Assert.Equal(14, dto.Policy.Policy.EffectiveOrphanGraceDays);
		Assert.True(dto.Policy.Bounds.MinShardCapacityRecords >= 1);
		Assert.True(dto.Policy.HotReloaded);
		Assert.NotNull(dto.CapacityStatus);
		Assert.False(dto.CapacityStatus!.RefusalActive);
		Assert.False(dto.CapacityStatus.CardinalityGuardEnabled);
	}

	/// <summary>Given a host with no shard sink at all, when the inventory is read, then the capacity
	/// state is absent instead of being reported as a healthy zero.</summary>
	[Fact]
	public async Task GetShardInventory_WithoutASink_ReportsAbsentCapacityState()
	{
		IpcDispatcher dispatcher = CreateDispatcher(sink: null);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetShardInventory },
			CancellationToken.None);

		ShardInventoryDto dto = Deserialize<ShardInventoryDto>(response);
		Assert.Null(dto.CapacityStatus);
		Assert.NotNull(dto.Policy);
	}

	// ── SaveShardingPolicy (91) ─────────────────────────────────────────────────

	/// <summary>Given a valid policy request, when it is saved, then the settings document carries the
	/// new values, the response reports them as effective (the change is live), and one audit row names
	/// the invoking identity and the old and new policy.</summary>
	[Fact]
	public async Task SaveShardingPolicy_WritesTheDocumentAndAuditsTheChange()
	{
		RecordingOperationLogWriter audit = new();
		IpcDispatcher dispatcher = CreateDispatcher(sink: CreateSink(), audit: audit);
		ShardingPolicyMutationRequest request = new()
		{
			Enabled = true,
			ActionsRoot = _actionsRoot,
			ShardCapacityRecords = 32,
			MaxOpenWriters = 4,
			MaxShardFiles = 128,
			MaxShardBytes = 4096,
			MaxTotalShardBytes = 1_048_576,
			MinFreeDiskBytes = 524_288,
			OrphanGraceDays = 21,
			SubnetAggregation = new SubnetAggregationMutationDto
			{
				Enabled = true,
				TotalFileThreshold = 100,
				NewFilesPerIntervalLimit = 10,
				IntervalSeconds = 30,
				MinSourceRowsPerInterval = 4,
			},
		};

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.SaveShardingPolicy, Payload = JsonSerializer.Serialize(request, JsonOptions.Default) },
			CancellationToken.None,
			callerIdentity: "TEST\\operator");

		Assert.True(response.Success, response.Error);
		ShardingPolicyDto dto = Deserialize<ShardingPolicyDto>(response);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.True(dto.HotReloaded);
		Assert.True(dto.Policy.Enabled);
		Assert.Equal(32, dto.Policy.ShardCapacityRecords);
		Assert.Equal(32, dto.Policy.EffectiveRingCapacityRecords);
		Assert.Equal(4096L, dto.Policy.MaxShardBytes);
		Assert.Equal(1_048_576L, dto.Policy.MaxTotalShardBytes);
		Assert.Equal(524_288L, dto.Policy.MinFreeDiskBytes);
		Assert.Equal(21, dto.Policy.OrphanGraceDays);
		Assert.True(dto.Policy.SubnetAggregationEnabled);
		Assert.Equal(100, dto.Policy.EffectiveSubnetAggregationTotalFileThreshold);

		JsonNode saved = JsonNode.Parse(File.ReadAllText(_settingsPath))!;
		JsonNode sharding = saved["RdpAudit"]!["Sharding"]!;
		Assert.True(sharding["Enabled"]!.GetValue<bool>());
		Assert.Equal(32, sharding["ShardCapacityRecords"]!.GetValue<int>());
		Assert.Equal(4096L, sharding["MaxShardBytes"]!.GetValue<long>());
		Assert.Equal(21, sharding["OrphanGraceDays"]!.GetValue<int>());
		Assert.True(sharding["SubnetAggregation"]!["Enabled"]!.GetValue<bool>());
		Assert.Equal(10, sharding["SubnetAggregation"]!["NewFilesPerIntervalLimit"]!.GetValue<int>());

		// Nothing else in the document moved: the save touches the Sharding section only.
		Assert.Equal(
			Path.Combine(_directory, "rdpaudit.db"),
			saved["RdpAudit"]!["Storage"]!["DatabasePath"]!.GetValue<string>());

		OperationLogEntry entry = Assert.Single(audit.Entries);
		Assert.Equal(ShardingPolicyService.OperationLogSource, entry.Source);
		Assert.Equal(ShardingPolicyService.OperationLogOperation, entry.Operation);
		Assert.Equal("Operator:TEST\\operator", entry.Actor);
		Assert.Contains("old=[enabled=False", entry.Message, StringComparison.Ordinal);
		Assert.Contains("new=[enabled=True", entry.Message, StringComparison.Ordinal);
	}

	/// <summary>Given a request with a negative ceiling, when it is saved, then the command refuses it,
	/// the settings document is byte-for-byte unchanged and no audit row is written: an invalid request
	/// leaves no partial change at all.</summary>
	[Theory]
	[InlineData("MaxShardBytes")]
	[InlineData("MaxTotalShardBytes")]
	[InlineData("MinFreeDiskBytes")]
	[InlineData("ShardCapacityRecords")]
	[InlineData("MaxOpenWriters")]
	[InlineData("MaxShardFiles")]
	[InlineData("OrphanGraceDays")]
	public async Task SaveShardingPolicy_RefusesNegativeValuesWithoutWriting(string field)
	{
		string before = File.ReadAllText(_settingsPath);
		RecordingOperationLogWriter audit = new();
		IpcDispatcher dispatcher = CreateDispatcher(sink: CreateSink(), audit: audit);
		ShardingPolicyMutationRequest request = new() { ActionsRoot = _actionsRoot };
		switch (field)
		{
			case "MaxShardBytes": request.MaxShardBytes = -1; break;
			case "MaxTotalShardBytes": request.MaxTotalShardBytes = -1; break;
			case "MinFreeDiskBytes": request.MinFreeDiskBytes = -1; break;
			case "ShardCapacityRecords": request.ShardCapacityRecords = 0; break;
			case "MaxOpenWriters": request.MaxOpenWriters = 0; break;
			case "MaxShardFiles": request.MaxShardFiles = -1; break;
			default: request.OrphanGraceDays = -1; break;
		}

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.SaveShardingPolicy, Payload = JsonSerializer.Serialize(request, JsonOptions.Default) },
			CancellationToken.None,
			callerIdentity: "TEST\\operator");

		Assert.False(response.Success);
		Assert.Contains(field, response.Error ?? string.Empty, StringComparison.Ordinal);
		Assert.Equal(before, File.ReadAllText(_settingsPath));
		Assert.Empty(audit.Entries);
	}

	/// <summary>Given a value above a supported maximum, when the policy is saved, then the service
	/// clamps it, writes the clamped value and reports the clamped value back - a save never widens a
	/// bound, and it never silently claims the unclamped value was applied.</summary>
	[Fact]
	public async Task SaveShardingPolicy_ClampsValuesAboveTheSupportedMaximum()
	{
		IpcDispatcher dispatcher = CreateDispatcher(sink: CreateSink());
		ShardingPolicyMutationRequest request = new()
		{
			ActionsRoot = _actionsRoot,
			ShardCapacityRecords = 8,
			OrphanGraceDays = int.MaxValue,
			SubnetAggregation = new SubnetAggregationMutationDto
			{
				TotalFileThreshold = int.MaxValue,
				NewFilesPerIntervalLimit = int.MaxValue,
				IntervalSeconds = int.MaxValue,
				MinSourceRowsPerInterval = int.MaxValue,
			},
		};

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.SaveShardingPolicy, Payload = JsonSerializer.Serialize(request, JsonOptions.Default) },
			CancellationToken.None,
			callerIdentity: "TEST\\operator");

		Assert.True(response.Success, response.Error);
		ShardingPolicyDto dto = Deserialize<ShardingPolicyDto>(response);
		Assert.Equal(ShardingOptions.MaxOrphanGraceDays, dto.Policy.OrphanGraceDays);
		Assert.Equal(SubnetAggregationOptions.MaxTotalFileThreshold, dto.Policy.SubnetAggregationTotalFileThreshold);
		Assert.Equal(SubnetAggregationOptions.MaxIntervalSeconds, dto.Policy.SubnetAggregationIntervalSeconds);
		Assert.Equal(SubnetAggregationOptions.MaxMinSourceRowsPerInterval, dto.Policy.SubnetAggregationMinSourceRowsPerInterval);

		JsonNode saved = JsonNode.Parse(File.ReadAllText(_settingsPath))!;
		Assert.Equal(
			ShardingOptions.MaxOrphanGraceDays,
			saved["RdpAudit"]!["Sharding"]!["OrphanGraceDays"]!.GetValue<int>());
	}

	/// <summary>Given an actions root that is relative or a drive root, when the policy is saved, then it
	/// is refused before anything is written: the sink owns an entire directory tree under that path.</summary>
	[Theory]
	[InlineData("relative\\shards")]
	[InlineData("C:\\")]
	public async Task SaveShardingPolicy_RefusesAnUnusableActionsRoot(string actionsRoot)
	{
		string before = File.ReadAllText(_settingsPath);
		IpcDispatcher dispatcher = CreateDispatcher(sink: CreateSink());
		ShardingPolicyMutationRequest request = new() { ActionsRoot = actionsRoot, ShardCapacityRecords = 8 };

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.SaveShardingPolicy, Payload = JsonSerializer.Serialize(request, JsonOptions.Default) },
			CancellationToken.None,
			callerIdentity: "TEST\\operator");

		Assert.False(response.Success);
		Assert.Contains("ActionsRoot", response.Error ?? string.Empty, StringComparison.Ordinal);
		Assert.Equal(before, File.ReadAllText(_settingsPath));
	}

	/// <summary>Given a policy save leaves the values unchanged, when the command completes, then it
	/// still audits the action and says the policy is unchanged - an operator's action is never silently
	/// dropped from the log.</summary>
	[Fact]
	public async Task SaveShardingPolicy_WithNoChange_StillReportsAndAudits()
	{
		RecordingOperationLogWriter audit = new();
		IpcDispatcher dispatcher = CreateDispatcher(sink: CreateSink(), audit: audit);
		ShardingPolicyMutationRequest request = new()
		{
			Enabled = false,
			ActionsRoot = _actionsRoot,
			ShardCapacityRecords = 16,
			MaxOpenWriters = 8,
			MaxShardFiles = 64,
			OrphanGraceDays = 14,
		};

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.SaveShardingPolicy, Payload = JsonSerializer.Serialize(request, JsonOptions.Default) },
			CancellationToken.None,
			callerIdentity: "TEST\\operator");

		Assert.True(response.Success, response.Error);
		ShardingPolicyDto dto = Deserialize<ShardingPolicyDto>(response);
		Assert.Contains("unchanged", dto.Message ?? string.Empty, StringComparison.OrdinalIgnoreCase);
		Assert.Single(audit.Entries);
	}

	// ── CollectShardGarbage (92) ────────────────────────────────────────────────

	/// <summary>Given an orphan shard past the grace period, when the collection is dispatched without a
	/// payload, then it runs as a dry run and deletes nothing: an omitted payload can never trigger a
	/// deletion.</summary>
	[Fact]
	public async Task CollectShardGarbage_WithoutAPayload_RunsAsADryRun()
	{
		string orphan = CreateOrphanShard("203.0.113.10", ageDays: 40);
		IpcDispatcher dispatcher = CreateDispatcher(sink: CreateSink());

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.CollectShardGarbage },
			CancellationToken.None,
			callerIdentity: "TEST\\operator");

		Assert.True(response.Success, response.Error);
		ShardGarbageCollectionReportDto report = Deserialize<ShardGarbageCollectionReportDto>(response);
		Assert.True(report.DryRun);
		Assert.Equal(0, report.DeletedFileCount);
		Assert.Single(report.Candidates);
		Assert.Equal(ShardGarbageDisposition.Eligible, report.Candidates[0].Disposition);
		Assert.True(File.Exists(orphan));
	}

	/// <summary>Given an apply request, when it is dispatched, then the eligible orphan is removed, the
	/// report names the exact path and its byte and record totals, and each removal is audited with the
	/// invoking identity.</summary>
	[Fact]
	public async Task CollectShardGarbage_AppliesAndNamesEveryDeletedFile()
	{
		string orphan = CreateOrphanShard("203.0.113.20", ageDays: 40);
		RecordingOperationLogWriter audit = new();
		IpcDispatcher dispatcher = CreateDispatcher(sink: CreateSink(), audit: audit);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.CollectShardGarbage,
				Payload = JsonSerializer.Serialize(new CollectShardGarbageRequest { DryRun = false }, JsonOptions.Default),
			},
			CancellationToken.None,
			callerIdentity: "TEST\\operator");

		Assert.True(response.Success, response.Error);
		ShardGarbageCollectionReportDto report = Deserialize<ShardGarbageCollectionReportDto>(response);
		Assert.False(report.DryRun);
		Assert.Equal(1, report.DeletedFileCount);
		string deleted = Assert.Single(report.DeletedPaths);
		Assert.EndsWith("cb007114" + ShardPath.ShardExtension, deleted, StringComparison.Ordinal);
		Assert.True(report.DeletedBytes > 0);
		Assert.False(File.Exists(orphan));

		OperationLogEntry entry = Assert.Single(audit.Entries);
		Assert.Equal("Operator:TEST\\operator", entry.Actor);
		Assert.Equal(ShardGarbageCollectorService.OperationLogOperation, entry.Operation);
		Assert.Contains(deleted, entry.Message, StringComparison.Ordinal);
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	private static T Deserialize<T>(IpcResponse response)
		=> JsonSerializer.Deserialize<T>(response.Payload ?? throw new InvalidOperationException("No payload."), JsonOptions.Default)
			?? throw new InvalidOperationException("The payload could not be deserialized.");

	private ShardIngestionSink CreateSink()
	{
		RdpAuditOptions options = new()
		{
			Sharding = new ShardingOptions { Enabled = true, ActionsRoot = _actionsRoot, ShardCapacityRecords = 16 },
		};
		return new ShardIngestionSink(
			new FileBackedOptionsMonitor(_settingsPath, options),
			NullLogger<ShardIngestionSink>.Instance,
			new ServiceMetrics());
	}

	private IpcDispatcher CreateDispatcher(ShardIngestionSink? sink, RecordingOperationLogWriter? audit = null)
	{
		RdpAuditOptions fallback = new()
		{
			Sharding = new ShardingOptions { Enabled = false, ActionsRoot = _actionsRoot, ShardCapacityRecords = 16 },
		};
		FileBackedOptionsMonitor monitor = new(_settingsPath, fallback);
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance, protector: null, overridePath: _settingsPath);
		IDbContextFactory<AuditDbContext> factory = new SingleConnectionDbContextFactory(_connection);
		ShardInventoryService inventory = new(
			factory,
			monitor,
			NullLogger<ShardInventoryService>.Instance,
			sink,
			settings);
		ShardingPolicyService policy = new(monitor, settings, NullLogger<ShardingPolicyService>.Instance, audit);
		ShardGarbageCollectorService collector = new(
			inventory,
			monitor,
			NullLogger<ShardGarbageCollectorService>.Instance,
			sink,
			audit);

		return new IpcDispatcher(
			factory,
			new ServiceMetrics(),
			monitor,
			settings,
			new FirewallManager(NullLogger<FirewallManager>.Instance),
			Array.Empty<RdpAudit.Core.Firewall.IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance,
			opLog: audit,
			shardInventory: inventory,
			shardingPolicy: policy,
			shardGarbageCollector: collector);
	}

	private string CreateOrphanShard(string ip, double ageDays)
	{
		char[] relative = new char[64];
		Assert.True(ShardPath.TryComposeShardPath(System.Net.IPAddress.Parse(ip), relative, out int length));
		string absolute = Path.Combine(
			_directory,
			new string(relative, 0, length).Replace('/', Path.DirectorySeparatorChar));
		Directory.CreateDirectory(Path.GetDirectoryName(absolute)!);
		using (ShardWriter writer = ShardWriter.OpenOrCreate(absolute, capacity: 8))
		{
			ShardRecord record = ShardRecord.Create(
				1, DateTime.UtcNow.Ticks, 4625, (ushort)ChannelCode.Security, 1, 255, 10, 0, 0, 1, 1, -1, -1, -1, -1, -1, 0);
			writer.Append(in record, out _);
			writer.Commit();
		}

		File.SetLastWriteTimeUtc(absolute, DateTime.UtcNow.AddDays(-ageDays));
		return absolute;
	}

	private sealed class SingleConnectionDbContextFactory(SqliteConnection connection) : IDbContextFactory<AuditDbContext>
	{
		public AuditDbContext CreateDbContext()
			=> new(new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(connection).Options);
	}

	private sealed class FileBackedOptionsMonitor(string path, RdpAuditOptions fallback) : IOptionsMonitor<RdpAuditOptions>
	{
		public RdpAuditOptions CurrentValue
		{
			get
			{
				try
				{
					if (!File.Exists(path))
					{
						return fallback;
					}

					JsonNode? section = JsonNode.Parse(File.ReadAllText(path))?[RdpAuditOptions.SectionName];
					return section is null
						? fallback
						: JsonSerializer.Deserialize<RdpAuditOptions>(section.ToJsonString(JsonOptions.Default), JsonOptions.Default) ?? fallback;
				}
				catch (JsonException)
				{
					return fallback;
				}
				catch (IOException)
				{
					return fallback;
				}
			}
		}

		public RdpAuditOptions Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private sealed class RecordingOperationLogWriter : IOperationLogWriter
	{
		public List<OperationLogEntry> Entries { get; } = new();

		public bool IsDebugEnabled => false;

		public Task WriteAsync(OperationLogEntry entry, CancellationToken ct = default)
		{
			Entries.Add(entry);
			return Task.CompletedTask;
		}

		public Task InfoAsync(string source, string operation, string message, CancellationToken ct = default)
			=> WriteAsync(new OperationLogEntry { Severity = OperationLogSeverity.Information, Source = source, Operation = operation, Message = message }, ct);

		public Task WarnAsync(string source, string operation, string message, string? detailsJson = null, CancellationToken ct = default)
			=> WriteAsync(new OperationLogEntry { Severity = OperationLogSeverity.Warning, Source = source, Operation = operation, Message = message, DetailsJson = detailsJson }, ct);

		public Task ErrorAsync(string source, string operation, string message, Exception? exception, OperationLogSeverity severity = OperationLogSeverity.Error, CancellationToken ct = default)
			=> WriteAsync(new OperationLogEntry { Severity = severity, Source = source, Operation = operation, Message = message, Exception = exception }, ct);

		public Task DebugAsync(string source, string operation, string message, Func<string?>? detailsBuilder = null, string? correlationId = null, CancellationToken ct = default)
			=> Task.CompletedTask;
	}
}
