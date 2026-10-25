// File:    tests/RdpAudit.Service.Tests/IpcDispatcherPaginationTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: P4 pagination regression tests: the Logs-tab QueryOperationLogs paging (Skip/Take)
//          must serve deterministic, non-overlapping pages ordered by a stable total order
//          (TimeUtc desc, Id desc) so an unstable page can never duplicate or drop rows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

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

/// <summary>P4 pagination tests for the operation-log paged IPC query.</summary>
public class IpcDispatcherPaginationTests
{
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitorLocal<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitorLocal(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private static async Task<(IDbContextFactory<AuditDbContext>, SqliteConnection)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;

		await using (AuditDbContext init = new(options))
		{
			await init.Database.EnsureCreatedAsync();
		}

		return (new TestDbContextFactory(options), conn);
	}

	private static IpcDispatcher CreateDispatcher(IDbContextFactory<AuditDbContext> factory)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitorLocal<RdpAuditOptions> mon = new(new RdpAuditOptions());
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager manager = new(NullLogger<FirewallManager>.Instance);
		return new IpcDispatcher(factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance);
	}

	private static async Task<OperationLogPageDto> QueryPageAsync(
		IpcDispatcher dispatcher,
		int page,
		int pageSize)
	{
		OperationLogQueryRequest req = new()
		{
			Page = page,
			PageSize = pageSize,
			ExcludeDebugNoise = true,
			GroupDuplicates = false,
		};
		IpcRequest ipc = new()
		{
			Command = IpcCommand.QueryOperationLogs,
			Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
		};
		IpcResponse response = await dispatcher.DispatchAsync(ipc, CancellationToken.None);
		Assert.True(response.Success, response.Error);
		return JsonSerializer.Deserialize<OperationLogPageDto>(response.Payload!, JsonOptions.Default)!;
	}

	[Fact]
	public async Task QueryOperationLogs_PagesDoNotOverlap_AndFollowStableOrder()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime baseUtc = DateTime.UtcNow.AddMinutes(-30);

			await using (AuditDbContext db = factory.CreateDbContext())
			{
				for (int i = 0; i < 12; i++)
				{
					db.OperationLogs.Add(new OperationLog
					{
						TimeUtc = baseUtc.AddMinutes(i),
						Severity = OperationLogSeverity.Information,
						Source = "Maintenance",
						Operation = "P4Probe",
						Message = "row-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
						IsDebug = false,
					});
				}

				await db.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory);

			OperationLogPageDto page0 = await QueryPageAsync(dispatcher, page: 0, pageSize: 5);
			OperationLogPageDto page1 = await QueryPageAsync(dispatcher, page: 1, pageSize: 5);
			OperationLogPageDto page2 = await QueryPageAsync(dispatcher, page: 2, pageSize: 5);

			Assert.Equal(IpcResultStatus.Success, page0.Status);
			Assert.Equal(5, page0.Items.Count);
			Assert.Equal(5, page1.Items.Count);
			Assert.Equal(2, page2.Items.Count);
			Assert.Equal(12, page0.TotalMatching);

			// Page 0 is newest-first with a deterministic tie-break (Id desc).
			for (int i = 1; i < page0.Items.Count; i++)
			{
				Assert.True(page0.Items[i - 1].TimeUtc >= page0.Items[i].TimeUtc);
				if (page0.Items[i - 1].TimeUtc == page0.Items[i].TimeUtc)
				{
					Assert.True(page0.Items[i - 1].Id > page0.Items[i].Id);
				}
			}

			// Pages must not share any row.
			HashSet<long> ids0 = page0.Items.Select(r => r.Id).ToHashSet();
			HashSet<long> ids1 = page1.Items.Select(r => r.Id).ToHashSet();
			HashSet<long> ids2 = page2.Items.Select(r => r.Id).ToHashSet();
			Assert.Empty(ids0.Intersect(ids1));
			Assert.Empty(ids0.Intersect(ids2));
			Assert.Empty(ids1.Intersect(ids2));

			// The union of the three pages must be exactly the 12 seeded rows.
			HashSet<long> union = new(ids0);
			union.UnionWith(ids1);
			union.UnionWith(ids2);
			Assert.Equal(12, union.Count);

			// The global order across the page boundary must stay strictly monotonic.
			Assert.True(page0.Items[^1].TimeUtc > page1.Items[0].TimeUtc
				|| (page0.Items[^1].TimeUtc == page1.Items[0].TimeUtc && page0.Items[^1].Id > page1.Items[0].Id));
			Assert.True(page1.Items[^1].TimeUtc > page2.Items[0].TimeUtc
				|| (page1.Items[^1].TimeUtc == page2.Items[0].TimeUtc && page1.Items[^1].Id > page2.Items[0].Id));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
