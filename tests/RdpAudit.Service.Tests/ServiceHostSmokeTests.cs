/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ServiceHostSmokeTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: B9 regression: one end-to-end run against a REAL host composition on a temporary ProgramData
//          root. Everything the Database tab asks for goes through the REAL dispatcher and the REAL
//          services: no canned DTOs, no fake dispatcher, no in-memory database.
//          What this test therefore verifies that nothing else did:
//            - the DI composition registered by Program.RegisterServices RESOLVES end to end - every
//              service the Database commands need (overview, retention policy, retention preview,
//              ledger, backups, purge-by-subject) is constructible from the container, which is the
//              class of defect a hand-wired test container can never see;
//            - migrations are APPLIED to a clean store by the real DatabaseInitializationWorker, and the
//              start-up sequence (pre-migration snapshot policy + downgrade guard) does not block a
//              normal start: the failure markers must be absent and the migration history must be the
//              complete one this build knows;
//            - the storage and retention reports come back with REAL values measured from that store
//              (non-zero sizes, the applied migration list, the policy read from the temp
//              appsettings), not with placeholders;
//            - a snapshot can be created, listed and verified against the store the host just migrated;
//            - a subject purge DRY RUN reaches the real purge service and reports it as a dry run.
//          WHAT IS DELIBERATELY NOT STARTED, and why - this is the honest part of the report, not a
//          convenience: the real host also registers 21 hosted services, and the machine-touching ones
//          cannot run inside a test process without damaging the machine or the suite:
//            IpcServerWorker                    binds \\.\pipe\RdpAuditService - the PRODUCTION pipe name.
//                                               B4/B21: a test that serves that name is reachable by every
//                                               other test project in a parallel run, which is exactly how
//                                               DatabasePageTests used to read a live service where it
//                                               asserts one is unreachable.
//            RestApiHostedService               binds a real TCP listener and resolves a certificate.
//            EventCollectorHostedWorker,        subscribe to the Security event channel and would consume
//            SecurityBackfillWorker             the operator's real event log.
//            EventProcessorWorker, AlertWorker, background loops that write to the store while the assertions
//            RetentionWorker, MaintenanceWorker, run, i.e. non-deterministic by construction.
//            InformationDensityRetentionWorker,
//            CrossHostCorrelationWorker,
//            AttackStatsRefreshWorker,
//            SessionCorrelationHydrationWorker,
//            AbuseIpDbReportWorker,
//            ThreatIntelEnrichmentWorker,
//            ProcessAlertAutoResponder
//            FirewallAutoBlockWorker,           invoke netsh / route / the registry to change real firewall
//            FirewallExpirationWorker,          state.
//            EnforcementReconciliationWorker
//            ZabbixPushWorker                   is NOT in this list, deliberately: with the shipped defaults
//                                               (Enabled=false) it never opens a socket - the loop only
//                                               re-reads the options every 30 s - so it can run in the test
//                                               process without touching the network or the store.
//          StoreIntegrityWorker and DatabaseInitializationWorker ARE started: they are the start-up path
//          this test is about, and the shutdown capture at the end also exercises the B19 fingerprint chain
//          with the real DPAPI protector against the temp root.
//          The list is asserted against what RegisterServices actually registered, so a newly added hosted
//          service forces a decision here instead of silently escaping the suite.
// Depends: Program.RegisterServices (reflection - the composition root has no other public entry point),
//          IpcDispatcher, DatabaseInitializationWorker, RdpAuditPaths, xUnit
// Extends: Add a command to the exercise list when the Database tab gains one that must work end to end.

using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class ServiceHostSmokeTests
{
	/// <summary>Hosted services the real composition root registers when the build contains every
	/// gated capability. Pinned so a new one cannot slip past the "which of these may run in a test"
	/// decision below.</summary>
	private const int RecordedHostedServiceCountWithEveryCapability = 22;

	/// <summary>
	/// Expected count for THIS build. The open-core split removes a gated worker from the composition
	/// of a lower edition instead of leaving it registered and idle, so the guard has to count what the
	/// edition actually contains: 21 historic workers plus the edition announcement, minus every gated
	/// worker the edition does not have. Hard-coding one number would either hide a forgotten
	/// registration in Community or fail a legitimate Pro composition.
	/// </summary>
	private static int RecordedHostedServiceCount =>
		RecordedHostedServiceCountWithEveryCapability
		- (RdpAudit.Core.Editions.EditionContext.Allows(RdpAudit.Core.Editions.EditionFeature.RestApi) ? 0 : 1)
		- (RdpAudit.Core.Editions.EditionContext.Allows(RdpAudit.Core.Editions.EditionFeature.CrossHostCorrelation) ? 0 : 1)
		- (RdpAudit.Core.Editions.EditionContext.Allows(RdpAudit.Core.Editions.EditionFeature.ZabbixIntegration) ? 0 : 1);

	private readonly string _root = Path.Combine(
		Path.GetTempPath(),
		"rdpaudit-smoke-" + Guid.NewGuid().ToString("N"));

	private string DatabasePath => Path.Combine(_root, RdpAuditPaths.DatabaseFileName);

	/// <summary>Names the size and last-write time of the machine's own database and settings file, so the
	/// smoke test can prove it did not touch them.</summary>
	private static string DescribeRealInstallation()
	{
		static string Describe(string path)
		{
			FileInfo info = new(path);
			return info.Exists
				? info.Length.ToString(System.Globalization.CultureInfo.InvariantCulture) + "@" + info.LastWriteTimeUtc.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture)
				: "(absent)";
		}

		return Describe(RdpAuditPaths.Default.DatabasePath)
			+ "|" + Describe(RdpAuditPaths.Default.AppSettingsPath);
	}

	private static void AssertRealInstallationUnchanged(string before)
	{
		string after = DescribeRealInstallation();
		Assert.True(string.Equals(before, after, StringComparison.Ordinal),
			"The smoke test changed the machine's real installation. Before: " + before + ", after: " + after
			+ ". The host must be redirected to the temporary root entirely.");

		if (string.Equals(before, "(absent)|(absent)", StringComparison.Ordinal))
		{
			Assert.False(File.Exists(RdpAuditPaths.Default.DatabasePath),
				"The smoke test created a database in the machine's real ProgramData root.");
		}
	}

	/// <summary>Removes the temporary root. Called from a finally so a failing assertion cannot leave the
	/// tree behind. The SQLite pools are cleared first: the host's connections are pooled process-wide, and a
	/// pooled handle keeps the database file open, which is how an earlier version of this test left eight
	/// directory trees in %TEMP%. A deletion that still fails is retried briefly and then given up on rather
	/// than masking the real failure.</summary>
	private void DeleteRoot()
	{
		Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
		for (int attempt = 0; attempt < 5; attempt++)
		{
			try
			{
				if (!Directory.Exists(_root))
				{
					return;
				}

				Directory.Delete(_root, recursive: true);
				return;
			}
			catch (IOException)
			{
				Thread.Sleep(200);
			}
			catch (UnauthorizedAccessException)
			{
				Thread.Sleep(200);
			}
		}
	}

	/// <summary>The whole point of B9: a real host, a clean temporary store, the Database tab's command set
	/// through the real dispatcher, and a clean shutdown.</summary>
	[Fact]
	public async Task RealHost_OnATemporaryProgramDataRoot_ServesEveryDatabaseCommand()
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		string realInstallationBefore = DescribeRealInstallation();

		try
		{
			Directory.CreateDirectory(_root);
			IHost host = BuildHost(out IReadOnlyList<string> notStarted);
			await host.StartAsync(CancellationToken.None);
			try
			{
			Assert.True(notStarted.Count == RecordedHostedServiceCount,
				"The composition root registers a different number of hosted services than this test records ("
				+ notStarted.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + " vs "
				+ RecordedHostedServiceCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
				+ "): decide for each new one whether it can run inside a test process. Registered: "
				+ string.Join(", ", notStarted));

			// ── Start-up: migrations on a clean store, no guard fired ────────────────
			Assert.True(File.Exists(DatabasePath), "The host did not create the database on the temporary root.");
			Assert.False(
				File.Exists(Path.Combine(_root, RdpAuditPaths.MigrationFailureMarkerFileName)),
				"The migration-failure marker exists after a start against a clean store.");
			Assert.False(
				File.Exists(Path.Combine(_root, RdpAuditPaths.CrashReportFileName))
				|| File.Exists(Path.Combine(_root, RdpAuditPaths.CrashFolderName, RdpAuditPaths.CrashReportFileName)),
				"The crash report exists after a start against a clean store.");

			using IServiceScope scope = host.Services.CreateScope();
			IpcDispatcher dispatcher = scope.ServiceProvider.GetRequiredService<IpcDispatcher>();

			// ── GetDatabaseOverview: real sizes and the real migration history ───────
			DatabaseOverviewDto overview = await DispatchAsync<DatabaseOverviewDto>(dispatcher, IpcCommand.GetDatabaseOverview);
			Assert.True(overview.Status == IpcResultStatus.Success, DescribeOverview(overview));
			Assert.Equal(Path.GetFullPath(DatabasePath), Path.GetFullPath(overview.DatabasePath));
			Assert.True(overview.DatabaseBytes > 0, "The real database file must have a size.");
			Assert.NotEmpty(overview.AppliedMigrations);
			Assert.Empty(overview.PendingMigrations);
			Assert.True(overview.LedgerChainIntact);
			Assert.False(overview.MigrationFailureMarkerPresent);

			// The row-count section is measured, not stubbed: every watched table is present.
			Assert.Contains(overview.TableRowCounts, row => string.Equals(row.Table, "RawEvents", StringComparison.Ordinal));
			Assert.All(overview.TableRowCounts, row => Assert.True(row.RowCount >= 0, row.Table + " reported " + row.RowCount));

			// ── The retention policy is the one the temp configuration carries ───────
			RetentionPolicyDto policy = await DispatchAsync<RetentionPolicyDto>(dispatcher, IpcCommand.GetRetentionPolicy);
			Assert.True(policy.Status == IpcResultStatus.Success, "GetRetentionPolicy reported " + policy.Status + ": " + policy.Message);
			Assert.NotNull(policy.Policy);
			Assert.NotNull(policy.GlobalWindows);
			Assert.True(policy.Policy.EffectiveTailKeepPerCode > 0, "The effective policy values must be resolved, not zero.");
			Assert.True(policy.Policy.EffectiveMinAgeDays > 0, "The effective age floor must be resolved, not zero.");
			Assert.True(policy.GlobalWindows.EventRetentionDays > 0, "The global retention windows must be real values.");

			RetentionPreviewDto preview = await DispatchAsync<RetentionPreviewDto>(dispatcher, IpcCommand.PreviewRetention);
			Assert.True(preview.Status == IpcResultStatus.Success, "PreviewRetention reported " + preview.Status + ": " + preview.Message);
			Assert.True(preview.RuleVersion > 0, "The dry run must report the rule version it evaluated.");
			Assert.True(preview.WouldDeleteRows >= 0);

			// ── Snapshots: create, list, verify ─────────────────────────────────────
			DatabaseBackupCreationDto created = await DispatchAsync<DatabaseBackupCreationDto>(
				dispatcher,
				IpcCommand.CreateDatabaseBackup,
				new CreateDatabaseBackupRequest { IncludeShards = false });
			Assert.True(created.Status == IpcResultStatus.Success,
				"CreateDatabaseBackup reported " + created.Status + ": " + created.Message);
			Assert.False(string.IsNullOrWhiteSpace(created.SnapshotName), created.Message);
			Assert.True(created.DatabaseBytes > 0, "The created snapshot must have a size.");
			Assert.False(string.IsNullOrWhiteSpace(created.DatabaseSha256), "The created snapshot must be hashed.");
			Assert.StartsWith(Path.GetFullPath(_root), Path.GetFullPath(created.SnapshotDirectory), StringComparison.OrdinalIgnoreCase);
			// The copy lives in the snapshot's db sub-folder (DatabaseBackupLayout): a snapshot directory that
			// holds only a manifest is exactly the "listed but not restorable" state the layout exists to
			// prevent, so the file itself is asserted rather than the reported byte count.
			Assert.True(
				File.Exists(Path.Combine(created.SnapshotDirectory, DatabaseBackupLayout.DatabaseFolderName, DatabaseBackupLayout.DatabaseFileName)),
				"The snapshot must hold the database copy under its db sub-folder. The snapshot holds: "
					+ string.Join(", ", Directory.GetFileSystemEntries(created.SnapshotDirectory).Select(Path.GetFileName)));

			DatabaseBackupListDto list = await DispatchAsync<DatabaseBackupListDto>(dispatcher, IpcCommand.ListDatabaseBackups);
			Assert.True(list.Status == IpcResultStatus.Success, "ListDatabaseBackups reported " + list.Status + ": " + list.Message);
			Assert.True(list.TotalCount >= 1, "The snapshot just created must be listed.");
			Assert.Contains(list.Entries, entry => string.Equals(entry.Name, created.SnapshotName, StringComparison.Ordinal));

			DatabaseBackupVerificationDto verification = await DispatchAsync<DatabaseBackupVerificationDto>(
				dispatcher,
				IpcCommand.VerifyDatabaseBackup,
				new VerifyDatabaseBackupRequest { Name = created.SnapshotName });
			Assert.True(verification.Status == IpcResultStatus.Success, "VerifyDatabaseBackup reported " + verification.Status + ": " + verification.Message);
			Assert.True(verification.IsUsable,
				"The snapshot the host just created must verify. Verdict=" + verification.VerdictName
				+ " schema=" + verification.SchemaVerdict + " quick_check=" + verification.QuickCheckResult
				+ " message=" + verification.Message);
			Assert.Equal(created.DatabaseSha256, verification.ActualSha256);

			// ── Ledger: readable on a fresh store (empty, but a real page) ───────────
			DeletionLedgerPageDto ledger = await DispatchAsync<DeletionLedgerPageDto>(
				dispatcher,
				IpcCommand.GetDeletionLedger,
				new DeletionLedgerQueryRequest { Page = 0, PageSize = 50 });
			Assert.True(ledger.Status == IpcResultStatus.Success, "GetDeletionLedger reported " + ledger.Status + ": " + ledger.Message);
			Assert.Equal(0, ledger.Page);
			Assert.Equal(0, ledger.TotalMatching);

			// ── Purge by subject: DRY RUN ONLY ──────────────────────────────────────
			// Apply is deliberately never requested here: a smoke test may not delete evidence.
			PurgeBySubjectReportDto purge = await DispatchAsync<PurgeBySubjectReportDto>(
				dispatcher,
				IpcCommand.PurgeBySubject,
				new PurgeBySubjectRequest
				{
					Kind = PurgeSubjectKind.Ip,
					Value = "203.0.113.7",
					Apply = false,
				});
			Assert.True(purge.Status == IpcResultStatus.Success, "PurgeBySubject reported " + purge.Status + ": " + purge.Message);
			Assert.True(purge.DryRun, "The purge must report itself as a dry run.");
			Assert.False(purge.Applied, "A dry run must never report that it applied deletions.");
			Assert.Equal(0, purge.TotalRowsDeleted);
		}
		finally
		{
			await host.StopAsync(TimeSpan.FromSeconds(30));
			host.Dispose();
			stopwatch.Stop();
		}

		// ── Shutdown ────────────────────────────────────────────────────────────────
		// The clean-shutdown capture runs here (StoreIntegrityWorker.StopAsync), so the B19 chain exists with
		// the real protector and the real paths - in the temp root.
		string chainDirectory = new RdpAuditPaths(_root).StoreFingerprintChainDirectory;
		Assert.True(
			Directory.Exists(chainDirectory) && Directory.GetFiles(chainDirectory, "*.json").Length > 0,
			"The clean-shutdown fingerprint chain entry was not written to the temporary root.");
		Assert.True(
			File.Exists(new RdpAuditPaths(_root).StoreFingerprintSealedTipPath),
			"The sealed fingerprint tip was not written to the temporary root.");

		// The real installation is untouched. Comparing the fingerprint of the machine's own files (rather
		// than only asserting "the file did not appear") catches a write to an installation that already
		// exists, which is the more likely accident on a developer machine.
		AssertRealInstallationUnchanged(realInstallationBefore);

		// A smoke test that takes minutes would not be run; the budget is part of the contract.
		Assert.True(stopwatch.Elapsed < TimeSpan.FromMinutes(3),
			"The end-to-end smoke test took " + stopwatch.Elapsed + ", which is beyond the budget for a test.");
		}
		finally
		{
			DeleteRoot();
		}
	}

	// ── Composition ──────────────────────────────────────────────────────────────

	/// <summary>Builds the host from the REAL composition root, redirected to the temporary root and with
	/// only the start-up workers enabled. See the file header for what is not started and why.</summary>
	private IHost BuildHost(out IReadOnlyList<string> notStarted)
	{
		ServiceCollection services = [];
		InvokeRegisterServices(services);

		// Redirect every machine-wide path into the temporary root. Registered AFTER RegisterServices, so
		// these win: the host must not read or write the real installation.
		RdpAuditPaths paths = new(_root);
		RdpAuditOptions options = new()
		{
			Storage = new StorageOptions
			{
				DatabasePath = DatabasePath,
			},
			Sharding = new ShardingOptions
			{
				ActionsRoot = paths.ActionsRootDirectory,
			},
		};
		options.Storage.Backup.BackupDirectory = paths.BackupsDirectory;

		// Snapshots are DISABLED by default (an operator switch, and a deliberate one: the refusal above is
		// what a stock deployment returns). The smoke test is about the create/list/verify machinery working
		// end to end, so it enables the switch the way an operator would - and leaves every other default
		// alone, so the rest of the run still exercises the shipped configuration.
		options.Storage.Backup.Enabled = true;

		services.AddSingleton<IRdpAuditPathsProvider>(new FixedPathsProvider(paths));
		services.AddSingleton<IOptions<RdpAuditOptions>>(Options.Create(options));
		services.AddSingleton<IOptionsMonitor<RdpAuditOptions>>(new StaticOptionsMonitor<RdpAuditOptions>(options));

		// Replace the hosted-service set with the start-up path only. The worker types themselves stay
		// registered (AddTimedHostedService<T> registers T as well), so these resolve the very instances the
		// composition root would have started - nothing is stubbed, the loops are simply not run.
		List<ServiceDescriptor> hosted = services.Where(descriptor => descriptor.ServiceType == typeof(IHostedService)).ToList();
		notStarted = hosted
			.Select(descriptor => DescribeHostedService(descriptor))
			.ToList();
		foreach (ServiceDescriptor descriptor in hosted)
		{
			services.Remove(descriptor);
		}

		services.AddSingleton<IHostedService>(sp => sp.GetRequiredService<StoreIntegrityWorker>());
		services.AddSingleton<IHostedService>(sp => sp.GetRequiredService<DatabaseInitializationWorker>());

		return new HostBuilder()
			.ConfigureServices(collection =>
			{
				foreach (ServiceDescriptor descriptor in services)
				{
					collection.Add(descriptor);
				}

				collection.AddLogging();
				collection.Configure<HostOptions>(hostOptions =>
				{
					// The same policy Program.Main uses, so the smoke test starts the host the way production
					// does: one failing worker must not tear the host down.
					hostOptions.ShutdownTimeout = TimeSpan.FromSeconds(30);
					hostOptions.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore;
				});
			})
			.Build();
	}

	/// <summary>Names a hosted-service descriptor without constructing it: every one of them wraps its
	/// worker in <c>Program.TimedHostedService</c>, and the inner type is what a reader needs to see.</summary>
	private static string DescribeHostedService(ServiceDescriptor descriptor)
		=> descriptor.ImplementationType?.Name
			?? descriptor.ImplementationFactory?.Method.ReturnType.Name
			?? descriptor.ImplementationInstance?.GetType().Name
			?? "(unknown)";

	/// <summary>Renders why an overview came back non-Success, so a failure names its section instead of
	/// only its status.</summary>
	private static string DescribeOverview(DatabaseOverviewDto overview)
		=> "The overview reported " + overview.Status + ": " + overview.Message
			+ " | partial=" + overview.IsPartial
			+ " | warnings=[" + string.Join("; ", overview.Warnings) + "]"
			+ " | sections=[" + string.Join("; ", overview.Sections.Select(section =>
				section.Section + "=" + section.Status + (string.IsNullOrEmpty(section.Error) ? string.Empty : "(" + section.Error + ")")))
			+ "]";

	private static async Task<T> DispatchAsync<T>(IpcDispatcher dispatcher, IpcCommand command, object? payload = null)
	{
		IpcRequest request = new()
		{
			Command = command,
			Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
		};

		IpcResponse response = await dispatcher.DispatchAsync(request, CancellationToken.None);
		Assert.True(response.Success, "The service refused " + command + ": " + response.Error);
		Assert.False(string.IsNullOrWhiteSpace(response.Payload), "The service returned no payload for " + command);

		T? value = JsonSerializer.Deserialize<T>(response.Payload!, JsonOptions.Default);
		return value ?? throw new InvalidOperationException("The payload of " + command + " did not deserialize.");
	}

	private static void InvokeRegisterServices(IServiceCollection services)
	{
		MethodInfo registerServices = typeof(Program).GetMethod(
			"RegisterServices",
			BindingFlags.NonPublic | BindingFlags.Static)
			?? throw new InvalidOperationException("Program.RegisterServices was not found.");

		try
		{
			registerServices.Invoke(null, [services]);
		}
		catch (TargetInvocationException ex) when (ex.InnerException is not null)
		{
			ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
			throw;
		}
	}

	private sealed class FixedPathsProvider(RdpAuditPaths paths) : IRdpAuditPathsProvider
	{
		public RdpAuditPaths Paths { get; } = paths;
	}

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
	{
		public T CurrentValue { get; } = value;

		public T Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}
}
