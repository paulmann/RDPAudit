/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : Program.cs
// Project: RdpAudit.Service (RdpAudit.Service)
// Purpose: Process entry point — configures host, DI, logging, and ordered worker registrations,
//          and sequences startup so schema migrations complete before any DB-backed diagnostics run.
//          v2.0.1: CrashGuard has no RecordFatal member (CS1061 on build) — reverted the host-level
//          fatal-fault handler to Serilog.Log.Fatal, which is guaranteed available since Serilog is
//          already the global logging pipeline configured by ConfigureSerilog below. This is a
//          host-lifecycle fault (StartAsync/WaitForShutdownAsync threw), distinct from a per-worker
//          fault that CrashGuard's installed handlers already catch.
// Depends: HostApplicationBuilder, AuditDbInitializer, DatabaseInitializationWorker, CrashGuard,
//          Serilog, IOptionsMonitor<RdpAuditOptions>, TimedHostedService
// Extends: Register a new worker via AddTimedHostedService in the ordered block inside
//          RegisterServices; add a new DI singleton in the composition block above it.

using System.Diagnostics;
using System.Net.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Diagnostics;
using RdpAudit.Core.Events;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.Security;
using RdpAudit.Service.AbuseIpDb;
using RdpAudit.Service.Alerts;
using RdpAudit.Service.Collectors;
using RdpAudit.Service.Firewall;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Processors;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Serilog;
using Serilog.Formatting.Compact;

namespace RdpAudit.Service;

/// <summary>Process entry point — configures host, DI, logging, and worker registrations.</summary>
public static class Program
{
	// ── Public API ───────────────────────────────────────────────────────────────

	public static async Task<int> Main(string[] args)
	{
		bool isService = !Debugger.IsAttached
			&& !args.Contains("--console", StringComparer.OrdinalIgnoreCase)
			&& WindowsServiceHelpers.IsWindowsService();

		HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string configPath = Path.Combine(programData, "RdpAudit", "appsettings.json");
		string? configDir = Path.GetDirectoryName(configPath);
		if (!string.IsNullOrEmpty(configDir))
		{
			Directory.CreateDirectory(configDir);
		}

		if (!File.Exists(configPath))
		{
			await File.WriteAllTextAsync(configPath, AppSettingsTemplate.Default).ConfigureAwait(false);
		}

		builder.Configuration
			.AddJsonFile(configPath, optional: false, reloadOnChange: true)
			.AddEnvironmentVariables("RDPAUDIT_");

		builder.Services.Configure<RdpAuditOptions>(
			builder.Configuration.GetSection(RdpAuditOptions.SectionName));

		// Singleton recorder for the most recent monitoring-config repair (surfaced via the
		// Diagnostic IPC command).
		builder.Services.AddSingleton<ConfigRepairReporter>();

		// Repair stale appsettings.json before any worker consumes the effective MonitoringOptions.
		// A pre-v3 config that pruned EnabledChannels (no Security) or wrote a partial EnabledEventIds
		// filter would otherwise leave the Security watcher disarmed at startup. The repair is
		// idempotent and runs every time options are materialized (including IOptionsMonitor reloads),
		// so an operator who hand-edits appsettings.json with the Configurator open also benefits.
		builder.Services.AddSingleton<IPostConfigureOptions<RdpAuditOptions>, MonitoringConfigPostConfigure>();

		ConfigureSerilog(builder, programData);

		if (isService)
		{
			builder.Services.AddWindowsService(o => o.ServiceName = "RdpAuditService");
		}

		builder.Services.Configure<HostOptions>(o =>
		{
			o.ShutdownTimeout = TimeSpan.FromSeconds(15);

			// A single faulted BackgroundService must never abort the host. Individual workers
			// already guard their loops, but this is the process-wide backstop so a fault in one
			// worker's StartAsync/ExecuteAsync cannot tear the whole service down.
			o.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore;
		});

		RegisterServices(builder.Services);

		using IHost host = builder.Build();

		// Install last-resort crash diagnostics before anything else can fault. From this point a
		// fault anywhere in the process is recorded as a Critical OperationLog (DB permitting) and
		// always to the Windows Event Log and a fallback file, instead of dying silently.
		CrashGuard crashGuard = host.Services.GetRequiredService<CrashGuard>();
		crashGuard.Install();

		try
		{
			// StartAsync runs the ordered hosted-service chain, whose FIRST member
			// (DatabaseInitializationWorker) applies EF migrations. Only AFTER it returns is the
			// schema guaranteed present — so the DB-backed startup diagnostic below can safely write
			// to OperationLogs. Emitting LogStartupDiagnostics before StartAsync was the direct cause
			// of the "SQLite Error 1: 'no such table: OperationLogs'" on first launch, because the
			// OperationLog INSERT raced ahead of the V133OperationLogs migration.
			await host.StartAsync().ConfigureAwait(false);

			RdpAuditOptions effectiveOptions = host.Services.GetRequiredService<IOptions<RdpAuditOptions>>().Value;
			crashGuard.LogStartupDiagnostics(effectiveOptions, configPath);

			await host.WaitForShutdownAsync().ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			// Last-resort: the host itself failed to start or shut down cleanly. This is a
			// host-lifecycle fault (StartAsync / WaitForShutdownAsync threw before or outside any
			// individual worker's own exception handling), distinct from the per-worker faults
			// CrashGuard.Install() already intercepts. CrashGuard exposes no RecordFatal member, so
			// log directly via Serilog.Log — the global logging pipeline is already fully configured
			// at this point (file sink + Windows Event Log sink from ConfigureSerilog), guaranteeing
			// this fault is captured even if the DB-backed OperationLog path is unavailable.
			Log.Fatal(ex, "Host failed to start or shut down cleanly");
			return 1;
		}

		return 0;
	}

	// ── Logging Configuration ────────────────────────────────────────────────────

	private static void ConfigureSerilog(HostApplicationBuilder builder, string programData)
	{
		string logDir = Path.Combine(programData, "RdpAudit", "logs");
		Directory.CreateDirectory(logDir);

		// DebugMode is read directly from the raw configuration section (not IOptions<T>) because
		// ConfigureSerilog runs before the DI container is built, so IOptionsMonitor<RdpAuditOptions>
		// is not yet resolvable. This mirrors RdpAuditOptions.Diagnostics.DebugMode's JSON path.
		// The RDPAUDIT_RdpAudit__Diagnostics__DebugMode / RDPAUDIT_RdpAudit__LogLevel environment
		// overrides documented for support are honoured here because AddEnvironmentVariables has
		// already been layered onto builder.Configuration above.
		bool debugMode = builder.Configuration
			.GetSection(RdpAuditOptions.SectionName)
			.GetSection(nameof(RdpAuditOptions.Diagnostics))
			.GetValue<bool>(nameof(DiagnosticsOptions.DebugMode));

		string? logLevelOverride = builder.Configuration
			.GetSection(RdpAuditOptions.SectionName)
			.GetValue<string?>("LogLevel");

		bool debugFromEnv = string.Equals(logLevelOverride, "Debug", StringComparison.OrdinalIgnoreCase);
		debugMode = debugMode || debugFromEnv;

		LoggerConfiguration logger = new LoggerConfiguration()
			.MinimumLevel.Is(debugMode ? Serilog.Events.LogEventLevel.Debug : Serilog.Events.LogEventLevel.Information)
			.ReadFrom.Configuration(builder.Configuration)
			.Enrich.FromLogContext()
			.WriteTo.File(
				new CompactJsonFormatter(),
				Path.Combine(logDir, "service-.log"),
				rollingInterval: RollingInterval.Day,
				retainedFileCountLimit: 90);

		if (debugMode)
		{
			// Persistent, human-readable DEBUG mirror requested by operators for support bundles:
			// every log event (all workers, all sinks) is duplicated here regardless of source, with
			// no rolling-by-day split, capped by size instead so a single file is always the target
			// of the Settings tab "Open debug log" link.
			string debugLogPath = Path.Combine(programData, "RdpAudit", "RDPAudit_DEBUG_Log.txt");
			logger = logger.WriteTo.File(
				debugLogPath,
				restrictedToMinimumLevel: Serilog.Events.LogEventLevel.Debug,
				rollingInterval: RollingInterval.Infinite,
				rollOnFileSizeLimit: true,
				fileSizeLimitBytes: 50 * 1024 * 1024,
				retainedFileCountLimit: 5,
				shared: true,
				outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff} {Level:u3}] {SourceContext}{NewLine}	{Message:lj}{NewLine}{Exception}");
		}

		if (OperatingSystem.IsWindows())
		{
			// Route the EventLog sink through a sub-logger that drops EF Core's per-statement
			// "Executed DbCommand" entries (logged at Information under the
			// Microsoft.EntityFrameworkCore.Database.Command source). Those are pure SQL noise in the
			// Windows Application event log; Warning / Error from that source (real DB problems) still
			// pass through, and the full-fidelity file sink above keeps everything for debugging.
			logger = logger.WriteTo.Logger(sub => sub
				.Filter.ByExcluding(IsEfCommandInformationOrLower)
				.WriteTo.EventLog(
					source: "RdpAuditService",
					logName: "Application",
					manageEventSource: false));
		}

		builder.Logging.ClearProviders();
		builder.Services.AddSerilog(logger.CreateLogger(), dispose: true);
	}

	/// <summary>True when <paramref name="logEvent"/> is an EF Core database-command log at
	/// Information level or below — the high-volume "Executed DbCommand" SQL trace. Used to keep that
	/// noise out of the Windows Application event log while preserving Warning / Error from the same
	/// source (connection failures, command errors).</summary>
	private static bool IsEfCommandInformationOrLower(Serilog.Events.LogEvent logEvent)
	{
		if (logEvent.Level >= Serilog.Events.LogEventLevel.Warning)
		{
			return false;
		}

		return logEvent.Properties.TryGetValue("SourceContext", out Serilog.Events.LogEventPropertyValue? source)
			&& source is Serilog.Events.ScalarValue { Value: string ctx }
			&& ctx.StartsWith("Microsoft.EntityFrameworkCore.Database.Command", StringComparison.Ordinal);
	}

	// ── Service Composition ──────────────────────────────────────────────────────

	private static void RegisterServices(IServiceCollection services)
	{
		services.AddSingleton<SqlitePragmaInterceptor>();

		if (OperatingSystem.IsWindows())
		{
			services.AddSingleton<IThirdPartyFirewallProbe, WindowsServiceThirdPartyFirewallProbe>();
		}

		services.AddDbContextFactory<AuditDbContext>((sp, options) =>
		{
			IOptions<RdpAuditOptions> opts = sp.GetRequiredService<IOptions<RdpAuditOptions>>();
			string dbPath = Path.GetFullPath(opts.Value.Storage.ResolveDatabasePath());
			string? dbDir = Path.GetDirectoryName(dbPath);
			if (!string.IsNullOrEmpty(dbDir))
			{
				Directory.CreateDirectory(dbDir);
			}

			options
				.UseSqlite($"Data Source={dbPath};Cache=Shared")
				.AddInterceptors(sp.GetRequiredService<SqlitePragmaInterceptor>());
		});

		services.AddSingleton<AuditDbInitializer>();
		services.AddSingleton<IOperationLogWriter, DbOperationLogWriter>();
		services.AddSingleton<OverviewProgressState>();
		services.AddSingleton<CrashGuard>();
		services.AddSingleton<BookmarkStore>();
		services.AddSingleton<EventChannel>();
		services.AddSingleton<ServiceMetrics>();
		services.AddSingleton<SessionCorrelationCache>();
		services.AddSingleton<RdpTransportIpCache>();
		services.AddSingleton<SessionIpCorrelationUpserter>();
		services.AddSingleton<RdpConnectionFactUpserter>();
		services.AddSingleton<AuthAttemptFactUpserter>();
		services.AddSingleton<SecurityCorrelationWatchdog>();
		services.AddSingleton<EventNormalizer>();
		services.AddSingleton<DbAlertContext>();
		services.AddSingleton<IAlertContext>(sp => sp.GetRequiredService<DbAlertContext>());
		services.AddSingleton<AlertCooldownTracker>();
		services.AddSingleton<SettingsManager>();
		services.AddSingleton<SecurityAuthProbeService>();
		services.AddSingleton<FirewallManager>();
		services.AddSingleton<ISecretProtector>(_ => CreateSecretProtector());
		services.AddSingleton<WindowsFirewallProvider>();
		services.AddSingleton<MikroTikFirewallProvider>();
		services.AddSingleton<IPsecBlockProvider>();
		services.AddSingleton<IFirewallProvider>(sp => sp.GetRequiredService<WindowsFirewallProvider>());
		services.AddSingleton<IFirewallProvider>(sp => sp.GetRequiredService<MikroTikFirewallProvider>());
		services.AddSingleton<IFirewallProvider>(sp => sp.GetRequiredService<IPsecBlockProvider>());

		if (OperatingSystem.IsWindows())
		{
			services.AddSingleton<RouteBlackholeProvider>();
			services.AddSingleton<IFirewallProvider>(sp => sp.GetRequiredService<RouteBlackholeProvider>());
			services.AddSingleton<IRdpPortProvider, RegistryRdpPortProvider>();
			services.AddSingleton<IFirewallRuleScanner>(sp => new PowerShellFirewallRuleScanner(
				sp.GetRequiredService<ILogger<PowerShellFirewallRuleScanner>>(),
				sp.GetRequiredService<ILogger<NetshFirewallRuleScanner>>()));
		}
		else
		{
			services.AddSingleton<IFirewallRuleScanner, UnsupportedFirewallRuleScanner>();
		}

		services.AddSingleton<EnforcementReconciliationService>();
		services.AddSingleton<ToolsDiagnosticsService>();
		services.AddSingleton<ApplicationDataPurgeService>();

		if (OperatingSystem.IsWindows())
		{
			services.AddSingleton<RdpSessionManager>();
			services.AddSingleton<ShadowPolicyManager>();
			services.AddSingleton<RdpConfigurationReader>();
		}

		services.AddHttpClient("AbuseIpDb");
		services.AddSingleton<IAbuseIpDbClient, AbuseIpDbClient>();

		services.AddHttpClient(MikroTikClient.HttpClientName);
		services.AddHttpClient(MikroTikClient.HttpClientNameInsecure)
			.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
			{
				ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
			});
		services.AddSingleton<IMikroTikClient, MikroTikClient>();

		services.AddScoped<IpcDispatcher>();

		AlertRuleRegistration.Register(services);

		// ── Ordered hosted-service chain ─────────────────────────────────────────
		// .NET's Generic Host invokes each IHostedService.StartAsync sequentially and synchronously
		// in registration order during host startup (dotnet/runtime#116181); BackgroundService.StartAsync
		// runs every line of ExecuteAsync up to its first await inline, on the SAME thread that is
		// starting the host — so a slow or stuck synchronous prefix in an earlier-registered worker
		// can delay or starve a later-registered one.
		//
		// ORDER RATIONALE:
		//   1. DatabaseInitializationWorker — applies EF migrations FIRST so no later worker (nor
		//      the post-StartAsync LogStartupDiagnostics call in Main) writes to a missing table.
		//   2. IpcServerWorker — the Configurator's only line of sight into the service; must come up
		//      independently of whether the event/security/alert pipeline is slow to initialize.
		//   3. Collectors → processor → correlation → alerts → maintenance → firewall → stats.
		//
		// AttackStatsRefreshWorker MUST precede AbuseIpDbReportWorker and is intentionally close to
		// the processing workers so RDP Activity (AttackStats) is refreshed promptly after events land
		// — a stalled processor previously left it starved (empty AttackStats, healthy Live Events).
		//
		// Every hosted service is wrapped in TimedHostedService so startup-sequence.log records the
		// exact begin/end/duration/failure of each StartAsync in registration order — a BEGIN line
		// with no matching END/FAILED line pinpoints the stuck worker.
		services.AddTimedHostedService<DatabaseInitializationWorker>(nameof(DatabaseInitializationWorker));
		services.AddTimedHostedService<IpcServerWorker>(nameof(IpcServerWorker));

		// EventCollectorWorker and SecurityBackfillWorker use the factory overload (explicit ctor)
		// rather than DI activation. The factory produces the instance that TimedHostedService hosts;
		// no other consumer resolves these types, so a distinct instance is correct and intended.
		services.AddTimedHostedService(sp => new EventCollectorWorker(
			sp.GetRequiredService<EventChannel>(),
			sp.GetRequiredService<BookmarkStore>(),
			sp.GetRequiredService<ServiceMetrics>(),
			sp.GetRequiredService<ILogger<EventCollectorWorker>>(),
			sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>(),
			sp.GetRequiredService<IDbContextFactory<AuditDbContext>>(),
			sp.GetRequiredService<IOperationLogWriter>()), nameof(EventCollectorWorker));

		services.AddTimedHostedService(sp => new SecurityBackfillWorker(
			sp.GetRequiredService<EventChannel>(),
			sp.GetRequiredService<ServiceMetrics>(),
			sp.GetRequiredService<ILogger<SecurityBackfillWorker>>(),
			sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>(),
			sp.GetRequiredService<BookmarkStore>(),
			sp.GetRequiredService<IDbContextFactory<AuditDbContext>>(),
			sp.GetRequiredService<OverviewProgressState>()), nameof(SecurityBackfillWorker));

		services.AddTimedHostedService<EventProcessorWorker>(nameof(EventProcessorWorker));
		services.AddTimedHostedService<SessionCorrelationHydrationWorker>(nameof(SessionCorrelationHydrationWorker));

		// Singleton + hosted-service-resolving-the-singleton so the IPC RebuildAttackStats action can
		// invoke the very same worker instance (sharing its re-entrancy gate) the background loop uses.
		// Registered AHEAD of the alert/maintenance/firewall workers so a stall there cannot starve
		// the RDP Activity refresh — the exact failure mode observed when EventProcessorWorker blocked
		// the startup chain and AttackStats stayed empty.
		services.AddSingleton<AttackStatsRefreshWorker>();
		services.AddTimedHostedService(sp => sp.GetRequiredService<AttackStatsRefreshWorker>(), nameof(AttackStatsRefreshWorker));

		services.AddTimedHostedService<AlertWorker>(nameof(AlertWorker));
		services.AddTimedHostedService<MaintenanceWorker>(nameof(MaintenanceWorker));
		services.AddTimedHostedService<FirewallAutoBlockWorker>(nameof(FirewallAutoBlockWorker));
		services.AddTimedHostedService<FirewallExpirationWorker>(nameof(FirewallExpirationWorker));
		services.AddTimedHostedService<EnforcementReconciliationWorker>(nameof(EnforcementReconciliationWorker));
		services.AddTimedHostedService<AbuseIpDbReportWorker>(nameof(AbuseIpDbReportWorker));
	}

	// ── Hosted-Service Registration Helpers ──────────────────────────────────────

	/// <summary>Registers <typeparamref name="T"/> as a singleton and wraps it in a
	/// <see cref="TimedHostedService"/> so its StartAsync begin/end/duration/failure is recorded to
	/// startup-sequence.log. Equivalent to <c>services.AddHostedService&lt;T&gt;()</c> plus timing.</summary>
	private static void AddTimedHostedService<T>(this IServiceCollection services, string name)
		where T : class, IHostedService
	{
		services.AddSingleton<T>();
		services.AddSingleton<IHostedService>(sp => new TimedHostedService(sp.GetRequiredService<T>(), name));
	}

	/// <summary>Same as the generic overload, for hosted services constructed via an explicit
	/// factory delegate (manual constructor call, or resolving a pre-registered singleton) rather
	/// than DI activation.</summary>
	private static void AddTimedHostedService(
		this IServiceCollection services, Func<IServiceProvider, IHostedService> factory, string name)
	{
		services.AddSingleton<IHostedService>(sp => new TimedHostedService(factory(sp), name));
	}

	// ── Startup Diagnostics Infrastructure ───────────────────────────────────────

	/// <summary>Decorates an <see cref="IHostedService"/> so every StartAsync call logs a begin
	/// timestamp, an end timestamp with elapsed duration, or a failure with the elapsed duration and
	/// exception detail — all to startup-sequence.log, independent of the Serilog pipeline (which may
	/// not have flushed, or may itself be stalled behind the very worker being timed). This is the
	/// direct answer to "which worker is blocking startup": a BEGIN line with no matching END/FAILED
	/// line is the stuck one.</summary>
	private sealed class TimedHostedService : IHostedService
	{
		private readonly IHostedService _inner;
		private readonly string _name;

		public TimedHostedService(IHostedService inner, string name)
		{
			_inner = inner ?? throw new ArgumentNullException(nameof(inner));
			_name = name ?? throw new ArgumentNullException(nameof(name));
		}

		public async Task StartAsync(CancellationToken cancellationToken)
		{
			StartupSequenceLog.Write("StartAsync BEGIN  " + _name);
			Stopwatch sw = Stopwatch.StartNew();
			try
			{
				await _inner.StartAsync(cancellationToken).ConfigureAwait(false);
				StartupSequenceLog.Write("StartAsync END    " + _name + " (" + sw.ElapsedMilliseconds + " ms)");
			}
			catch (Exception ex)
			{
				StartupSequenceLog.Write("StartAsync FAILED " + _name + " (" + sw.ElapsedMilliseconds + " ms): "
					+ ex.GetType().Name + ": " + ex.Message);
				throw;
			}
		}

		public Task StopAsync(CancellationToken cancellationToken) => _inner.StopAsync(cancellationToken);
	}

	/// <summary>Minimal, dependency-free append-only writer for the hosted-service startup sequence
	/// trace. Deliberately bypasses Serilog/DI entirely: the whole point of this log is to diagnose a
	/// startup that never reaches a working logging pipeline (e.g. a worker stuck before the DI
	/// container finishes composing, or Serilog's own sink stalled behind a slow disk/AV filter), so
	/// it must not share any dependency with the thing it is meant to debug. Mirrors
	/// IpcServerWorker.WriteIpcDebugLine's file-size-capped append pattern.</summary>
	private static class StartupSequenceLog
	{
		public static void Write(string line)
		{
			try
			{
				string dir = Path.Combine(
					Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
					"RdpAudit",
					"logs");
				Directory.CreateDirectory(dir);
				string path = Path.Combine(dir, "startup-sequence.log");
				FileInfo fi = new(path);
				if (fi.Exists && fi.Length > 512 * 1024)
				{
					File.Delete(path);
				}

				File.AppendAllText(path, "[" + DateTime.UtcNow.ToString("O") + "] " + line + Environment.NewLine);
			}
			catch (Exception)
			{
				// Never let a diagnostics write take down startup.
			}
		}
	}

	// ── Secret Protection ────────────────────────────────────────────────────────

	private static ISecretProtector CreateSecretProtector()
	{
		if (OperatingSystem.IsWindows())
		{
			return new DpapiSecretProtector();
		}

		// Non-production fallback so the host can boot under non-Windows CI / test rigs without
		// resolving DPAPI. Service production deployments always run on Windows.
		return new InMemorySecretProtector();
	}
}
