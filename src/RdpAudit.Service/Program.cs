/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : Program.cs
// Project: RdpAudit.Service (RdpAudit.Service)
// Purpose: Process entry point - configures host, DI, logging, and ordered worker registrations,
//          and sequences startup so schema migrations complete before any DB-backed diagnostics run.
//          v2.0.2: Wired the v2 event-collection composition - ChannelHealthPolicy singleton,
//          RingBufferEventPipe over the existing EventChannel, EventLogWatcherEventSourceFactory,
//          ServiceMetricsChannelStatusSink, and EventCollectorHost - and swapped the hosted
//          collector from the retired EventCollectorWorker (v2.1.x) to the thin EventCollectorHostedWorker
//          shim. The legacy worker was fully retired in v2.3.x; the shim is now the only
//          registered hosted service for event collection.
//          v2.0.2: Added the pre-host SingleInstanceGuard on Global\RdpAuditService: a second
//          instance (manual publish\Service\RdpAudit.Service.exe run, with or without --console)
//          is refused BEFORE the host is built with the documented exit code 0x1000, so it can
//          never race the IPC named pipe or apply EF migrations.
//          v2.0.1: CrashGuard has no RecordFatal member (CS1061 on build) - reverted the host-level
//          fatal-fault handler to Serilog.Log.Fatal, which is guaranteed available since Serilog is
//          already the global logging pipeline configured by ConfigureSerilog below. This is a
//          host-lifecycle fault (StartAsync/WaitForShutdownAsync threw), distinct from a per-worker
//          fault that CrashGuard's installed handlers already catch.
// Depends: HostApplicationBuilder, AuditDbInitializer, DatabaseInitializationWorker, CrashGuard,
//          Serilog, IOptionsMonitor<RdpAuditOptions>, TimedHostedService, EventCollectorHost,
//          IEventPipe (RingBufferEventPipe), IEventSourceFactory, IChannelStatusSink,
//          SingleInstanceGuard, SingleInstanceExitCodePolicy
// Extends: Register a new worker via AddTimedHostedService in the ordered block inside
//          RegisterServices; add a new DI singleton in the composition block above it. To plug in
//          a different event transport (MPMC ring, shared-memory) register another IEventPipe.
//          To replace the ETW/EventLog collector, register a different IEventSourceFactory.

using RdpAudit.Core.Editions;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Diagnostics;
using RdpAudit.Core.Events;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.RestApi;
using RdpAudit.Core.Security;
using RdpAudit.Core.ThreatIntel;
using RdpAudit.Core.Util;
using RdpAudit.Service.AbuseIpDb;
using RdpAudit.Service.Alerts;
using RdpAudit.Service.Collectors;
using RdpAudit.Service.EventSources;
using RdpAudit.Service.Firewall;
using RdpAudit.Service.Infrastructure;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.ProcessMonitoring;
using RdpAudit.Service.Processors;
using RdpAudit.Service.RestApi;
using RdpAudit.Service.Sessions;
using RdpAudit.Service.Storage;
using RdpAudit.Service.ThreatIntel;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Serilog;
using Serilog.Formatting.Compact;

namespace RdpAudit.Service;

/// <summary>Process entry point - configures host, DI, logging, and worker registrations.</summary>
public static class Program
{
	// ── Public API ───────────────────────────────────────────────────────────────

	public static async Task<int> Main(string[] args)
	{
		bool isConsole = args.Contains("--console", StringComparer.OrdinalIgnoreCase);
		bool isService = !Debugger.IsAttached
			&& !isConsole
			&& WindowsServiceHelpers.IsWindowsService();

		// Legacy code pages (cp437, cp866, cp1251, ...) must be resolvable before the console stream
		// is pinned below or any console tool is spawned with an OEM decoder. The registration is
		// idempotent, so doing it here is harmless even though OemConsoleEncoding also does it.
		System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);

		if (isConsole)
		{
			// Pin the console stream explicitly. Measured on this host: a redirected .NET console
			// stream is NOT UTF-8 by default - the child reported code page 437 and UTF-8 bytes on
			// that pipe arrived as mojibake - so the one deliberate console line below would reach
			// an operator as garbage the moment it gains a culture-specific part. The Windows event
			// log and Serilog are unaffected by this.
			// No preamble is emitted either: measured, a redirected .NET console stream starts with
			// the first character, so a reader gets no stray BOM bytes to strip. UTF8Encoding(false)
			// states that intent rather than relying on the default.
			Console.OutputEncoding = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
		}

		WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
		{
			Args = args,
		});

		// The worker host itself exposes NO TCP surface: the read-only REST API owns its own
		// Kestrel listener inside RestApiHostedService (fail-closed plan), so the outer host
		// runs over an inert server that binds no sockets (verified: no localhost:5000 fallback
		// bind, unlike the default Kestrel).
		builder.WebHost.UseServer(new InertWebServer());

		RdpAuditPaths programPaths = RdpAuditPaths.Default;
		string configPath = programPaths.AppSettingsPath;
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

		// Fail closed on the encryption-at-rest setting BEFORE anything opens the store. A configuration that
		// claims the evidence store is encrypted while this build encrypts nothing is the one thing that must
		// never start: the operator would be making decisions on a false assurance taken from the product's own
		// settings file. See docs/89-encryption-at-rest-decision.md.
		RdpAuditOptions startupOptions = builder.Configuration
			.GetSection(RdpAuditOptions.SectionName)
			.Get<RdpAuditOptions>() ?? new RdpAuditOptions();
		string? encryptionWarning = StorageEncryptionGuard.AssertSupported(startupOptions.Storage.Encryption);
		builder.Services.AddSingleton(new StorageEncryptionStartupNote(encryptionWarning));

		// Single source of truth for every runtime path (D2). Production resolves through
		// RdpAuditPaths.Default; tests register a fake rooted at a temp directory.
		builder.Services.AddSingleton<IRdpAuditPathsProvider, DefaultRdpAuditPathsProvider>();

		// Singleton recorder for the most recent monitoring-config repair (surfaced via the
		// Diagnostic IPC command).
		builder.Services.AddSingleton<ConfigRepairReporter>();

		// Repair stale appsettings.json before any worker consumes the effective MonitoringOptions.
		// A pre-v3 config that pruned EnabledChannels (no Security) or wrote a partial EnabledEventIds
		// filter would otherwise leave the Security watcher disarmed at startup. The repair is
		// idempotent and runs every time options are materialized (including IOptionsMonitor reloads),
		// so an operator who hand-edits appsettings.json with the Configurator open also benefits.
		builder.Services.AddSingleton<IPostConfigureOptions<RdpAuditOptions>, MonitoringConfigPostConfigure>();

		ConfigureSerilog(builder, programPaths.LogDirectory);

		// ── Single-Instance Guard ───────────────────────────────────────────────
		// Acquire the Global\RdpAuditService mutex BEFORE the host is built and BEFORE any DI
		// service is registered: a second process (manual publish\Service\RdpAudit.Service.exe run,
		// with or without --console) must be refused here so it can never race the IPC named pipe,
		// apply EF migrations, or start a duplicate event collector. The synchronous TryAcquire
		// uses a zero-timeout wait and runs on the startup thread before any hosted service exists,
		// so it cannot block a service event loop; no async/Task/CancellationToken surface is
		// needed at this stage.
		using SingleInstanceGuard singleInstanceGuard = new(SingleInstanceGuard.DefaultMutexName);

		SingleInstanceAcquireResult acquireResult;
		try
		{
			acquireResult = singleInstanceGuard.TryAcquire();
		}
		catch (Exception ex) when (ex is Win32Exception || ex is UnauthorizedAccessException)
		{
			// A caller without rights in the mutex DACL fails to open the existing kernel object
			// even though it exists. That is still a refusal: the expected state is a single owner
			// and the actual state is the native error, reported through the same structured path
			// and the same documented exit code.
			return RefuseStartupSingleInstance(ex.Message, isConsole);
		}

		if (acquireResult.FallbackToDefaultAcl)
		{
			Log.Warning(
				"Single-instance mutex was created without the explicit LocalSystem/Administrators DACL; process-default ACL applies: {MutexName}",
				SingleInstanceGuard.DefaultMutexName);
		}

		if (acquireResult.Status == SingleInstanceAcquireStatus.RecoveredAbandoned)
		{
			Log.Warning(
				"Ownership of an abandoned single-instance mutex was recovered; startup continues: {MutexName}",
				SingleInstanceGuard.DefaultMutexName);
		}

		if (acquireResult.Status == SingleInstanceAcquireStatus.AlreadyRunning)
		{
			// The mutex exists and is held by a live RdpAuditService process: refuse this instance.
			return RefuseStartupSingleInstance(
				"the mutex is already owned by a running RdpAuditService process",
				isConsole);
		}

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

		await using WebApplication app = builder.Build();

		// Install last-resort crash diagnostics before anything else can fault. From this point a
		// fault anywhere in the process is recorded as a Critical OperationLog (DB permitting) and
		// always to the Windows Event Log and a fallback file, instead of dying silently.
		CrashGuard crashGuard = app.Services.GetRequiredService<CrashGuard>();
		crashGuard.Install();

		try
		{
			// StartAsync runs the ordered hosted-service chain, whose FIRST member
			// (DatabaseInitializationWorker) applies EF migrations. Only AFTER it returns is the
			// schema guaranteed present - so the DB-backed startup diagnostic below can safely write
			// to OperationLogs. Emitting LogStartupDiagnostics before StartAsync was the direct cause
			// of the "SQLite Error 1: 'no such table: OperationLogs'" on first launch, because the
			// OperationLog INSERT raced ahead of the V133OperationLogs migration.
			// StartAsync starts both the Kestrel server and the ordered hosted-service chain, whose
			// FIRST member (DatabaseInitializationWorker) applies EF migrations.
			await app.StartAsync().ConfigureAwait(false);

			RdpAuditOptions effectiveOptions = app.Services.GetRequiredService<IOptions<RdpAuditOptions>>().Value;
			crashGuard.LogStartupDiagnostics(effectiveOptions, configPath);

			// The encryption-at-rest assertion already ran (fail-closed) before the host was built; its
			// non-fatal note - the one case where a mode is honoured but the product cannot verify it - is
			// logged here, where the Serilog pipeline is guaranteed to be up.
			string? encryptionNote = app.Services.GetRequiredService<StorageEncryptionStartupNote>().Warning;
			if (!string.IsNullOrEmpty(encryptionNote))
			{
				Log.Warning("Encryption at rest: {Note}", encryptionNote);
			}

			await app.WaitForShutdownAsync().ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			// Last-resort: the host itself failed to start or shut down cleanly. This is a
			// host-lifecycle fault (StartAsync / WaitForShutdownAsync threw before or outside any
			// individual worker's own exception handling), distinct from the per-worker faults
			// CrashGuard.Install() already intercepts. CrashGuard exposes no RecordFatal member, so
			// log directly via Serilog.Log - the global logging pipeline is already fully configured
			// at this point (file sink + Windows Event Log sink from ConfigureSerilog), guaranteeing
			// this fault is captured even if the DB-backed OperationLog path is unavailable.
			Log.Fatal(ex, "Host failed to start or shut down cleanly");
			return 1;
		}

		return 0;
	}

	// ── Single-Instance Refusal Path ─────────────────────────────────────────

	/// <summary>Emits the single structured refusal event and returns the documented project exit
	/// code (<see cref="SingleInstanceExitCodePolicy.AlreadyRunningExitCode"/>). ExpectedState is
	/// the designed single-owner state; ActualState carries the concrete reason the process could
	/// not reach it. Console mode additionally writes one plain English line to stderr so an
	/// operator launching publish\Service\RdpAudit.Service.exe --console sees the cause without
	/// opening a log file.</summary>
	private static int RefuseStartupSingleInstance(string actualReason, bool isConsole)
	{
		const int exitCode = SingleInstanceExitCodePolicy.AlreadyRunningExitCode;

		if (isConsole)
		{
			// Deliberately plain console output (not a Serilog template): the operator typed a
			// command and expects the answer right there. Console.OutputEncoding was pinned to UTF-8
			// at the top of Main, so this line survives a redirected pipe on any locale - and the
			// console stream carries ONE encoding, not one per writer.
			Console.Error.WriteLine(
				"RdpAuditService is already running. This instance cannot start: single-instance " +
				"mutex " + SingleInstanceGuard.DefaultMutexName + " refused startup (pid " +
				Environment.ProcessId.ToString(CultureInfo.InvariantCulture) + ", exit code 0x" +
				exitCode.ToString("X", CultureInfo.InvariantCulture) + ").");
		}

		Log.Error(
			"Startup refused by the single-instance guard: ExpectedState={ExpectedState}, ActualState={ActualState}, MutexName={MutexName}, ProcessId={ProcessId}, StartMode={StartMode}, ExitCode={ExitCode}",
			"single RdpAuditService owner",
			actualReason,
			SingleInstanceGuard.DefaultMutexName,
			Environment.ProcessId,
			isConsole ? "console" : "service",
			exitCode);

		return exitCode;
	}

	// ── Logging Configuration ────────────────────────────────────────────────────

	private static void ConfigureSerilog(WebApplicationBuilder builder, string logDir)
{
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
			// The same predicate the Event Log sink uses below. EF Core writes one "Executed DbCommand"
			// record per command (with the SQL text and the parameters) and a batch commit issues about
			// seven of them, so on a busy host this single sink was producing hundreds of megabytes of
			// SQL noise per day. Warning / Error from the same source and every other Information record
			// still pass: IsEfCommandInformationOrLower excludes only Level < Warning for that category.
			// The RDPAudit_DEBUG_Log.txt mirror (DebugMode only) keeps the full stream for support.
			.WriteTo.Logger(sub => sub
				.Filter.ByExcluding(IsEfCommandInformationOrLower)
				.WriteTo.File(
					new CompactJsonFormatter(),
					Path.Combine(logDir, RdpAuditPaths.ServiceLogFilePrefix + RdpAuditPaths.ServiceLogExtension),
					rollingInterval: RollingInterval.Day,
					retainedFileCountLimit: 90));

		if (debugMode)
		{
			// Persistent, human-readable DEBUG mirror requested by operators for support bundles:
			// every log event (all workers, all sinks) is duplicated here regardless of source, with
			// no rolling-by-day split, capped by size instead so a single file is always the target
			// of the Settings tab "Open debug log" link. Lives under the same logs\ folder as the
			// structured sinks, and timestamps are normalized to UTC with an explicit 'Z' suffix so
			// support bundles collected in different timezones compare directly.
			string debugLogPath = Path.Combine(logDir, RdpAuditPaths.DebugLogFileName);
			logger = logger.WriteTo.Logger(sub => sub
				.Enrich.With<UtcTimestampEnricher>()
				.WriteTo.File(
					debugLogPath,
					restrictedToMinimumLevel: Serilog.Events.LogEventLevel.Debug,
					rollingInterval: RollingInterval.Infinite,
					rollOnFileSizeLimit: true,
					fileSizeLimitBytes: 50 * 1024 * 1024,
					retainedFileCountLimit: 5,
					shared: true,
					outputTemplate: "[{UtcTimestamp:yyyy-MM-dd HH:mm:ss.fff'Z'} {Level:u3}] {SourceContext}{NewLine}\t{Message:lj}{NewLine}{Exception}"));
		}

		if (OperatingSystem.IsWindows())
		{
			// Route the EventLog sink through a sub-logger that drops EF Core's per-statement
			// "Executed DbCommand" entries (logged at Information under the
			// Microsoft.EntityFrameworkCore.Database.Command source). Those are pure SQL noise in the
			// Windows Application event log; Warning / Error from that source (real DB problems) still
			// pass through. The day-rolling file sink above applies the same predicate; the
			// RDPAudit_DEBUG_Log.txt mirror (DebugMode only) keeps the full stream for support.
			logger = logger.WriteTo.Logger(sub => sub
				.Filter.ByExcluding(IsEfCommandInformationOrLower)
				.WriteTo.EventLog(
					source: "RdpAuditService",
					logName: "Application",
					manageEventSource: false));
		}

		Serilog.Core.Logger serilogLogger = logger.CreateLogger();

		// Publish the logger to Serilog's static Log surface so the pre-host single-instance guard
		// (and any other pre-host startup diagnostic) can emit structured events through the same
		// pipeline the host will use.
		Log.Logger = serilogLogger;

		builder.Logging.ClearProviders();
		builder.Services.AddSerilog(serilogLogger, dispose: true);
	}

	/// <summary>True when <paramref name="logEvent"/> is an EF Core database-command log at
	/// Information level or below - the high-volume "Executed DbCommand" SQL trace. Used to keep that
	/// noise out of the day-rolling file sink and the Windows Application event log while preserving
	/// Warning / Error from the same source (connection failures, command errors) and every
	/// Information record from any other source.</summary>
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
				.UseSqlite(AuditDbContextOptionsFactory.BuildConnectionString(dbPath))
				.AddInterceptors(sp.GetRequiredService<SqlitePragmaInterceptor>());
			AuditDbContextOptions.ApplyWarningPolicy(options);
		});

		// Registered through an explicit factory so the initializer receives the effective options: it re-asserts
		// the encryption-at-rest guard immediately before it opens the store (defence in depth behind the
		// pre-host assertion in Main).
		services.AddSingleton(sp => new AuditDbInitializer(
			sp.GetRequiredService<IDbContextFactory<AuditDbContext>>(),
			sp.GetRequiredService<ILogger<AuditDbInitializer>>(),
			sp.GetService<IPreMigrationBackupProvider>(),
			sp.GetRequiredService<IOptions<RdpAuditOptions>>().Value));
		services.AddSingleton<IOperationLogWriter, DbOperationLogWriter>();
		services.AddSingleton<OverviewProgressState>();
		services.AddSingleton<CrashGuard>();
		services.AddSingleton<BookmarkStore>();

		// Unified bookmark commit (spec section D). Registering the ledger is what switches both
		// EventCollectorHost and EventProcessorWorker out of the legacy split commit: the collector
		// stops publishing positions ahead of persistence, and the processor writes each bookmark
		// inside the same SQLite transaction as the events it covers. Remove this single line to
		// fall back to the v1 behaviour.
		services.AddSingleton<BookmarkCheckpointLedger>();
		services.AddSingleton<EventChannel>();
		services.AddSingleton<ServiceMetrics>();
		services.AddSingleton(sp =>
		{
			MonitoringOptions monitoring = sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>().CurrentValue.Monitoring;
			return new EventFloodGuard(
				monitoring.FloodGuardBucketCount,
				TimeSpan.FromSeconds(Math.Max(1, monitoring.FloodGuardWindowSeconds)),
				monitoring.FloodGuardSoftThreshold,
				monitoring.FloodGuardHardThreshold,
				monitoring.FloodGuardSampleEveryN);
		});

		// v2 event-collection composition. The IEventPipe adapter reuses the same underlying
		// ring-buffer instance that lives inside EventChannel, so every hosted worker - the
		// EventCollectorHostedWorker producer, the SecurityBackfillWorker producer (iter16), and
		// the EventProcessorWorker consumer (iter17) - shares a single physical transport with
		// no duplication, no dropped pipeline hop, and a semaphore-backed wake on every write.
		services.AddSingleton<ChannelHealthPolicy>();
		services.AddSingleton<RingBufferEventPipe>(sp =>
			new RingBufferEventPipe(sp.GetRequiredService<EventChannel>()));
		services.AddSingleton<IEventPipe>(sp => new FloodGuardEventPipe(
			sp.GetRequiredService<RingBufferEventPipe>(),
			sp.GetRequiredService<EventFloodGuard>(),
			sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>(),
			sp.GetRequiredService<ServiceMetrics>()));
		// IngestionMode selection: pick the transport factory once at startup and log the
		// decision so operators can confirm which transport is armed. IngestionMode.Etw
		// fail-fasts when the probe declines (throws at first resolution). Auto silently
		// falls back to EventLog and records the reason. See EventSourceFactorySelector
		// for the pure selection matrix and MonitoringConfigRepair for the out-of-range
		// clamp that this branch relies on.
		services.AddSingleton<EventLogWatcherEventSourceFactory>();
		services.AddSingleton<EtwEventSourceFactory>();
		services.AddSingleton<HybridEventSourceFactory>();
		services.AddSingleton<IEventSourceFactory>(sp =>
		{
			var options = sp.GetRequiredService<IOptions<RdpAuditOptions>>().Value;
			var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("RdpAudit.Service.EventSources.IngestionModeSelector");
			var requested = options.Monitoring.IngestionMode;

			var selection = EventSourceFactorySelector.Select(
				requested,
				// commit 3c: real ETW probe. Runs once per service start. Returns Ok=true when the
				// host is Windows and the current process is elevated enough to open a real-time
				// TraceEventSession. See EtwAvailabilityProbe for the exact conditions.
				EtwAvailabilityProbe.Probe);

			if (selection.RequestedMode == IngestionMode.Etw &&
				selection.ChosenTransport == IngestionMode.Etw &&
				selection.FallbackReason is not null)
			{
				// Fail-fast contract: operator asked for Etw explicitly and probe declined.
				logger.LogCritical(
					"IngestionMode=Etw requested but ETW is unavailable: {Reason}",
					selection.FallbackReason);
				throw new InvalidOperationException(
					"IngestionMode=Etw requested but ETW is unavailable: " + selection.FallbackReason);
			}

			if (selection.FallbackReason is not null)
			{
				logger.LogWarning(
					"IngestionMode={Requested} resolved to {Chosen}: {Reason}",
					selection.RequestedMode,
					selection.ChosenTransport,
					selection.FallbackReason);
			}
			else
			{
				logger.LogInformation(
					"Event ingestion transport: {Chosen} (IngestionMode={Requested}).",
					selection.ChosenTransport,
					selection.RequestedMode);
			}

			return selection.ChosenTransport switch
			{
				// IngestionMode.Etw does NOT mean "every channel via ETW". It means "prefer ETW
				// where possible, fall back to EventLog per channel". The HybridEventSourceFactory
				// consults EtwProviderMap at Create time and routes each channel independently.
				IngestionMode.Etw => sp.GetRequiredService<HybridEventSourceFactory>(),
				_ => sp.GetRequiredService<EventLogWatcherEventSourceFactory>(),
			};
		});
		services.AddSingleton<IChannelStatusSink, ServiceMetricsChannelStatusSink>();
		services.AddSingleton<EventCollectorHost>();
		services.AddSingleton<SessionCorrelationCache>();
		services.AddSingleton<RdpTransportIpCache>();
		services.AddSingleton<SessionIpCorrelationUpserter>();
		services.AddSingleton<RdpConnectionFactUpserter>();
		services.AddSingleton<AuthAttemptFactUpserter>();
		services.AddSingleton<IpEventSummaryUpserter>();
		services.AddSingleton<ShardIngestionSink>();
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
			services.AddSingleton<IExternalCommandRunner, ExternalCommandRunner>();
			services.AddSingleton<IFirewallRuleScanner>(sp => new PowerShellFirewallRuleScanner(
				sp.GetRequiredService<ILogger<PowerShellFirewallRuleScanner>>(),
				sp.GetRequiredService<IExternalCommandRunner>(),
				new NetshFirewallRuleScanner(sp.GetRequiredService<ILogger<NetshFirewallRuleScanner>>()),
				sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>(),
				reportBackend: sp.GetRequiredService<ServiceMetrics>().RecordFirewallScanBackend));
		}
		else
		{
			services.AddSingleton<IFirewallRuleScanner, UnsupportedFirewallRuleScanner>();
		}

		services.AddSingleton<EnforcementReconciliationService>();
		services.AddSingleton<ToolsDiagnosticsService>();
		services.AddSingleton<ApplicationDataPurgeService>();

		// Stage 2a Database-tab data services (IPC ordinals 80-84). Scoped like IpcDispatcher so every
		// command gets a clean reader/writer. The information-density engine they build internally is
		// stateless, so the dry-run preview and the background pass still evaluate identical rules on
		// identical option snapshots - which is what makes the preview a prediction, not an estimate.
		services.AddScoped<DatabaseOverviewService>();
		services.AddScoped<RetentionPolicyService>();
		services.AddScoped<RetentionPreviewService>();
		services.AddScoped<DeletionLedgerQueryService>();

		// Stage 2b database snapshots (IPC ordinals 85-87 and the pre-migration guard). Registered as
		// one singleton instance shared by two roles: the IPC surface creates, lists and verifies
		// snapshots, and AuditDbInitializer asks the same object for the mandatory pre-migration
		// snapshot through IPreMigrationBackupProvider. One instance means one set of effective options
		// and one retention policy, so the snapshot the initializer demands and the snapshot an
		// operator creates are the same artifact in the same folder. The service is stateless between
		// calls, so a singleton cannot carry state across operations.
		services.AddSingleton<DatabaseBackupService>();
		services.AddSingleton<IPreMigrationBackupProvider>(sp => sp.GetRequiredService<DatabaseBackupService>());

		// Stage 3 Database-tab UI support (IPC ordinals 88-90). Scoped like the other per-command
		// services so every call gets a clean reader; both are stateless and neither mutates the
		// evidence store (the inventory is a read-only projection, the maintenance surface runs only
		// read-safe pragmas), so a scope boundary cannot lose state an operator asked for.
		services.AddScoped<ShardInventoryService>();
		services.AddScoped<DatabaseMaintenanceService>();

		// Stage 4 shard capacity governance (IPC ordinals 91-92). The policy writer is scoped like the
		// other per-command services; the orphan collector additionally reads the live shard sink's
		// open-writer set, which is registered as a singleton above, so a deletion can never race a
		// writer that still has the shard mapped.
		services.AddScoped<ShardingPolicyService>();
		services.AddScoped<ShardGarbageCollectorService>();

		// Stage 5 storage hardening (IPC ordinals 93-94). Both are scoped like the other per-command
		// services. The compaction refusal only reads page accounting; the subject purge opens one context
		// per call and deletes in bounded batches, so a scope boundary per command keeps its connection
		// lifetime as short as the command itself.
		services.AddScoped<DatabaseCompactionService>();
		services.AddScoped<PurgeBySubjectService>();

		// Stage 5 store integrity (documented in docs/88 and docs/41). The fingerprint store and the
		// integrity service are SINGLETONS: the shutdown worker, the maintenance worker and the database
		// initializer must all resolve the same instance, because they read and write the same fingerprint
		// chain and any state carried between them would be a correctness bug rather than a cache.
		// The store is built explicitly because three of its dependencies are optional for other hosts but
		// mandatory here (B19): the path provider, the secret protector that SEALS the chain tip, and the
		// sink that mirrors the key facts outside %ProgramData%.
		services.AddSingleton<IStoreFingerprintAlarmSink, WindowsEventLogStoreFingerprintAlarmSink>();
		services.AddSingleton(sp => new StoreFingerprintStore(
			sp.GetRequiredService<IRdpAuditPathsProvider>(),
			sp.GetRequiredService<ISecretProtector>(),
			sp.GetRequiredService<IStoreFingerprintAlarmSink>(),
			sp.GetRequiredService<ILogger<StoreFingerprintStore>>()));
		services.AddSingleton<StoreIntegrityService>();

		// Stage 5 storage ACL: a singleton because the start-up verification and the Database-tab overview
		// must report the same assessment, and the enforcer holds no per-call state beyond the last result.
		services.AddSingleton<RdpAudit.Service.Security.StorageAclEnforcer>();

		if (OperatingSystem.IsWindows())
		{
			services.AddSingleton<RdpSessionManager>();
			services.AddSingleton<ShadowPolicyManager>();
			services.AddSingleton<RdpConfigurationReader>();
		}

		services.AddHttpClient("AbuseIpDb");
		services.AddSingleton<IAbuseIpDbClient, AbuseIpDbClient>();

		// Backlog #5 threat-intel reputation lookup. The IPC request path reads ONLY cache rows
		// through ThreatIntelLookupStore - the actual /api/v2/check HTTP calls happen exclusively
		// here, in the background enrichment worker. Fail-closed at every layer.
		services.AddSingleton<IThreatIntelligenceClient, AbuseIpDbThreatIntelClient>();
		services.AddSingleton(TimeProvider.System);
		services.AddSingleton<ThreatIntelLookupStore>();
		services.AddSingleton<KnownProcessStore>();
		services.AddSingleton<ThreatIntelRateLimiter>(sp => new ThreatIntelRateLimiter(TimeProvider.System));

		services.AddHttpClient(MikroTikClient.HttpClientName);
		services.AddHttpClient(MikroTikClient.HttpClientNameInsecure)
			.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
			{
				ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
			});
		services.AddSingleton<IMikroTikClient, MikroTikClient>();

		// Zabbix integration: the push client (trapper protocol) and the provisioning client
		// (JSON-RPC). Two named HttpClient registrations mirror the MikroTik precedent so the
		// certificate-validation exemption is an explicit, separate pipeline.
		services.AddHttpClient(Zabbix.ZabbixApiClient.HttpClientName);
		services.AddHttpClient(Zabbix.ZabbixApiClient.HttpClientNameInsecure)
			.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
			{
				ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
			});
		services.AddSingleton<Zabbix.IZabbixSender, Zabbix.ZabbixSenderClient>();
		services.AddSingleton<Zabbix.IZabbixApiClient, Zabbix.ZabbixApiClient>();
		services.AddSingleton<Zabbix.ZabbixPushStateStore>();
		services.AddSingleton<Zabbix.ZabbixPushService>();

		services.AddScoped<IpcDispatcher>();
		services.AddScoped<SessionTimelineQueryService>();

		// Read-only REST API (roadmap backlog #3). The hosted service builds the fail-closed plan
		// at start and owns its own Kestrel listener; registered after IpcServerWorker so the
		// database migrations (DatabaseInitializationWorker) have already completed before the
		// API can accept requests.
		services.AddSingleton<IRestApiCertificateResolver, RestApiCertificateResolver>();
		services.AddSingleton<RestApiHostedService>();

		// The /events endpoint reads through its own Mode=ReadOnly context factory: queries over
		// this reader physically cannot write to the database, regardless of future handler bugs.
		services.AddSingleton<IPagedEventReader>(sp => new PagedEventReader(
			new ReadOnlyAuditDbContextFactory(sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>())));

		AlertRuleRegistration.Register(services);

		// ── Ordered hosted-service chain ─────────────────────────────────────────
		// .NET's Generic Host invokes each IHostedService.StartAsync sequentially and synchronously
		// in registration order during host startup (dotnet/runtime#116181); BackgroundService.StartAsync
		// runs every line of ExecuteAsync up to its first await inline, on the SAME thread that is
		// starting the host - so a slow or stuck synchronous prefix in an earlier-registered worker
		// can delay or starve a later-registered one.
		//
		// ORDER RATIONALE:
		//   0. StoreIntegrityWorker - registered FIRST so its StopAsync runs LAST (the Generic Host stops
		//      hosted services in reverse registration order). Its StartAsync is a no-op; it exists to take the
		//      store fingerprint after every writer has stopped, which is the only baseline that can support a
		//      conclusion about rows that disappeared while the service was not running.
		//   1. DatabaseInitializationWorker - applies EF migrations FIRST so no later worker (nor
		//      the post-StartAsync LogStartupDiagnostics call in Main) writes to a missing table.
		//   2. IpcServerWorker - the Configurator's only line of sight into the service; must come up
		//      independently of whether the event/security/alert pipeline is slow to initialize.
		//   3. Collectors → processor → correlation → alerts → maintenance → firewall → stats.
		//
		// AttackStatsRefreshWorker MUST precede AbuseIpDbReportWorker and is intentionally close to
		// the processing workers so RDP Activity (AttackStats) is refreshed promptly after events land
		// - a stalled processor previously left it starved (empty AttackStats, healthy Live Events).
		//
		// Every hosted service is wrapped in TimedHostedService so startup-sequence.log records the
		// exact begin/end/duration/failure of each StartAsync in registration order - a BEGIN line
		// with no matching END/FAILED line pinpoints the stuck worker.
		// 0. EditionAnnouncementWorker — records the edition of THIS binary and every configured
		//    feature the build does not contain, so a Pro feature requested on a Community install is
		//    an explicit warning in the log instead of a silently idle subsystem.
		services.AddTimedHostedService<EditionAnnouncementWorker>(nameof(EditionAnnouncementWorker));
		services.AddTimedHostedService<StoreIntegrityWorker>(nameof(StoreIntegrityWorker));
		services.AddTimedHostedService<DatabaseInitializationWorker>(nameof(DatabaseInitializationWorker));
		services.AddTimedHostedService<IpcServerWorker>(nameof(IpcServerWorker));
		// Edition gate: the read-only REST API is a Pro capability. A Community build registers the
		// service for diagnostics but never starts a listener, so the port is closed by construction.
		if (EditionContext.Allows(EditionFeature.RestApi))
		{
			services.AddTimedHostedService(sp => sp.GetRequiredService<RestApiHostedService>(), nameof(RestApiHostedService));
		}

		// v2 collector: EventCollectorHostedWorker is a thin BackgroundService shim that composes
		// EventCollectorHost + IEventSourceFactory + IEventPipe. The legacy monolithic
		// EventCollectorWorker class was retired in v2.3.x; this shim is the only registered
		// hosted service for event collection.
		// SecurityBackfillWorker still uses the factory overload (explicit ctor) so it can bind
		// its 6 dependencies deterministically without DI activation gymnastics.
		services.AddTimedHostedService(sp => new EventCollectorHostedWorker(
			sp.GetRequiredService<EventCollectorHost>(),
			sp.GetRequiredService<BookmarkStore>(),
			sp.GetRequiredService<ChannelHealthPolicy>(),
			sp.GetRequiredService<ServiceMetrics>(),
			sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>(),
			sp.GetRequiredService<ILogger<EventCollectorHostedWorker>>(),
			sp.GetRequiredService<IDbContextFactory<AuditDbContext>>(),
			sp.GetRequiredService<IOperationLogWriter>()), nameof(EventCollectorHostedWorker));

		// iter16: SecurityBackfillWorker writes through IEventPipe so the semaphore-backed
		// WaitToReadAsync consumer wakes on every backfill event. The pipe wraps the same
		// physical ring buffer EventChannel exposes - no duplication, no dropped pipeline hop.
		services.AddTimedHostedService(sp => new SecurityBackfillWorker(
			sp.GetRequiredService<IEventPipe>(),
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
		// the RDP Activity refresh - the exact failure mode observed when EventProcessorWorker blocked
		// the startup chain and AttackStats stayed empty.
		services.AddSingleton<AttackStatsRefreshWorker>();
		services.AddTimedHostedService(sp => sp.GetRequiredService<AttackStatsRefreshWorker>(), nameof(AttackStatsRefreshWorker));

		services.AddTimedHostedService<AlertWorker>(nameof(AlertWorker));
		services.AddTimedHostedService<RetentionWorker>(nameof(RetentionWorker));
		// Information-density retention (Storage.RetentionPolicy). Registered immediately after
		// RetentionWorker so the age windows own their pruning first and the pressure pass only ever
		// sees what the age windows left behind. Disabled by default: with
		// Storage.RetentionPolicy.Enabled=false the worker does no work and writes nothing.
		services.AddTimedHostedService<InformationDensityRetentionWorker>(nameof(InformationDensityRetentionWorker));
		services.AddTimedHostedService<MaintenanceWorker>(nameof(MaintenanceWorker));
		// Edition gate: cross-host correlation is a Pro capability.
		if (EditionContext.Allows(EditionFeature.CrossHostCorrelation))
		{
			services.AddTimedHostedService<CrossHostCorrelationWorker>(nameof(CrossHostCorrelationWorker));
		}
		services.AddTimedHostedService<FirewallAutoBlockWorker>(nameof(FirewallAutoBlockWorker));
		services.AddTimedHostedService<FirewallExpirationWorker>(nameof(FirewallExpirationWorker));
		services.AddTimedHostedService<EnforcementReconciliationWorker>(nameof(EnforcementReconciliationWorker));
		services.AddTimedHostedService<AbuseIpDbReportWorker>(nameof(AbuseIpDbReportWorker));
		services.AddTimedHostedService<ThreatIntelEnrichmentWorker>(nameof(ThreatIntelEnrichmentWorker));
		services.AddTimedHostedService<ProcessAlertAutoResponder>(nameof(ProcessAlertAutoResponder));
		// Zabbix push: last in the chain on purpose. It is an outbound notification channel, so a
		// slow remote server must never delay ingestion, alerting or enforcement at startup.
		// Edition gate: the Zabbix push channel is a Pro capability.
		if (EditionContext.Allows(EditionFeature.ZabbixIntegration))
		{
			services.AddTimedHostedService<Zabbix.ZabbixPushWorker>(nameof(Zabbix.ZabbixPushWorker));
		}
	}

	// ── Hosted-Service Registration Helpers ──────────────────────────────────────

	/// <summary>Registers <typeparamref name="T"/> as a singleton and wraps it in a
	/// <see cref="TimedHostedService"/> so its StartAsync begin/end/duration/failure is recorded to
	/// startup-sequence.log. Equivalent to <c>services.AddHostedService&lt;T&gt;()</c> plus timing.</summary>
	private static void AddTimedHostedService<T>(this IServiceCollection services, string name)
		where T : class, IHostedService
	{
		services.AddSingleton<T>();
		services.AddSingleton<IHostedService>(sp => new TimedHostedService(
			sp.GetRequiredService<T>(), name, ResolveStartupSequenceLogPath(sp)));
	}

	/// <summary>Same as the generic overload, for hosted services constructed via an explicit
	/// factory delegate (manual constructor call, or resolving a pre-registered singleton) rather
	/// than DI activation.</summary>
	private static void AddTimedHostedService(
		this IServiceCollection services, Func<IServiceProvider, IHostedService> factory, string name)
	{
		services.AddSingleton<IHostedService>(sp => new TimedHostedService(
			factory(sp), name, ResolveStartupSequenceLogPath(sp)));
	}

	/// <summary>Resolves the startup-sequence log path from the registered
	/// <see cref="IRdpAuditPathsProvider"/>, or null when none is in scope (tests / stubbed
	/// providers). A null path keeps TimedHostedService's startup trace silent (D2 guard).</summary>
	private static string? ResolveStartupSequenceLogPath(IServiceProvider sp)
		=> (sp.GetService(typeof(IRdpAuditPathsProvider)) as IRdpAuditPathsProvider)
			?.Paths.StartupSequenceLogPath;

	// ── Startup Diagnostics Infrastructure ───────────────────────────────────────

	/// <summary>Decorates an <see cref="IHostedService"/> so every StartAsync call logs a begin
	/// timestamp, an end timestamp with elapsed duration, or a failure with the elapsed duration and
	/// exception detail - all to startup-sequence.log, independent of the Serilog pipeline (which may
	/// not have flushed, or may itself be stalled behind the very worker being timed). This is the
	/// direct answer to "which worker is blocking startup": a BEGIN line with no matching END/FAILED
	/// line is the stuck one.</summary>
	internal sealed class TimedHostedService : IHostedService
	{
		private readonly IHostedService _inner;
		private readonly string _name;
		private readonly string? _startupSequenceLogPath;

		public TimedHostedService(IHostedService inner, string name, string? startupSequenceLogPath = null)
		{
			_inner = inner ?? throw new ArgumentNullException(nameof(inner));
			_name = name ?? throw new ArgumentNullException(nameof(name));
			_startupSequenceLogPath = startupSequenceLogPath;
		}

	/// <summary>Registered hosted-service name passed by <see cref="AddTimedHostedService{T}"/>; used by
	/// composition-root tests to assert exactly one registration per worker without starting the host.</summary>
	internal string Name => _name;

	/// <summary>The wrapped hosted service instance.</summary>
	internal IHostedService Inner => _inner;

	public async Task StartAsync(CancellationToken cancellationToken)
	{
		StartupSequenceLog.Write(_startupSequenceLogPath, "StartAsync BEGIN  " + _name);
		Stopwatch sw = Stopwatch.StartNew();
		try
		{
			await _inner.StartAsync(cancellationToken).ConfigureAwait(false);
			StartupSequenceLog.Write(_startupSequenceLogPath, "StartAsync END    " + _name + " (" + sw.ElapsedMilliseconds + " ms)");
		}
		catch (Exception ex)
		{
			StartupSequenceLog.Write(_startupSequenceLogPath, "StartAsync FAILED " + _name + " (" + sw.ElapsedMilliseconds + " ms): "
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
		public static void Write(string? path, string line)
		{
			// D2 guard: TimedHostedService resolves the path from IRdpAuditPathsProvider at
			// registration time. Null means no provider in scope (unit tests / diagnostic
			// reflection) - stay silent instead of reaching for the real %ProgramData% tree.
			if (path is null)
			{
				return;
			}

			try
			{
				DiagnosticLogRotation.AppendLine(
					path,
					"[" + DateTime.UtcNow.ToString("O") + "] " + line);
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
