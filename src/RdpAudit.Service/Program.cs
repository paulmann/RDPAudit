// File:    src/RdpAudit.Service/Program.cs
// Module:  RdpAudit.Service
// Purpose: Process entry point — configures host, DI, logging, and worker registrations.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

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

		builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(15));

		RegisterServices(builder.Services);

		using IHost host = builder.Build();

		// Install last-resort crash diagnostics before anything else can fault. From this point a
		// fault anywhere in the process is recorded as a Critical OperationLog (DB permitting) and
		// always to the Windows Event Log and a fallback file, instead of dying silently.
		CrashGuard crashGuard = host.Services.GetRequiredService<CrashGuard>();
		crashGuard.Install();
		RdpAuditOptions effectiveOptions = host.Services.GetRequiredService<IOptions<RdpAuditOptions>>().Value;
		crashGuard.LogStartupDiagnostics(effectiveOptions, configPath);

		using (IServiceScope scope = host.Services.CreateScope())
		{
			AuditDbInitializer initializer = scope.ServiceProvider.GetRequiredService<AuditDbInitializer>();
			await initializer.EnsureCreatedAsync().ConfigureAwait(false);

			BookmarkStore store = scope.ServiceProvider.GetRequiredService<BookmarkStore>();
			await store.LoadAllAsync().ConfigureAwait(false);
		}

		await host.RunAsync().ConfigureAwait(false);
		return 0;
	}

	private static void ConfigureSerilog(HostApplicationBuilder builder, string programData)
	{
		string logDir = Path.Combine(programData, "RdpAudit", "logs");
		Directory.CreateDirectory(logDir);

		LoggerConfiguration logger = new LoggerConfiguration()
			.ReadFrom.Configuration(builder.Configuration)
			.Enrich.FromLogContext()
			.WriteTo.File(
				new CompactJsonFormatter(),
				Path.Combine(logDir, "service-.log"),
				rollingInterval: RollingInterval.Day,
				retainedFileCountLimit: 90);

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

	private static void RegisterServices(IServiceCollection services)
	{
		services.AddSingleton<SqlitePragmaInterceptor>();

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

		services.AddHostedService(sp => new EventCollectorWorker(
			sp.GetRequiredService<EventChannel>(),
			sp.GetRequiredService<BookmarkStore>(),
			sp.GetRequiredService<ServiceMetrics>(),
			sp.GetRequiredService<ILogger<EventCollectorWorker>>(),
			sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>(),
			sp.GetRequiredService<IDbContextFactory<AuditDbContext>>(),
			sp.GetRequiredService<IOperationLogWriter>()));
		services.AddHostedService(sp => new SecurityBackfillWorker(
			sp.GetRequiredService<EventChannel>(),
			sp.GetRequiredService<ServiceMetrics>(),
			sp.GetRequiredService<ILogger<SecurityBackfillWorker>>(),
			sp.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>(),
			sp.GetRequiredService<BookmarkStore>(),
			sp.GetRequiredService<IDbContextFactory<AuditDbContext>>(),
			sp.GetRequiredService<OverviewProgressState>()));
		services.AddHostedService<EventProcessorWorker>();
		services.AddHostedService<SessionCorrelationHydrationWorker>();
		services.AddHostedService<AlertWorker>();
		services.AddHostedService<IpcServerWorker>();
		services.AddHostedService<MaintenanceWorker>();
		services.AddHostedService<FirewallAutoBlockWorker>();
		services.AddHostedService<FirewallExpirationWorker>();
		services.AddHostedService<EnforcementReconciliationWorker>();
		// Singleton + hosted-service-resolving-the-singleton so the IPC RebuildAttackStats action can
		// invoke the very same worker instance (sharing its re-entrancy gate) the background loop uses.
		services.AddSingleton<AttackStatsRefreshWorker>();
		services.AddHostedService(sp => sp.GetRequiredService<AttackStatsRefreshWorker>());
		services.AddHostedService<AbuseIpDbReportWorker>();
	}

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
