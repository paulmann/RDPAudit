// File:    src/RdpAudit.Service/Alerts/AlertRuleRegistration.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Registers every IAlertRule implementation with the DI container.
//          Threshold rules receive AlertCooldownTracker via DI to dedupe alert floods.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.DependencyInjection;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Alerts;

/// <summary>Registers every IAlertRule implementation with the DI container.</summary>
public static class AlertRuleRegistration
{
	public static void Register(IServiceCollection services)
	{
		services.AddSingleton<IAlertRule>(sp => new BruteForceRule(sp.GetRequiredService<AlertCooldownTracker>()));
		services.AddSingleton<IAlertRule>(sp => new BruteForceNtlmRule(sp.GetRequiredService<AlertCooldownTracker>()));
		services.AddSingleton<IAlertRule, PassTheHashRule>();
		services.AddSingleton<IAlertRule, GoldenTicketRule>();
		services.AddSingleton<IAlertRule, OffHoursLoginRule>();
		services.AddSingleton<IAlertRule, ExternalRdpLoginRule>();
		services.AddSingleton<IAlertRule, RdpSessionHijackRule>();
		services.AddSingleton<IAlertRule, RapidReconnectRule>();
		services.AddSingleton<IAlertRule, UnknownIpSuccessRule>();
		services.AddSingleton<IAlertRule, PrivilegedLoginRule>();
		services.AddSingleton<IAlertRule, ProcessAnomalyRule>();
		services.AddSingleton<IAlertRule, LsassAccessRule>();
		services.AddSingleton<IAlertRule, TaskPersistenceRule>();
		services.AddSingleton<IAlertRule, TaskModifiedRule>();
		services.AddSingleton<IAlertRule, ServiceInstallRule>();
		services.AddSingleton<IAlertRule, NewAccountRule>();
		services.AddSingleton<IAlertRule, PrivilegedGroupChangeRule>();
		services.AddSingleton<IAlertRule, StickyKeysBackdoorRule>();
		services.AddSingleton<IAlertRule, RdpPortChangedRule>();
		services.AddSingleton<IAlertRule, LsassPplTamperRule>();
		services.AddSingleton<IAlertRule>(sp => new KerberosSprayRule(sp.GetRequiredService<AlertCooldownTracker>()));
	}
}
