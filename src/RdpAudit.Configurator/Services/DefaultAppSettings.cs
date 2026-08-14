/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DefaultAppSettings.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Services)
// Purpose: Renders the first-run default appsettings.json without taking a Configurator-to-Service dependency.
// Depends: JsonEncodedText, RdpAuditOptions, MonitoringOptions
// Extends: Keep this template aligned with Service defaults for implemented and bound option keys only.

using System.Text.Json;

namespace RdpAudit.Configurator.Services;

/// <summary>Renders the default appsettings.json content used by the first-run installer.</summary>
internal static class DefaultAppSettings
{
	private const string DatabasePathPlaceholder = "__RDPAUDIT_DB_PATH__";

	internal static string Render(string databasePath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
		string escaped = JsonEncodedText.Encode(databasePath).Value;
		return Template.Replace(DatabasePathPlaceholder, escaped, StringComparison.Ordinal);
	}

	private const string Template = """
	{
		"Serilog": {
			"MinimumLevel": {
				"Default": "Information",
				"Override": {
					"Microsoft": "Warning",
					"Microsoft.EntityFrameworkCore": "Warning"
				}
			}
		},
		"RdpAudit": {
			"Monitoring": {
				"FilterLocalAddresses": true,
				"TrackProcessCreation": true,
				"TrackScheduledTasks": true,
				"TrackAccountChanges": true,
				"TrackKerberos": true,
				"TrackObjectAccess": true,
				"BatchSize": 100,
				"BatchTimeoutMilliseconds": 500,
				"ChannelCapacity": 50000,
				"FloodGuardEnabled": true,
				"FloodGuardWindowSeconds": 10,
				"FloodGuardSoftThreshold": 1000,
				"FloodGuardHardThreshold": 10000,
				"FloodGuardSampleEveryN": 32,
				"FloodGuardBucketCount": 4096
			},
			"Alerts": {
				"EnableBruteForceDetection": true,
				"BruteForceThreshold": 10,
				"BruteForceWindowMinutes": 5,
				"BruteForceNtlmThreshold": 20,
				"KerberosSprayThreshold": 20,
				"RapidReconnectSeconds": 30,
				"UnknownIpSuccessFailureThreshold": 5,
				"OffHoursAlertEnabled": true,
				"BusinessHoursStart": "08:00:00",
				"BusinessHoursEnd": "20:00:00",
				"KerberosExpectedEncryptionType": "0x12",
				"WhitelistIps": [],
				"WhitelistUsers": []
			},
			"Firewall": {
				"AutoBlockBruteForce": false,
				"AutoBlockThreshold": 50,
				"BlockRuleName": "RdpAudit-Block"
			},
			"Storage": {
				"DatabasePath": "__RDPAUDIT_DB_PATH__",
				"EventRetentionDays": 365,
				"LogRetentionDays": 90,
				"AlertRetentionDays": 730
			},
			"Diagnostics": {
				"DebugMode": false,
				"LogEventXmlAtDebug": false,
				"LogChannelDrops": true,
				"LogAlertEvaluationTimings": false
			}
		}
	}
	""";
}
