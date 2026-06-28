// File:    src/RdpAudit.Configurator/Services/DefaultAppSettings.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Renders the default appsettings.json content used by the first-run installer.
//          Kept in the Configurator project to preserve Configurator -> Core dependency
//          (Configurator cannot reference the Service project).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

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
				"ChannelCapacity": 50000
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
