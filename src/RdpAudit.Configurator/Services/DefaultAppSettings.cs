/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
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
				"ChannelCapacity": 32768,
				"FloodGuardEnabled": true,
				"FloodGuardWindowSeconds": 10,
				"FloodGuardSoftThreshold": 1000,
				"FloodGuardHardThreshold": 10000,
				"FloodGuardSampleEveryN": 32,
				"FloodGuardBucketCount": 4096,
				"FirstReadLookbackHours": 24
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
				"WhitelistUsers": [],
				"EnablePrivilegedLoginDetection": true,
				"PrivilegedLoginSuppressionWindowMinutes": 5,
				"PrivilegedLoginRateLimitPerMinute": 20,
				"AlertEventMaxAgeMinutes": 5
			},
			"Notifications": {
				"EnableTrayNotifier": true,
				"StartWithWindows": true,
				"PollIntervalSeconds": 5,
				"MinimumSeverity": "High",
				"MaxToastsPerMinute": 10,
				"UseNativeToasts": false,
				"ShowAlerts": {},
				"ShowEvents": {}
			},
			"Firewall": {
				"AutoBlockBruteForce": false,
				"AutoBlockThreshold": 50,
				"BlockRuleName": "RdpAudit-Block",
			"DefaultBlockDurationMinutes": 4320,
			"MaxActiveBlocks": 10000,
			"RefusePrivateAddressBlock": true,
			"AutoBlockDebounceSeconds": 60,
			"PowerShellScanTimeoutSeconds": 30,
			"PowerShellRetryProbeIntervalMinutes": 15
			},
			"Storage": {
				"DatabasePath": "__RDPAUDIT_DB_PATH__",
				"EventRetentionDays": 365,
				"LogRetentionDays": 90,
				"AlertRetentionDays": 730,
				"Decimation": {
					"Enabled": false,
					"MinAgeDays": 30,
					"BurstGapSeconds": 300,
					"CandidateMinRows": 100000,
					"HeadKeepPerBurst": 100,
					"TailKeepPerBurst": 100,
					"MaxCandidateEventIds": 5,
					"BatchSize": 5000
				},
				"RetentionPolicy": {
					"Enabled": false,
					"LegalHold": false,
					"AnchorScope": "PerCode",
					"TailKeepPerCode": 512,
					"CandidateMinRows": 1000,
					"MinAgeDays": 7,
					"MaxRowsPerPass": 50000,
					"MaxWriterLockMs": 250,
					"DeleteBatchRows": 2000,
					"MaxDatabaseBytes": 0,
					"MaxRawEventRows": 0,
					"MinFreeDiskBytes": 0,
					"ProtectedEventIds": [4672, 4673, 4674, 4697, 4720, 4722, 4723, 4724, 4728, 4732, 4756, 4769, 4771, 7045]
				},
				"Backup": {
					"Enabled": false,
					"RetentionCopies": 5,
					"MinFreeDiskBytesBeforeBackup": 0,
					"IncludeShards": false,
					"PreMigrationBackupEnabled": true,
					"BackupDirectory": ""
				},
				"Integrity": {
					"Enabled": true,
					"QuickCheckEnabled": true,
					"FullCheckEnabled": false,
					"FullCheckIntervalDays": 7,
					"MaintenanceWindowStartHourLocal": 3,
					"MaintenanceWindowDurationHours": 4,
					"ForeignKeyCheckEnabled": true
				},
				"Encryption": {
					"Mode": "None",
					"KeySecretName": "",
					"KeyRotationDays": 0
				}
			},
			"Sharding": {
				"Enabled": false,
				"ActionsRoot": "",
				"ShardCapacityRecords": 1024,
				"MaxOpenWriters": 128,
				"MaxShardFiles": 4096,
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
			},
		"Diagnostics": {
			"DebugMode": false,
			"LogEventXmlAtDebug": false,
			"LogChannelDrops": true,
			"LogAlertEvaluationTimings": false
		},
		"Api": {
			"Enabled": false,
			"Token": "",
			"ListenAddress": "127.0.0.1",
			"Port": 8443,
			"CertificateThumbprint": "",
			"CertificateSubject": "",
			"AllowInsecureLoopback": false,
			"MaxConnections": 100,
			"RateLimitPerMinute": 60
		},
		"ProcessMonitoring": {
			"Enabled": true,
			"BaselineWindowsDays": [7, 30, 365],
			"AlertWindowDays": 7,
			"AutoCloseSessionOnNewProcess": false,
			"EnableAlertOnSystemProcesses": true,
			"MaxObservations": 5000,
			"MaxAutoCloseOperationsPerMinute": 10,
			"AutoClosePollIntervalSeconds": 10
		}
		}
	}
	""";
}
