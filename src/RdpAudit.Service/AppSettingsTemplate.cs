/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : AppSettingsTemplate.cs
// Project: RdpAudit.Service (RdpAudit.Service)
// Purpose: Provides the default persisted appsettings.json content written on first service startup.
// Depends: RdpAuditOptions, MonitoringOptions
// Extends: Add only option keys that have corresponding bound option properties and active service code.

namespace RdpAudit.Service;

/// <summary>Default appsettings.json template written on first service start.</summary>
public static class AppSettingsTemplate
{
	public const string Default = """
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
			"EnablePrivilegedLoginDetection": true,
			"PrivilegedLoginSuppressionWindowMinutes": 5,
			"PrivilegedLoginRateLimitPerMinute": 20,
			"AlertEventMaxAgeMinutes": 5,
			"KerberosExpectedEncryptionType": "0x12",
			"WhitelistIps": [],
			"WhitelistUsers": []
		},
		"Firewall": {
			"AutoBlockBruteForce": false,
			"AutoBlockThreshold": 50,
			"BlockRuleName": "RdpAudit-Block",
			"Provider": "Windows",
			"Whitelist": [],
			"Blacklist": [],
			"BlockOnBlacklistedLogin": false,
			"InstantBlockLogins": [],
			"DefaultBlockDurationMinutes": 4320,
			"MaxActiveBlocks": 10000,
			"WhitelistIps": [],
			"RefusePrivateAddressBlock": true,
			"AutoBlockDebounceSeconds": 60,
			"PowerShellScanTimeoutSeconds": 30,
			"PowerShellRetryProbeIntervalMinutes": 15
		},
		"Storage": {
			"DatabasePath": "",
			"EventRetentionDays": 365,
			"LogRetentionDays": 90,
			"AlertRetentionDays": 730,
			"AbuseReportRetentionDays": 365,
			"ActiveBlockRetentionDays": 90,
			"AttackStatRetentionDays": 180,
			"MaintenanceBatchSize": 50000,
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
		"Logs": {
			"ViewDepthDays": 60,
			"RetentionDays": 60,
			"DefaultPageSize": 500
		},
		"AbuseIpDb": {
			"Enabled": false,
			"ReportAttacks": false,
			"ApiKey": "",
			"BaseUrl": "https://api.abuseipdb.com",
			"EndpointUrl": "https://api.abuseipdb.com/api/v2/report",
			"TimeoutSeconds": 15,
			"MaxReportsPerMinute": 60,
			"MaxReportsPerHour": 100,
			"MaxReportsPerDay": 500,
			"DeduplicationWindowMinutes": 15,
			"CacheLookups": true,
			"CacheTtlMinutes": 60,
			"ReportThreshold": 80,
			"MinThreatScore": 60.0,
			"MinFailedAttempts": 10,
			"ReportCategories": [18, 22],
			"ReportDedupeEnabled": true,
			"ReportCooldownHours": 24,
			"CheckEnabled": false,
			"CheckMaxLookupsPerMinute": 30,
			"CheckMaxLookupsPerDay": 500,
			"CheckMaxAgeInDays": 30,
			"CheckWorkerIntervalSeconds": 300
		},
		"MikroTik": {
			"Enabled": false,
			"AddAttackerRules": true,
			"BaseUrl": "",
			"UseHttps": true,
			"Host": "",
			"Port": 0,
			"UserName": "",
			"Password": "",
			"TimeoutSeconds": 15,
			"AddressList": "rdpaudit-block",
			"FilterChain": "input",
			"FilterAction": "drop",
			"CommentTemplate": "RdpAudit auto-block",
			"CommentPrefix": "RdpAudit",
			"ValidateServerCertificate": true,
			"MaxOperationsPerMinute": 120,
			"BlockDurationDays": 0,
			"BlockDurationHours": 1,
			"BlockDurationMinutes": 0
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
		"SessionControl": {
			"Enabled": true,
			"AllowDisconnect": true,
			"AllowLogoff": true,
			"AllowShadow": false,
			"RequireShadowPolicy": true,
			"BackupShadowPolicyOnApply": true,
			"ShadowPolicyMode": 1,
			"MaxOperationsPerMinute": 30,
			"AuditAllOperations": true
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
		},
		"Zabbix": {
			"Enabled": false,
			"ServerHost": "",
			"ServerPort": 10051,
			"HostName": "",
			"HostGroup": "RDPAudit",
			"TrapperAllowedHosts": "",
			"ApiUrl": "",
			"ApiToken": "",
			"ApiUser": "",
			"ApiPassword": "",
			"ValidateServerCertificate": true,
			"TimeoutSeconds": 15,
			"PushIntervalSeconds": 60,
			"MinimumSeverity": "Medium",
			"MaxIncidentsPerPush": 20,
			"MaxBacklogIncidents": 500,
			"ProvisionTriggers": true,
			"CreateDashboard": true
		},
		"CrossHost": {
			"Enabled": false,
			"Hosts": [],
			"PollIntervalSeconds": 60,
			"ConnectTimeoutMs": 5000,
			"MaxFactsPerPoll": 1000
		}
	}
}
""";
}
