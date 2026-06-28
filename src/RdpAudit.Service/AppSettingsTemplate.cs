// File:    src/RdpAudit.Service/AppSettingsTemplate.cs
// Module:  RdpAudit.Service
// Purpose: Default appsettings.json template written on first service start.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.2

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
			"AutoBlockDebounceSeconds": 60
		},
		"Storage": {
			"DatabasePath": "",
			"EventRetentionDays": 365,
			"LogRetentionDays": 90,
			"AlertRetentionDays": 730,
			"AbuseReportRetentionDays": 365,
			"ActiveBlockRetentionDays": 90,
			"AttackStatRetentionDays": 180,
			"MaintenanceBatchSize": 50000
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
			"ReportCooldownHours": 24
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
		}
	}
}
""";
}
