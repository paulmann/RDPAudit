/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixPushStateStore.cs
// Project: RdpAudit.Service (RdpAudit.Service.Zabbix)
// Purpose: Durable push position. The acknowledged alert id is what makes the push exactly-once
//          across a restart: it is only advanced after the server accepted the batch, so a crash
//          between "sent" and "recorded" re-sends the same incidents instead of losing them, and a
//          re-sent batch overwrites the same item values rather than duplicating them.
//          Writes are atomic (temp + replace); an unreadable file is moved aside with a timestamp
//          instead of being silently discarded.
// Extends: System.Object

using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Zabbix;

/// <summary>Persisted position and counters of the push pipeline.</summary>
public sealed class ZabbixPushState
{
	/// <summary>Highest alert id the server has accepted. Everything above it is still pending.</summary>
	public long LastPushedAlertId { get; set; }

	/// <summary>Last sequence number that was attempted.</summary>
	public long Sequence { get; set; }

	/// <summary>Moment of the last attempt (UTC).</summary>
	public DateTime? LastPushUtc { get; set; }

	/// <summary>Moment of the last accepted batch (UTC).</summary>
	public DateTime? LastSuccessUtc { get; set; }

	/// <summary>Consecutive failed attempts since the last success.</summary>
	public int ConsecutiveFailures { get; set; }

	/// <summary>Last failure text; empty after a success.</summary>
	public string LastError { get; set; } = string.Empty;

	/// <summary>Values accepted over the lifetime of this state file.</summary>
	public long ValuesSent { get; set; }

	/// <summary>Values rejected over the lifetime of this state file.</summary>
	public long ValuesFailed { get; set; }

	/// <summary>Incidents discarded by the backlog cap over the lifetime of this state file.</summary>
	public long IncidentsSkipped { get; set; }

	/// <summary>The incidents carried by the last accepted batch, newest first.</summary>
	public List<ZabbixSentIncidentDto> RecentIncidents { get; set; } = new();
}

/// <summary>Reads and writes <see cref="ZabbixPushState"/> atomically.</summary>
public sealed class ZabbixPushStateStore
{
	/// <summary>Maximum number of incidents remembered for the tab's list.</summary>
	public const int MaxRememberedIncidents = 50;

	private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

	private static readonly JsonSerializerOptions SerializerOptions = new(JsonOptions.Indented)
	{
		PropertyNameCaseInsensitive = true,
	};

	private readonly IRdpAuditPathsProvider _paths;
	private readonly ILogger<ZabbixPushStateStore> _logger;
	private readonly object _gate = new();

	/// <summary>Creates the store.</summary>
	/// <param name="paths">Path provider; tests pass a temporary root.</param>
	/// <param name="logger">Logger.</param>
	public ZabbixPushStateStore(IRdpAuditPathsProvider paths, ILogger<ZabbixPushStateStore> logger)
	{
		ArgumentNullException.ThrowIfNull(paths);
		ArgumentNullException.ThrowIfNull(logger);
		_paths = paths;
		_logger = logger;
	}

	/// <summary>Absolute path of the state file.</summary>
	public string StatePath => _paths.Paths.ZabbixPushStatePath;

	/// <summary>Loads the state; a missing file yields a fresh state, an unreadable one is moved aside.</summary>
	public ZabbixPushState Load()
	{
		string path = StatePath;
		lock (_gate)
		{
			if (!File.Exists(path))
			{
				return new ZabbixPushState();
			}

			try
			{
				string json = File.ReadAllText(path, Encoding.UTF8);
				return JsonSerializer.Deserialize<ZabbixPushState>(json, SerializerOptions) ?? new ZabbixPushState();
			}
			catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
			{
				string aside = path + ".corrupt-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
				_logger.LogError(ex,
					"The Zabbix push state file is unreadable; it will be kept as {Aside} and the position restarts at zero. "
					+ "Restarting the position re-sends recent incidents rather than losing them.",
					aside);
				try
				{
					File.Move(path, aside, overwrite: true);
				}
				catch (IOException moveError)
				{
					_logger.LogWarning(moveError, "The unreadable Zabbix push state file could not be moved aside.");
				}

				return new ZabbixPushState();
			}
		}
	}

	/// <summary>Writes the state atomically: a crash leaves either the previous file or the new one.</summary>
	/// <param name="state">State to persist.</param>
	public void Save(ZabbixPushState state)
	{
		ArgumentNullException.ThrowIfNull(state);

		if (state.RecentIncidents.Count > MaxRememberedIncidents)
		{
			state.RecentIncidents = state.RecentIncidents.GetRange(0, MaxRememberedIncidents);
		}

		string path = StatePath;
		string? directory = Path.GetDirectoryName(path);
		string json = JsonSerializer.Serialize(state, SerializerOptions);

		lock (_gate)
		{
			if (!string.IsNullOrEmpty(directory))
			{
				Directory.CreateDirectory(directory);
			}

			string temp = path + ".tmp";
			File.WriteAllText(temp, json, Utf8NoBom);
			if (File.Exists(path))
			{
				File.Replace(temp, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
			}
			else
			{
				File.Move(temp, path);
			}
		}
	}
}
