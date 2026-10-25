// File:    src/RdpAudit.Service/Services/ShardInventoryService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Read-only shard-tree inventory for the Database tab's Shards section (IPC ordinal 88).
//          Cross-references the IpEventSummary shard metadata with a bounded filesystem walk of the
//          actions root: every summary row with a confirmed shard file becomes one entry, and every
//          .rdpshard file on disk that no summary row points at is reported as an ORPHAN - visible
//          to the operator, deliberately not collected (capacity governance and orphan GC are later
//          stages, docs/86). The walk is bounded and skips reparse points so a pathological or
//          hostile directory tree cannot turn a read-only inventory into an unbounded enumeration,
//          exactly like the overview's shard-tree section.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Service.Storage;

namespace RdpAudit.Service.Services;

/// <summary>Builds the read-only shard inventory for the Database tab.</summary>
public sealed class ShardInventoryService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Upper bound on the tree walk so the inventory stays a bounded read. Reaching it
	/// marks the response truncated instead of failing the command.</summary>
	private const int MaxShardTreeFilesScanned = 100_000;

	/// <summary>Upper bound on entries returned. The summary aggregate still counts everything the
	/// walk saw, so a truncated response is a stated lower bound, never a silent cut.</summary>
	internal const int MaxEntriesReturned = 2000;

	/// <summary>Upper bound on orphan files the inventory opens to read their headers. Orphans are
	/// rare; a tree full of unreadable shards must not turn the inventory into a mass open.</summary>
	private const int MaxOrphanHeaderReads = 1000;

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<ShardInventoryService> _logger;
	private readonly ShardIngestionSink? _sink;
	private readonly SettingsManager? _settings;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service over the database factory and the live options monitor. The shard
	/// sink and the settings manager are optional so a host (or a test) without them still gets a
	/// complete tree inventory; the two capacity fields are then reported as absent instead of invented.</summary>
	public ShardInventoryService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<ShardInventoryService> logger,
		ShardIngestionSink? sink = null,
		SettingsManager? settings = null)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_logger = logger;
		_sink = sink;
		_settings = settings;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Builds the inventory. Never throws for a walk failure; a degraded read is named in
	/// Warnings instead of failing the whole command.</summary>
	public async Task<ShardInventoryDto> BuildAsync(CancellationToken cancellationToken)
	{
		RdpAuditOptions options = _options.CurrentValue;
		string actionsRoot = SafeFullPath(options.Sharding.ResolveActionsRoot());

		ShardInventoryDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = DateTime.UtcNow,
			ActionsRoot = actionsRoot,
			ShardingEnabled = options.Sharding.Enabled,
			// The policy is read here rather than from a separate command, so a client that polls the
			// inventory always sees the policy the service is enforcing.
			Policy = new ShardingPolicyDto
			{
				Status = IpcResultStatus.Success,
				QueriedUtc = DateTime.UtcNow,
				Policy = ShardingPolicyValuesDto.FromOptions(options.Sharding),
				Bounds = new ShardingPolicyBoundsDto(),
				SettingsPath = _settings?.EffectiveConfigPath ?? SettingsManager.ConfigPath,
				HotReloaded = true,
			},
			// Absent - not healthy - when this host has no shard sink: a null is an honest "unknown".
			CapacityStatus = _sink?.GetCapacityStatus(),
		};

		// Referenced shards: one entry per summary row that names a confirmed shard file. The sink is
		// the sole writer of these columns and takes values only from shard headers or real file
		// lengths, so a non-null ShardRelativePath is a confirmed artifact.
		Dictionary<string, ShardInventoryEntryDto> referenced = await LoadReferencedEntriesAsync(cancellationToken)
			.ConfigureAwait(false);
		DescribeAggregateEntries(referenced);

		List<ShardInventoryEntryDto> orphans = new();
		WalkTree(dto, actionsRoot, referenced, orphans, cancellationToken);

		// Referenced first (by path), then orphans, so the grid reads as "known shards, then loose files".
		dto.Entries.AddRange(referenced.Values.OrderBy(entry => entry.RelativePath, StringComparer.OrdinalIgnoreCase));
		dto.Entries.AddRange(orphans);
		if (dto.Entries.Count > MaxEntriesReturned)
		{
			dto.Summary.EntriesReturned = MaxEntriesReturned;
			dto.Entries.RemoveRange(MaxEntriesReturned, dto.Entries.Count - MaxEntriesReturned);
			dto.Warnings.Add(string.Format(
				CultureInfo.InvariantCulture,
				"The inventory was truncated to the first {0} entries; the summary still counts the whole walk.",
				MaxEntriesReturned));
			dto.Summary.Truncated = true;
		}
		else
		{
			dto.Summary.EntriesReturned = dto.Entries.Count;
		}

		dto.Message = string.Format(
			CultureInfo.InvariantCulture,
			"shardFiles={0} orphanFiles={1} orphanBytes={2} totalShardBytes={3} records={4} evicted={5} entriesReturned={6} truncated={7}",
			dto.Summary.ShardFiles,
			dto.Summary.OrphanFiles,
			dto.Summary.OrphanBytes,
			dto.Summary.TotalShardBytes,
			dto.Summary.TotalRecords,
			dto.Summary.TotalEvicted,
			dto.Summary.EntriesReturned,
			dto.Summary.Truncated);

		return dto;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>Returns the normalized relative paths of every shard file an <c>IpEventSummary</c> row
	/// currently names. Used by the orphan collector to re-validate a candidate immediately before it
	/// deletes it, so the check uses exactly the normalization the inventory walk uses.</summary>
	internal async Task<HashSet<string>> LoadReferencedPathSetAsync(CancellationToken cancellationToken)
	{
		HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
		await foreach (string? path in db.IpEventSummaries.AsNoTracking()
			.Where(row => row.ShardRelativePath != null)
			.Select(row => row.ShardRelativePath)
			.AsAsyncEnumerable()
			.WithCancellation(cancellationToken)
			.ConfigureAwait(false))
		{
			string relative = NormalizeRelativePath(path ?? string.Empty);
			if (relative.Length != 0)
			{
				paths.Add(relative);
			}
		}

		return paths;
	}

	/// <summary>Rewrites a subnet-aggregate entry so its displayed address is the bucket the file name
	/// encodes - not whichever member source happened to be read first - and states how many summary
	/// rows share the file. Purely a presentation of facts already in the entry.</summary>
	private static void DescribeAggregateEntries(Dictionary<string, ShardInventoryEntryDto> referenced)
	{
		foreach (ShardInventoryEntryDto entry in referenced.Values)
		{
			if (!entry.IsSubnetAggregate)
			{
				continue;
			}

			string? bucket = IpTextFromHex(entry.IpHex);
			if (bucket is not null)
			{
				entry.IpText = bucket;
			}

			if (entry.SharedBySourceCount > 1)
			{
				entry.Note = string.Format(
					CultureInfo.InvariantCulture,
					"Subnet aggregate: the same shard file is named by {0} IpEventSummary rows.",
					entry.SharedBySourceCount);
			}
		}
	}

	/// <summary>Loads one entry per summary row that names a shard file, keyed by the normalized
	/// relative path, streaming the table instead of buffering the whole projection.</summary>
	private async Task<Dictionary<string, ShardInventoryEntryDto>> LoadReferencedEntriesAsync(
		CancellationToken cancellationToken)
	{
		Dictionary<string, ShardInventoryEntryDto> referenced = new(StringComparer.OrdinalIgnoreCase);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
		await foreach (IpEventSummary summary in db.IpEventSummaries.AsNoTracking()
			.Where(row => row.ShardRelativePath != null)
			.AsAsyncEnumerable()
			.WithCancellation(cancellationToken)
			.ConfigureAwait(false))
		{
			string relative = NormalizeRelativePath(summary.ShardRelativePath ?? string.Empty);
			if (relative.Length == 0)
			{
				continue;
			}

			if (referenced.TryGetValue(relative, out ShardInventoryEntryDto? shared))
			{
				// Several summary rows naming one file is the honest signature of a subnet aggregate: the
				// shard is shared, so the count is reported instead of the later rows silently replacing the
				// first one.
				shared.SharedBySourceCount++;
				continue;
			}

			referenced[relative] = new ShardInventoryEntryDto
			{
				RelativePath = relative,
				IpText = summary.IpText,
				IpHex = IpHexFromRelativePath(relative),
				Records = summary.ShardRecordCount ?? -1,
				Bytes = summary.ShardBytes ?? -1,
				FormatVersion = summary.ShardFormatVersion ?? -1,
				Evicted = summary.ShardEvictedCount ?? -1,
				OldestRetainedUtc = summary.ShardOldestRetainedUtc is { } ticks
					? new DateTime(ticks, DateTimeKind.Utc)
					: null,
				IsOrphan = false,
				IsSubnetAggregate = summary.IsSubnetAggregate,
			};
		}

		return referenced;
	}

	/// <summary>
	/// Walks the actions root once and folds every file into the summary; shard files that no
	/// summary row references become orphan entries. Bounded, reparse-point-free, and tolerant of
	/// files that vanish or are unreadable mid-walk.
	/// </summary>
	private void WalkTree(
		ShardInventoryDto dto,
		string actionsRoot,
		Dictionary<string, ShardInventoryEntryDto> referenced,
		List<ShardInventoryEntryDto> orphans,
		CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(actionsRoot) || !Directory.Exists(actionsRoot))
		{
			// No shard tree yet is an honest zero, not an error.
			return;
		}

		EnumerationOptions enumerationOptions = new()
		{
			RecurseSubdirectories = true,
			IgnoreInaccessible = true,
			AttributesToSkip = FileAttributes.ReparsePoint,
		};

		int orphanHeaderReads = 0;
		foreach (string file in Directory.EnumerateFiles(actionsRoot, "*", enumerationOptions))
		{
			cancellationToken.ThrowIfCancellationRequested();
			if (dto.Summary.ScannedFileCount >= MaxShardTreeFilesScanned)
			{
				dto.Summary.Truncated = true;
				dto.Warnings.Add(string.Format(
					CultureInfo.InvariantCulture,
					"The shard-tree walk stopped after {0} files; every count is a lower bound.",
					MaxShardTreeFilesScanned));
				break;
			}

			dto.Summary.ScannedFileCount++;

			long bytes = -1;
			DateTime? lastWriteUtc = null;
			try
			{
				FileInfo info = new(file);
				if (info.Exists)
				{
					bytes = info.Length;
					lastWriteUtc = info.LastWriteTimeUtc;
				}
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
			{
				// A file that vanished or is unreadable mid-walk keeps its -1; the entry still names it.
			}

			if (!file.EndsWith(ShardPath.ShardExtension, StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			dto.Summary.ShardFiles++;
			if (bytes >= 0)
			{
				dto.Summary.TotalShardBytes += bytes;
			}

			string relative = NormalizeRelativePath(Path.GetRelativePath(actionsRoot, file));
			if (referenced.TryGetValue(relative, out ShardInventoryEntryDto? entry))
			{
				// The on-disk length is the current truth; the summary may lag a commit behind.
				if (bytes >= 0)
				{
					entry.Bytes = bytes;
				}

				entry.LastWriteUtc = lastWriteUtc;

				if (entry.Records >= 0)
				{
					dto.Summary.TotalRecords += entry.Records;
				}

				if (entry.Evicted >= 0)
				{
					dto.Summary.TotalEvicted += entry.Evicted;
				}

				continue;
			}

			ShardInventoryEntryDto orphan = BuildOrphanEntry(file, relative, bytes, lastWriteUtc, orphanHeaderReads < MaxOrphanHeaderReads);
			if (orphan.Note is null)
			{
				// A header was actually read; keep the budget accounted so a tree of half-readable
				// shards cannot turn the inventory into an unbounded open loop.
				orphanHeaderReads++;
			}

			dto.Summary.OrphanFiles++;
			if (orphan.Bytes >= 0)
			{
				dto.Summary.OrphanBytes += orphan.Bytes;
			}

			if (orphan.Records >= 0)
			{
				dto.Summary.TotalRecords += orphan.Records;
			}

			if (orphan.Evicted >= 0)
			{
				dto.Summary.TotalEvicted += orphan.Evicted;
			}

			orphans.Add(orphan);
		}
	}

	/// <summary>Builds the entry for a shard file no summary row points at. When the header budget
	/// allows it, the shard header is read for records / format version / evicted count; otherwise
	/// those stay unknown and the entry says so instead of inventing values.</summary>
	private ShardInventoryEntryDto BuildOrphanEntry(
		string absolutePath,
		string relativePath,
		long bytes,
		DateTime? lastWriteUtc,
		bool mayReadHeader)
	{
		ShardInventoryEntryDto entry = new()
		{
			RelativePath = relativePath,
			IpHex = IpHexFromRelativePath(relativePath),
			Bytes = bytes,
			LastWriteUtc = lastWriteUtc,
			IsOrphan = true,
		};

		string? ipText = IpTextFromHex(entry.IpHex);
		if (ipText is not null)
		{
			entry.IpText = ipText;
			entry.IsSubnetAggregate = relativePath.Contains(ShardPath.AggregateSuffix, StringComparison.OrdinalIgnoreCase);
		}
		else
		{
			entry.Note = "The file name is not a valid shard name.";
			return entry;
		}

		if (!mayReadHeader)
		{
			entry.Note = "The header was not read; the orphan-header read budget was exhausted.";
			return entry;
		}

		try
		{
			using ShardReader? reader = ShardReader.Open(absolutePath);
			if (reader is null)
			{
				entry.Note = "The shard header is missing or unreadable.";
				return entry;
			}

			HeaderPayload snapshot = reader.Snapshot;
			entry.Records = snapshot.Count;
			entry.FormatVersion = snapshot.FormatVersion > (uint)int.MaxValue ? -1 : checked((int)snapshot.FormatVersion);
			entry.Evicted = checked((long)snapshot.TotalEvicted);
			foreach (ShardRecord record in reader.ReadAll())
			{
				entry.OldestRetainedUtc = new DateTime(record.TimeUtcTicks, DateTimeKind.Utc);
				break;
			}
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
		{
			_logger.LogWarning(ex, "Shard inventory could not read the orphan shard header {Path}", absolutePath);
			entry.Note = "The shard header could not be read: " + ex.GetType().Name;
		}

		return entry;
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	/// <summary>Normalizes a shard-relative path to forward slashes without a leading separator, so
	/// the filesystem walk and the summary rows compare equal for the same file.</summary>
	internal static string NormalizeRelativePath(string path)
	{
		string normalized = path.Replace('\\', '/').TrimStart('/');
		if (normalized.StartsWith(ShardPath.ActionsRootFolder + "/", StringComparison.OrdinalIgnoreCase))
		{
			normalized = normalized[(ShardPath.ActionsRootFolder.Length + 1)..];
		}

		return normalized;
	}

	/// <summary>Extracts the uppercase hexadecimal address from a shard relative path (the file name
	/// without extension and without the <c>-agg</c> aggregate suffix); empty when it is not a shard name.</summary>
	internal static string IpHexFromRelativePath(string relativePath)
	{
		string name = Path.GetFileName(relativePath);
		if (!name.EndsWith(ShardPath.ShardExtension, StringComparison.OrdinalIgnoreCase))
		{
			return string.Empty;
		}

		name = name[..^ShardPath.ShardExtension.Length];
		if (name.EndsWith(ShardPath.AggregateSuffix, StringComparison.OrdinalIgnoreCase))
		{
			name = name[..^ShardPath.AggregateSuffix.Length];
		}

		if (name.Length is not 8 and not 32 || !IsHex(name))
		{
			return string.Empty;
		}

		return name.ToUpperInvariant();
	}

	/// <summary>Decodes a shard file's hexadecimal name into its canonical textual IP; null when the
	/// name is not a decodable shard name.</summary>
	private static string? IpTextFromHex(string hex)
	{
		if (hex.Length is not 8 and not 32)
		{
			return null;
		}

		byte[] bytes = new byte[hex.Length / 2];
		for (int index = 0; index < bytes.Length; index++)
		{
			if (!byte.TryParse(hex.AsSpan(index * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[index]))
			{
				return null;
			}
		}

		try
		{
			return new IPAddress(bytes).ToString();
		}
		catch (FormatException)
		{
			return null;
		}
	}

	private static bool IsHex(string value)
	{
		foreach (char c in value)
		{
			bool hex = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
			if (!hex)
			{
				return false;
			}
		}

		return true;
	}

	/// <summary>Full path of a configured location, or the raw value when the path is unusable.</summary>
	private static string SafeFullPath(string? path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return string.Empty;
		}

		try
		{
			return Path.GetFullPath(path);
		}
		catch (ArgumentException)
		{
			return path;
		}
		catch (NotSupportedException)
		{
			return path;
		}
	}
}
