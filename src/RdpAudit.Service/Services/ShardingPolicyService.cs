/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardingPolicyService.cs
// Project: RdpAudit.Service (RdpAudit.Service.Services)
// Purpose: Reads and writes the shard capacity policy the Database tab governs: the ShardingOptions
//          ceilings (per-shard bytes, whole-tree bytes, free-disk floor), the ring geometry, the file
//          budget, the orphan grace period and the cardinality-guard thresholds. Writes validate the
//          whole request BEFORE touching anything - a structural fault (a negative ceiling, an unusable
//          actions root) is refused with no write at all - then persist the clamped values into
//          appsettings.json through SettingsManager (atomic replace, secret handling, schema
//          validation) and write one OperationLog row carrying the old policy, the new policy and the
//          invoking identity. IOptionsMonitor re-reads the file through its change token, so the new
//          policy is in force without a service restart.
// Depends: ShardingOptions, SubnetAggregationOptions, SettingsManager, IOperationLogWriter,
//          ShardingPolicyDto
// Extends: Add a clampsable field by adding it to ShardingPolicyValuesDto and its validation branch
//          here; never widen a bound silently - report the clamped value instead.

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Services;

/// <summary>Read/write service for the shard capacity policy the Database tab governs.</summary>
public sealed class ShardingPolicyService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Logical OperationLog source for sharding-policy mutations.</summary>
	internal const string OperationLogSource = "Sharding";

	/// <summary>Logical OperationLog operation name for sharding-policy mutations.</summary>
	internal const string OperationLogOperation = "SaveShardingPolicy";

	/// <summary>Name of the settings section written under <c>RdpAudit</c>.</summary>
	private const string SectionName = "Sharding";

	/// <summary>Name of the nested cardinality-guard section written under <c>RdpAudit.Sharding</c>.</summary>
	private const string SubnetAggregationSectionName = "SubnetAggregation";

	private static readonly JsonSerializerOptions SectionJson = new()
	{
		WriteIndented = true,
	};

	private static readonly JsonSerializerOptions DocumentJson = new()
	{
		WriteIndented = true,
	};

	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly SettingsManager _settings;
	private readonly IOperationLogWriter? _operationLog;
	private readonly ILogger<ShardingPolicyService> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service over the live options monitor and the settings writer.</summary>
	public ShardingPolicyService(
		IOptionsMonitor<RdpAuditOptions> options,
		SettingsManager settings,
		ILogger<ShardingPolicyService> logger,
		IOperationLogWriter? operationLog = null)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(settings);
		ArgumentNullException.ThrowIfNull(logger);
		_options = options;
		_settings = settings;
		_logger = logger;
		_operationLog = operationLog;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Reads the effective shard policy. Never throws for a settings problem: the values come
	/// from the live options monitor, which has already bound the document.</summary>
	public ShardingPolicyDto Get()
	{
		DateTime nowUtc = DateTime.UtcNow;
		return new ShardingPolicyDto
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = nowUtc,
			Policy = ShardingPolicyValuesDto.FromOptions(_options.CurrentValue.Sharding),
			Bounds = new ShardingPolicyBoundsDto(),
			SettingsPath = _settings.EffectiveConfigPath,
			HotReloaded = true,
			Message = "The shard policy is read from the live options monitor; a save is in force without a restart.",
		};
	}

	/// <summary>
	/// Applies an operator-edited shard policy. The request is validated and clamped in full before
	/// anything is written; an invalid request is refused with no partial write. On success one
	/// OperationLog row records the old policy, the new policy and <paramref name="invokedBy"/>.
	/// </summary>
	/// <exception cref="IpcException">The request is structurally invalid.</exception>
	public async Task<ShardingPolicyDto> SaveAsync(
		ShardingPolicyMutationRequest request,
		string invokedBy,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(request);

		ShardingOptions current = _options.CurrentValue.Sharding;
		ShardingOptions candidate = Validate(request);
		string oldSummary = DescribePolicy(current);
		string newSummary = DescribePolicy(candidate);

		PersistSettings(candidate);

		ShardingPolicyDto result = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = DateTime.UtcNow,
			// Re-read through the live monitor: the DTO reports what the service actually enforces, never
			// what the request asked for.
			Policy = ShardingPolicyValuesDto.FromOptions(_options.CurrentValue.Sharding),
			Bounds = new ShardingPolicyBoundsDto(),
			SettingsPath = _settings.EffectiveConfigPath,
			HotReloaded = true,
		};

		bool audited = await WriteAuditAsync(invokedBy, oldSummary, newSummary, cancellationToken).ConfigureAwait(false);
		if (!audited)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "The shard policy was saved, but the audit entry could not be written. See the service log.";
			return result;
		}

		result.Message = oldSummary == newSummary
			? "The shard policy was saved unchanged."
			: "The shard policy was saved and is live: " + newSummary;
		return result;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Validates the whole request and returns the options instance to persist. Negative values and an
	/// unusable actions root are refused rather than clamped: a negative ceiling is almost always a
	/// typo, and silently turning it into "disabled" would remove the safety limit the operator meant to
	/// set. A value above a supported maximum is clamped through the option's own <c>Resolve*</c> helper,
	/// and the clamped value is what gets written and reported.
	/// </summary>
	private static ShardingOptions Validate(ShardingPolicyMutationRequest request)
	{
		if (request.ShardCapacityRecords < ShardingOptions.MinShardCapacityRecords)
		{
			throw new IpcException(string.Format(
				CultureInfo.InvariantCulture,
				"ShardCapacityRecords must be at least {0}.",
				ShardingOptions.MinShardCapacityRecords));
		}

		if (request.MaxOpenWriters < 1)
		{
			throw new IpcException("MaxOpenWriters must be at least 1.");
		}

		if (request.MaxShardFiles < 0)
		{
			throw new IpcException("MaxShardFiles must not be negative; use 0 to refuse every new shard file.");
		}

		if (request.MaxShardBytes < 0)
		{
			throw new IpcException("MaxShardBytes must not be negative; use 0 to disable the per-shard byte ceiling.");
		}

		if (request.MaxTotalShardBytes < 0)
		{
			throw new IpcException("MaxTotalShardBytes must not be negative; use 0 to disable the shard byte budget.");
		}

		if (request.MinFreeDiskBytes < 0)
		{
			throw new IpcException("MinFreeDiskBytes must not be negative; use 0 to disable the free-disk floor.");
		}

		if (request.OrphanGraceDays < 0)
		{
			throw new IpcException("OrphanGraceDays must not be negative.");
		}

		SubnetAggregationMutationDto aggregation = request.SubnetAggregation
			?? new SubnetAggregationMutationDto();
		if (aggregation.TotalFileThreshold < SubnetAggregationOptions.MinTotalFileThreshold)
		{
			throw new IpcException(string.Format(
				CultureInfo.InvariantCulture,
				"SubnetAggregation.TotalFileThreshold must be at least {0}.",
				SubnetAggregationOptions.MinTotalFileThreshold));
		}

		if (aggregation.NewFilesPerIntervalLimit < SubnetAggregationOptions.MinNewFilesPerIntervalLimit)
		{
			throw new IpcException(string.Format(
				CultureInfo.InvariantCulture,
				"SubnetAggregation.NewFilesPerIntervalLimit must be at least {0}.",
				SubnetAggregationOptions.MinNewFilesPerIntervalLimit));
		}

		if (aggregation.IntervalSeconds < SubnetAggregationOptions.MinIntervalSeconds)
		{
			throw new IpcException(string.Format(
				CultureInfo.InvariantCulture,
				"SubnetAggregation.IntervalSeconds must be at least {0}.",
				SubnetAggregationOptions.MinIntervalSeconds));
		}

		if (aggregation.MinSourceRowsPerInterval < 0)
		{
			throw new IpcException("SubnetAggregation.MinSourceRowsPerInterval must not be negative.");
		}

		string actionsRoot = (request.ActionsRoot ?? string.Empty).Trim();
		ValidateActionsRoot(actionsRoot);

		ShardingOptions candidate = new()
		{
			Enabled = request.Enabled,
			ActionsRoot = actionsRoot,
			ShardCapacityRecords = request.ShardCapacityRecords,
			MaxOpenWriters = request.MaxOpenWriters,
			MaxShardFiles = request.MaxShardFiles,
			MaxShardBytes = request.MaxShardBytes,
			MaxTotalShardBytes = request.MaxTotalShardBytes,
			MinFreeDiskBytes = request.MinFreeDiskBytes,
			OrphanGraceDays = request.OrphanGraceDays,
			SubnetAggregation = new SubnetAggregationOptions
			{
				Enabled = aggregation.Enabled,
				TotalFileThreshold = aggregation.TotalFileThreshold,
				NewFilesPerIntervalLimit = aggregation.NewFilesPerIntervalLimit,
				IntervalSeconds = aggregation.IntervalSeconds,
				MinSourceRowsPerInterval = aggregation.MinSourceRowsPerInterval,
			},
		};

		// Clamp through the option's own helpers, then write the clamped values: a save never widens a
		// bound, and the operator sees the effective value echoed back on the response.
		candidate.OrphanGraceDays = candidate.ResolveOrphanGraceDays();
		candidate.SubnetAggregation.TotalFileThreshold = candidate.SubnetAggregation.ResolveTotalFileThreshold();
		candidate.SubnetAggregation.NewFilesPerIntervalLimit = candidate.SubnetAggregation.ResolveNewFilesPerIntervalLimit();
		candidate.SubnetAggregation.IntervalSeconds = candidate.SubnetAggregation.ResolveIntervalSeconds();
		candidate.SubnetAggregation.MinSourceRowsPerInterval = candidate.SubnetAggregation.ResolveMinSourceRowsPerInterval();
		return candidate;
	}

	/// <summary>The actions root must be empty (ProgramData default) or an absolute path that is not a
	/// drive root: the sink writes its entire tree under this directory, so a relative or wholesale-root
	/// value is refused before anything is persisted.</summary>
	private static void ValidateActionsRoot(string actionsRoot)
	{
		if (actionsRoot.Length == 0)
		{
			return;
		}

		if (!Path.IsPathFullyQualified(actionsRoot))
		{
			throw new IpcException("ActionsRoot must be an absolute path, or empty to use the ProgramData default.");
		}

		string? root = Path.GetPathRoot(actionsRoot);
		if (string.IsNullOrEmpty(root)
			|| string.Equals(
				Path.TrimEndingDirectorySeparator(Path.GetFullPath(actionsRoot)),
				Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)),
				StringComparison.OrdinalIgnoreCase))
		{
			throw new IpcException("ActionsRoot must not be a drive root; choose a directory dedicated to the shard tree.");
		}
	}

	/// <summary>
	/// Merges the resolved sharding values into the existing appsettings.json document and writes it
	/// through <see cref="SettingsManager"/>, which validates that the document still binds to
	/// <c>RdpAuditOptions</c>, protects secret fields and replaces the file atomically. Only the
	/// <c>Sharding</c> keys are touched; every other section is carried over verbatim.
	/// </summary>
	private void PersistSettings(ShardingOptions policy)
	{
		string path = _settings.EffectiveConfigPath;
		JsonObject root;
		try
		{
			root = File.Exists(path)
				? JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? new JsonObject()
				: new JsonObject();
		}
		catch (JsonException ex)
		{
			throw new IpcException("Shard settings could not be saved; the settings file is invalid: " + ex.Message, ex);
		}
		catch (IOException ex)
		{
			throw new IpcException("Shard settings could not be saved: " + ex.Message, ex);
		}

		JsonObject rdpAudit = EnsureObject(root, RdpAuditOptions.SectionName);
		JsonObject sharding = EnsureObject(rdpAudit, SectionName);

		sharding["Enabled"] = policy.Enabled;
		sharding["ActionsRoot"] = policy.ActionsRoot;
		sharding["ShardCapacityRecords"] = policy.ShardCapacityRecords;
		sharding["MaxOpenWriters"] = policy.MaxOpenWriters;
		sharding["MaxShardFiles"] = policy.MaxShardFiles;
		sharding["MaxShardBytes"] = policy.MaxShardBytes;
		sharding["MaxTotalShardBytes"] = policy.MaxTotalShardBytes;
		sharding["MinFreeDiskBytes"] = policy.MinFreeDiskBytes;
		sharding["OrphanGraceDays"] = policy.OrphanGraceDays;

		JsonNode? aggregationNode = JsonSerializer.SerializeToNode(policy.SubnetAggregation, SectionJson);
		if (aggregationNode is null)
		{
			throw new IpcException("Shard settings could not be serialized.");
		}

		sharding[SubnetAggregationSectionName] = aggregationNode;

		try
		{
			_settings.Save(root.ToJsonString(DocumentJson));
		}
		catch (JsonException ex)
		{
			throw new IpcException("Shard settings were refused because the settings file is invalid: " + ex.Message, ex);
		}
		catch (IOException ex)
		{
			throw new IpcException("Shard settings could not be saved: " + ex.Message, ex);
		}
		catch (InvalidOperationException ex)
		{
			throw new IpcException("Shard settings could not be saved: " + ex.Message, ex);
		}
	}

	private static JsonObject EnsureObject(JsonObject parent, string name)
	{
		if (parent[name] is JsonObject existing)
		{
			return existing;
		}

		JsonObject created = new();
		parent[name] = created;
		return created;
	}

	/// <summary>One line per policy field, used for the audit row's old/new comparison and the
	/// operator-facing save message.</summary>
	private static string DescribePolicy(ShardingOptions options)
		=> string.Format(
			CultureInfo.InvariantCulture,
			"enabled={0}; actionsRoot={1}; capacityRecords={2}; maxOpenWriters={3}; maxShardFiles={4}; maxShardBytes={5}; maxTotalShardBytes={6}; minFreeDiskBytes={7}; orphanGraceDays={8}; subnetAggregation={9}; totalFileThreshold={10}; newFilesPerIntervalLimit={11}; intervalSeconds={12}; minSourceRowsPerInterval={13}",
			options.Enabled,
			options.ActionsRoot.Length == 0 ? "(default)" : options.ActionsRoot,
			options.ShardCapacityRecords,
			options.MaxOpenWriters,
			options.MaxShardFiles,
			options.MaxShardBytes,
			options.MaxTotalShardBytes,
			options.MinFreeDiskBytes,
			options.OrphanGraceDays,
			options.SubnetAggregation.Enabled,
			options.SubnetAggregation.TotalFileThreshold,
			options.SubnetAggregation.NewFilesPerIntervalLimit,
			options.SubnetAggregation.IntervalSeconds,
			options.SubnetAggregation.MinSourceRowsPerInterval);

	// ── Audit ────────────────────────────────────────────────────────────────────

	/// <summary>Writes the single audit row of a policy save, carrying the actor and the old and new
	/// policy. Returns false when the row could not be written, so the caller can report that the change
	/// happened but is not fully accounted for.</summary>
	private async Task<bool> WriteAuditAsync(
		string invokedBy,
		string oldSummary,
		string newSummary,
		CancellationToken cancellationToken)
	{
		if (_operationLog is null)
		{
			return true;
		}

		string actor = string.IsNullOrWhiteSpace(invokedBy) ? "Operator" : invokedBy;
		string message = string.Format(
			CultureInfo.InvariantCulture,
			"{0} applied by {1}; old=[{2}]; new=[{3}]",
			OperationLogOperation,
			actor,
			oldSummary,
			newSummary);
		string detailsJson = JsonSerializer.Serialize(new
		{
			invokedBy = actor,
			configPath = _settings.EffectiveConfigPath,
			oldPolicy = oldSummary,
			newPolicy = newSummary,
		});

		try
		{
			await _operationLog.WriteAsync(new OperationLogEntry
			{
				Severity = OperationLogSeverity.Information,
				Source = OperationLogSource,
				Operation = OperationLogOperation,
				Message = message,
				DetailsJson = detailsJson,
				Actor = actor,
			}, cancellationToken).ConfigureAwait(false);
			return true;
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Sharding policy audit entry could not be written");
			return false;
		}
	}
}
