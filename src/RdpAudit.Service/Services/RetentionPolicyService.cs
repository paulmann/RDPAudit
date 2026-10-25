/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionPolicyService.cs
// Project: RdpAudit.Service (RdpAudit.Service.Services)
// Purpose: Reads and writes the retention settings the Database tab governs: the global
//          StorageOptions windows, the per-event-code EventRetention overrides and the
//          information-density RetentionPolicyOptions block. Reads report both the configured and
//          the clamped-effective value of every clampsable field, so a hand-edited appsettings.json
//          is visible as such instead of being silently normalised in the UI. Writes validate the
//          whole request BEFORE touching anything, clamp through the RetentionPolicyOptions.Resolve*
//          helpers, persist the clamped values into appsettings.json through SettingsManager (atomic
//          replace, secret handling, schema validation) and the overrides into EventRetention, and
//          write one OperationLog row carrying the old value, the new value and the invoking
//          Windows identity. The database transaction is committed only after the settings document
//          has been written, so an invalid or unwritable request leaves no partial change.
// Depends: AuditDbContext, RetentionPolicyOptions, SettingsManager, IOperationLogWriter,
//          RetentionPolicyDto, EventCatalog
// Extends: Add a clampsable field by adding it to RetentionPolicyValuesDto and its Resolve* branch
//          here; add a validation rule by extending Validate*.

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>Read/write service for the retention settings the Database tab governs.</summary>
public sealed class RetentionPolicyService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Largest retention window the editor accepts, in days (one hundred years). A larger
	/// value is refused rather than clamped, because it is almost always a typo and silently
	/// turning it into "forever" would hide that.</summary>
	internal const int MaxRetentionWindowDays = 36_500;

	/// <summary>Logical OperationLog source for retention mutations.</summary>
	private const string OperationLogSource = "Retention";

	/// <summary>Logical OperationLog operation name for retention mutations.</summary>
	private const string OperationLogOperation = "SaveRetentionPolicy";

	/// <summary>Name of the settings section written under <c>RdpAudit.Storage</c>.</summary>
	private const string PolicySectionName = "RetentionPolicy";

	/// <summary>Section serializer. PascalCase and string enums match the rest of appsettings.json
	/// (see <c>AppSettingsTemplate</c>), so a hand-edited document and a service-written document
	/// look the same.</summary>
	private static readonly JsonSerializerOptions SectionJson = new()
	{
		WriteIndented = true,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
		Converters = { new JsonStringEnumConverter() },
	};

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly SettingsManager _settings;
	private readonly IOperationLogWriter? _operationLog;
	private readonly ILogger<RetentionPolicyService> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service over the database factory, the live options monitor and the
	/// settings writer.</summary>
	public RetentionPolicyService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		SettingsManager settings,
		ILogger<RetentionPolicyService> logger,
		IOperationLogWriter? operationLog = null)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(settings);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_settings = settings;
		_logger = logger;
		_operationLog = operationLog;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Reads the effective retention settings. A failure to read the per-event overrides
	/// is reported on the DTO rather than thrown, so the caller still receives the policy.</summary>
	public async Task<RetentionPolicyDto> GetAsync(CancellationToken cancellationToken)
	{
		DateTime nowUtc = DateTime.UtcNow;
		StorageOptions storage = _options.CurrentValue.Storage;
		RetentionPolicyDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Policy = BuildPolicyValues(storage.RetentionPolicy),
			GlobalWindows = BuildWindows(storage),
			ConfigPath = _settings.EffectiveConfigPath,
			QueriedUtc = nowUtc,
		};

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			dto.EventWindows = await ReadEventWindowsAsync(db, cancellationToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Retention per-event overrides could not be read");
			dto.Status = IpcResultStatus.Unavailable;
			dto.EventWindowsUnavailable = true;
			dto.Message = "The per-event retention overrides could not be read; the rest of the policy is current.";
		}

		return dto;
	}

	/// <summary>
	/// Applies an operator-edited retention policy. The request is validated and clamped in full
	/// before anything is written; an invalid request is refused with no partial write. On success the
	/// settings document is written first (atomic replace, validated by <see cref="SettingsManager"/>)
	/// and the database transaction is committed only afterwards, and one OperationLog row records the
	/// old value, the new value and <paramref name="invokedBy"/>.
	/// </summary>
	/// <exception cref="IpcException">The request is structurally invalid or carries nothing to save.</exception>
	public async Task<RetentionPolicyDto> SaveAsync(
		RetentionPolicyMutationRequest request,
		string invokedBy,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(request);

		StorageOptions currentStorage = _options.CurrentValue.Storage;
		ResolvedMutation mutation = Resolve(request, currentStorage);

		DateTime nowUtc = DateTime.UtcNow;
		string oldSummary = DescribePolicy(currentStorage.RetentionPolicy) + "; " + DescribeWindows(currentStorage);
		string newSummary = DescribePolicy(mutation.Policy) + "; " + DescribeWindows(mutation.Storage);
		long nowTicks = nowUtc.Ticks;

		int overridesChanged = 0;
		await using (AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false))
		{
			await using IDbContextTransaction transaction =
				await db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
			try
			{
				overridesChanged = await ApplyEventWindowsAsync(db, mutation, nowTicks, cancellationToken)
					.ConfigureAwait(false);
				await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

				// The settings document is written inside the open transaction: if the file cannot be
				// written, the transaction rolls back and the database keeps its previous overrides, so
				// the operator never ends up with half of a change.
				PersistSettings(mutation, currentStorage);

				await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
			}
			catch
			{
				await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
				throw;
			}
		}

		RetentionPolicyDto result = new()
		{
			Status = IpcResultStatus.Success,
			Policy = BuildPolicyValues(mutation.Policy),
			GlobalWindows = BuildWindows(mutation.Storage),
			ConfigPath = _settings.EffectiveConfigPath,
			QueriedUtc = nowUtc,
		};

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			result.EventWindows = await ReadEventWindowsAsync(db, cancellationToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Retention overrides could not be re-read after save");
			result.EventWindowsUnavailable = true;
		}

		bool audited = await WriteAuditAsync(
			invokedBy,
			oldSummary,
			newSummary,
			mutation,
			overridesChanged,
			cancellationToken).ConfigureAwait(false);
		if (!audited)
		{
			// The change is durable; failing to record it is a compliance problem, so say so instead
			// of returning a clean success.
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "The retention policy was saved, but the audit entry could not be written. See the service log.";
		}

		return result;
	}

	// ── Validation and clamping ──────────────────────────────────────────────────

	/// <summary>
	/// Validates and clamps the whole request. Structural faults (unknown anchor scope, unknown event
	/// id, duplicated event id, negative or absurd window, non-positive protected code, nothing to
	/// save) are refused; a numeric retention-policy field outside its supported range is clamped
	/// through the matching <c>Resolve*</c> helper and the clamped value is what gets written.
	/// </summary>
	private static ResolvedMutation Resolve(RetentionPolicyMutationRequest request, StorageOptions currentStorage)
	{
		bool hasPolicy = request.Policy is not null;
		bool hasWindows = request.GlobalWindows is not null;
		bool hasOverrides = request.EventWindows.Count > 0 || request.EventWindowsReplaceAll;
		if (!hasPolicy && !hasWindows && !hasOverrides)
		{
			throw new IpcException("SaveRetentionPolicy requires at least one policy, window or per-event change.");
		}

		RetentionPolicyOptions policy = hasPolicy ? ClampPolicy(request.Policy!) : ClonePolicy(currentStorage.RetentionPolicy);
		StorageOptions storage = CloneStorage(currentStorage);
		if (hasWindows)
		{
			ValidateWindows(request.GlobalWindows!);
			storage.EventRetentionDays = request.GlobalWindows!.EventRetentionDays;
			storage.AlertRetentionDays = request.GlobalWindows.AlertRetentionDays;
			storage.AbuseReportRetentionDays = request.GlobalWindows.AbuseReportRetentionDays;
			storage.ActiveBlockRetentionDays = request.GlobalWindows.ActiveBlockRetentionDays;
			storage.AttackStatRetentionDays = request.GlobalWindows.AttackStatRetentionDays;
			storage.SessionIpCorrelationRetentionDays = request.GlobalWindows.SessionIpCorrelationRetentionDays;
			storage.RdpConnectionFactRetentionDays = request.GlobalWindows.RdpConnectionFactRetentionDays;
			storage.LogRetentionDays = request.GlobalWindows.LogRetentionDays;
		}

		storage.RetentionPolicy = policy;
		List<EventRetentionWindowDto> overrides = ValidateEventWindows(request.EventWindows);
		return new ResolvedMutation(storage, policy, overrides, request.EventWindowsReplaceAll);
	}

	private static RetentionPolicyOptions ClampPolicy(RetentionPolicyValuesDto source)
	{
		if (!Enum.IsDefined(source.AnchorScope))
		{
			throw new IpcException(string.Format(
				CultureInfo.InvariantCulture,
				"SaveRetentionPolicy: AnchorScope {0} is not a supported anchor scope.",
				source.AnchorScope));
		}

		List<int> protectedCodes = [];
		foreach (int code in source.ProtectedEventIds)
		{
			if (code <= 0)
			{
				throw new IpcException(string.Format(
					CultureInfo.InvariantCulture,
					"SaveRetentionPolicy: ProtectedEventIds contains the invalid event id {0}.",
					code));
			}

			protectedCodes.Add(code);
		}

		if (protectedCodes.Count == 0)
		{
			// An empty protected list would resolve back to the built-in set anyway; write that set
			// explicitly so the document says what is actually enforced.
			protectedCodes.AddRange(RetentionPolicyOptions.DefaultProtectedEventIds);
		}

		protectedCodes.Sort();
		return new RetentionPolicyOptions
		{
			Enabled = source.Enabled,
			LegalHold = source.LegalHold,
			AnchorScope = source.AnchorScope,
			ProtectedEventIds = [.. protectedCodes],
			TailKeepPerCode = Math.Clamp(
				source.TailKeepPerCode,
				RetentionPolicyOptions.MinTailKeepPerCode,
				RetentionPolicyOptions.MaxTailKeepPerCode),
			CandidateMinRows = Math.Clamp(
				source.CandidateMinRows,
				RetentionPolicyOptions.MinCandidateMinRows,
				RetentionPolicyOptions.MaxCandidateMinRows),
			MinAgeDays = Math.Clamp(
				source.MinAgeDays,
				RetentionPolicyOptions.MinMinAgeDays,
				RetentionPolicyOptions.MaxMinAgeDays),
			MaxRowsPerPass = Math.Clamp(
				source.MaxRowsPerPass,
				RetentionPolicyOptions.MinMaxRowsPerPass,
				RetentionPolicyOptions.MaxMaxRowsPerPass),
			MaxWriterLockMs = Math.Clamp(
				source.MaxWriterLockMs,
				RetentionPolicyOptions.MinMaxWriterLockMs,
				RetentionPolicyOptions.MaxMaxWriterLockMs),
			DeleteBatchRows = Math.Clamp(
				source.DeleteBatchRows,
				RetentionPolicyOptions.MinDeleteBatchRows,
				RetentionPolicyOptions.MaxDeleteBatchRows),
			MaxDatabaseBytes = Math.Max(0L, source.MaxDatabaseBytes),
			MaxRawEventRows = Math.Max(0L, source.MaxRawEventRows),
			MinFreeDiskBytes = Math.Max(0L, source.MinFreeDiskBytes),
		};
	}

	private static void ValidateWindows(RetentionWindowsDto windows)
	{
		ValidateWindow("EventRetentionDays", windows.EventRetentionDays);
		ValidateWindow("AlertRetentionDays", windows.AlertRetentionDays);
		ValidateWindow("AbuseReportRetentionDays", windows.AbuseReportRetentionDays);
		ValidateWindow("ActiveBlockRetentionDays", windows.ActiveBlockRetentionDays);
		ValidateWindow("AttackStatRetentionDays", windows.AttackStatRetentionDays);
		ValidateWindow("SessionIpCorrelationRetentionDays", windows.SessionIpCorrelationRetentionDays);
		ValidateWindow("RdpConnectionFactRetentionDays", windows.RdpConnectionFactRetentionDays);
		ValidateWindow("LogRetentionDays", windows.LogRetentionDays);
	}

	private static void ValidateWindow(string name, int days)
	{
		if (days < 0 || days > MaxRetentionWindowDays)
		{
			throw new IpcException(string.Format(
				CultureInfo.InvariantCulture,
				"SaveRetentionPolicy: {0} must be between 0 and {1} days.",
				name,
				MaxRetentionWindowDays));
		}
	}

	/// <summary>
	/// Validates the per-event override set: every id must be catalogued (the Event Collection tab is
	/// the only other writer of this table and enforces the same rule), no id may appear twice, and a
	/// window must be a sane number of days.
	/// </summary>
	private static List<EventRetentionWindowDto> ValidateEventWindows(List<EventRetentionWindowDto> windows)
	{
		List<EventRetentionWindowDto> validated = new(windows.Count);
		HashSet<int> seen = new(windows.Count);
		foreach (EventRetentionWindowDto window in windows)
		{
			if (!EventCatalog.TryGet(window.EventId, out _))
			{
				throw new IpcException(string.Format(
					CultureInfo.InvariantCulture,
					"SaveRetentionPolicy: event id {0} is not present in the Event Collection catalog.",
					window.EventId));
			}

			if (!seen.Add(window.EventId))
			{
				throw new IpcException(string.Format(
					CultureInfo.InvariantCulture,
					"SaveRetentionPolicy: event id {0} was supplied more than once.",
					window.EventId));
			}

			if (window.RetentionDays < 0 || window.RetentionDays > MaxRetentionWindowDays)
			{
				throw new IpcException(string.Format(
					CultureInfo.InvariantCulture,
					"SaveRetentionPolicy: retention for event id {0} must be between 0 and {1} days.",
					window.EventId,
					MaxRetentionWindowDays));
			}

			validated.Add(new EventRetentionWindowDto
			{
				EventId = window.EventId,
				RetentionDays = window.RetentionDays,
			});
		}

		return validated;
	}

	// ── Persistence ──────────────────────────────────────────────────────────────

	/// <summary>
	/// Upserts the requested per-event overrides and, when the request asked for it, removes every
	/// override the request did not name. The rows are only staged here; the caller commits them.
	/// </summary>
	private static async Task<int> ApplyEventWindowsAsync(
		AuditDbContext db,
		ResolvedMutation mutation,
		long nowTicks,
		CancellationToken cancellationToken)
	{
		if (!mutation.EventWindowsReplaceAll && mutation.EventWindows.Count == 0)
		{
			return 0;
		}

		List<EventRetention> existing = await db.EventRetentions.ToListAsync(cancellationToken).ConfigureAwait(false);
		Dictionary<int, EventRetention> byEventId = new(existing.Count);
		foreach (EventRetention row in existing)
		{
			byEventId[row.EventId] = row;
		}

		int changed = 0;
		if (mutation.EventWindowsReplaceAll)
		{
			HashSet<int> desired = [.. mutation.EventWindows.Select(window => window.EventId)];
			foreach (EventRetention row in existing)
			{
				if (!desired.Contains(row.EventId))
				{
					db.EventRetentions.Remove(row);
					changed++;
				}
			}
		}

		foreach (EventRetentionWindowDto window in mutation.EventWindows)
		{
			if (byEventId.TryGetValue(window.EventId, out EventRetention? row))
			{
				if (row.RetentionDays != window.RetentionDays)
				{
					row.RetentionDays = window.RetentionDays;
					row.UpdatedUtc = nowTicks;
					changed++;
				}

				continue;
			}

			db.EventRetentions.Add(new EventRetention
			{
				EventId = window.EventId,
				RetentionDays = window.RetentionDays,
				UpdatedUtc = nowTicks,
			});
			changed++;
		}

		return changed;
	}

	/// <summary>
	/// Merges the resolved retention values into the existing appsettings.json document and writes it
	/// through <see cref="SettingsManager"/>, which validates that the document still binds to
	/// <c>RdpAuditOptions</c>, preserves protected secrets and replaces the file atomically. Only the
	/// retention keys are touched; every other section is carried over verbatim. <c>IOptionsMonitor</c>
	/// picks the new file up through its change token, so the policy is live without a service restart.
	/// </summary>
	private void PersistSettings(ResolvedMutation mutation, StorageOptions currentStorage)
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
			throw new IpcException("Retention settings could not be saved; the settings file is invalid: " + ex.Message, ex);
		}
		catch (IOException ex)
		{
			throw new IpcException("Retention settings could not be saved: " + ex.Message, ex);
		}

		JsonObject rdpAudit = EnsureObject(root, RdpAuditOptions.SectionName);
		JsonObject storage = EnsureObject(rdpAudit, "Storage");

		storage["EventRetentionDays"] = mutation.Storage.EventRetentionDays;
		storage["AlertRetentionDays"] = mutation.Storage.AlertRetentionDays;
		storage["AbuseReportRetentionDays"] = mutation.Storage.AbuseReportRetentionDays;
		storage["ActiveBlockRetentionDays"] = mutation.Storage.ActiveBlockRetentionDays;
		storage["AttackStatRetentionDays"] = mutation.Storage.AttackStatRetentionDays;
		storage["SessionIpCorrelationRetentionDays"] = mutation.Storage.SessionIpCorrelationRetentionDays;
		storage["RdpConnectionFactRetentionDays"] = mutation.Storage.RdpConnectionFactRetentionDays;
		storage["LogRetentionDays"] = mutation.Storage.LogRetentionDays;
		// DatabasePath and every non-retention Storage key stay exactly as the operator had them.
		storage["DatabasePath"] = currentStorage.DatabasePath;
		storage["LogDirectory"] = currentStorage.LogDirectory;
		storage["MaintenanceBatchSize"] = currentStorage.MaintenanceBatchSize;

		JsonNode? policyNode = JsonSerializer.SerializeToNode(mutation.Policy, SectionJson);
		if (policyNode is null)
		{
			throw new IpcException("Retention settings could not be serialized.");
		}

		storage[PolicySectionName] = policyNode;

		try
		{
			_settings.Save(root.ToJsonString(JsonOptions.Indented));
		}
		catch (JsonException ex)
		{
			throw new IpcException("Retention settings were refused because the settings file is invalid: " + ex.Message, ex);
		}
		catch (IOException ex)
		{
			throw new IpcException("Retention settings could not be saved: " + ex.Message, ex);
		}
		catch (InvalidOperationException ex)
		{
			throw new IpcException("Retention settings could not be saved: " + ex.Message, ex);
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

	// ── Audit ────────────────────────────────────────────────────────────────────

	/// <summary>
	/// Writes the SOC2 audit row for the mutation: the invoking Windows identity as the actor, and the
	/// old and new value in the message and the structured details. Returns false when the row could
	/// not be written, so the caller can report an unaudited change instead of a clean success.
	/// </summary>
	private async Task<bool> WriteAuditAsync(
		string invokedBy,
		string oldSummary,
		string newSummary,
		ResolvedMutation mutation,
		int overridesChanged,
		CancellationToken cancellationToken)
	{
		if (_operationLog is null)
		{
			return false;
		}

		string actor = string.IsNullOrWhiteSpace(invokedBy) ? "Operator" : invokedBy;
		string message =
			"SaveRetentionPolicy applied by " + actor + "; perEventOverridesChanged=" +
			overridesChanged.ToString(CultureInfo.InvariantCulture) +
			"; replaceAll=" + mutation.EventWindowsReplaceAll.ToString(CultureInfo.InvariantCulture) +
			"; old=[" + oldSummary + "]; new=[" + newSummary + "]";

		string detailsJson = JsonSerializer.Serialize(
			new
			{
				invokedBy = actor,
				configPath = _settings.EffectiveConfigPath,
				perEventOverridesChanged = overridesChanged,
				eventWindowsReplaceAll = mutation.EventWindowsReplaceAll,
				oldPolicy = oldSummary,
				newPolicy = newSummary,
			},
			JsonOptions.Default);

		try
		{
			await _operationLog.WriteAsync(
				new OperationLogEntry
				{
					Severity = OperationLogSeverity.Information,
					Source = OperationLogSource,
					Operation = OperationLogOperation,
					Message = message,
					DetailsJson = detailsJson,
					Actor = actor,
				},
				cancellationToken).ConfigureAwait(false);
			return true;
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Retention policy audit entry could not be written");
			return false;
		}
	}

	// ── Projection ───────────────────────────────────────────────────────────────

	/// <summary>Projects the policy with both the configured and the clamped value of every
	/// clampsable field, plus the supported bounds, so a client never has to invent a limit.</summary>
	private static RetentionPolicyValuesDto BuildPolicyValues(RetentionPolicyOptions policy)
		=> new()
		{
			Enabled = policy.Enabled,
			LegalHold = policy.LegalHold,
			AnchorScope = policy.AnchorScope,
			EffectiveAnchorScope = policy.ResolveAnchorScope(),
			ProtectedEventIds = [.. policy.ProtectedEventIds],
			EffectiveProtectedEventIds = [.. policy.ResolveProtectedEventIds()],
			TailKeepPerCode = policy.TailKeepPerCode,
			EffectiveTailKeepPerCode = policy.ResolveTailKeepPerCode(),
			CandidateMinRows = policy.CandidateMinRows,
			EffectiveCandidateMinRows = policy.ResolveCandidateMinRows(),
			MinAgeDays = policy.MinAgeDays,
			EffectiveMinAgeDays = policy.ResolveMinAgeDays(),
			MaxRowsPerPass = policy.MaxRowsPerPass,
			EffectiveMaxRowsPerPass = policy.ResolveMaxRowsPerPass(),
			MaxWriterLockMs = policy.MaxWriterLockMs,
			EffectiveMaxWriterLockMs = policy.ResolveMaxWriterLockMs(),
			DeleteBatchRows = policy.DeleteBatchRows,
			EffectiveDeleteBatchRows = policy.ResolveDeleteBatchRows(),
			MaxDatabaseBytes = policy.MaxDatabaseBytes,
			EffectiveMaxDatabaseBytes = policy.ResolveMaxDatabaseBytes(),
			MaxRawEventRows = policy.MaxRawEventRows,
			EffectiveMaxRawEventRows = policy.ResolveMaxRawEventRows(),
			MinFreeDiskBytes = policy.MinFreeDiskBytes,
			EffectiveMinFreeDiskBytes = policy.ResolveMinFreeDiskBytes(),
			HasAnyPressureTrigger = policy.HasAnyPressureTrigger(),
			PressureDeletionAllowed = policy.IsPressureDeletionAllowed(),
			Bounds = new RetentionPolicyBoundsDto(),
		};

	private static RetentionWindowsDto BuildWindows(StorageOptions storage)
		=> new()
		{
			EventRetentionDays = storage.EventRetentionDays,
			AlertRetentionDays = storage.AlertRetentionDays,
			AbuseReportRetentionDays = storage.AbuseReportRetentionDays,
			ActiveBlockRetentionDays = storage.ActiveBlockRetentionDays,
			AttackStatRetentionDays = storage.AttackStatRetentionDays,
			SessionIpCorrelationRetentionDays = storage.SessionIpCorrelationRetentionDays,
			RdpConnectionFactRetentionDays = storage.RdpConnectionFactRetentionDays,
			LogRetentionDays = storage.LogRetentionDays,
		};

	/// <summary>
	/// Reads the persisted per-event overrides and enriches each one with the catalog metadata the
	/// editor renders. The query is bounded by the number of overrides the operator ever created,
	/// which is at most the catalog size.
	/// </summary>
	private static async Task<List<EventRetentionWindowDto>> ReadEventWindowsAsync(
		AuditDbContext db,
		CancellationToken cancellationToken)
	{
		List<EventRetention> rows = await db.EventRetentions.AsNoTracking()
			.OrderBy(row => row.EventId)
			.ToListAsync(cancellationToken).ConfigureAwait(false);

		List<EventRetentionWindowDto> windows = new(rows.Count);
		foreach (EventRetention row in rows)
		{
			bool catalogued = EventCatalog.TryGet(row.EventId, out EventDescriptor? descriptor);
			windows.Add(new EventRetentionWindowDto
			{
				EventId = row.EventId,
				Channel = catalogued ? descriptor!.Channel : string.Empty,
				DisplayName = catalogued ? descriptor!.Description : string.Empty,
				RetentionDays = row.RetentionDays,
				DefaultRetentionDays = catalogued ? descriptor!.DefaultRetentionDays : -1,
				UpdatedUtc = row.UpdatedUtc > 0 ? new DateTime(row.UpdatedUtc, DateTimeKind.Utc) : null,
			});
		}

		return windows;
	}

	// ── Summaries ────────────────────────────────────────────────────────────────

	private static string DescribePolicy(RetentionPolicyOptions policy) => policy.Describe();

	private static string DescribeWindows(StorageOptions storage)
		=> string.Format(
			CultureInfo.InvariantCulture,
			"Windows(events={0} alerts={1} abuseReports={2} activeBlocks={3} attackStats={4} correlations={5} connectionFacts={6} logs={7})",
			storage.EventRetentionDays,
			storage.AlertRetentionDays,
			storage.AbuseReportRetentionDays,
			storage.ActiveBlockRetentionDays,
			storage.AttackStatRetentionDays,
			storage.SessionIpCorrelationRetentionDays,
			storage.RdpConnectionFactRetentionDays,
			storage.LogRetentionDays);

	private static RetentionPolicyOptions ClonePolicy(RetentionPolicyOptions source)
		=> new()
		{
			Enabled = source.Enabled,
			LegalHold = source.LegalHold,
			AnchorScope = source.AnchorScope,
			ProtectedEventIds = [.. source.ProtectedEventIds],
			TailKeepPerCode = source.TailKeepPerCode,
			CandidateMinRows = source.CandidateMinRows,
			MinAgeDays = source.MinAgeDays,
			MaxRowsPerPass = source.MaxRowsPerPass,
			MaxWriterLockMs = source.MaxWriterLockMs,
			DeleteBatchRows = source.DeleteBatchRows,
			MaxDatabaseBytes = source.MaxDatabaseBytes,
			MaxRawEventRows = source.MaxRawEventRows,
			MinFreeDiskBytes = source.MinFreeDiskBytes,
		};

	/// <summary>Copies every storage field the retention writer must carry over untouched.</summary>
	private static StorageOptions CloneStorage(StorageOptions source)
		=> new()
		{
			DatabasePath = source.DatabasePath,
			LogDirectory = source.LogDirectory,
			MaintenanceBatchSize = source.MaintenanceBatchSize,
			EventRetentionDays = source.EventRetentionDays,
			AlertRetentionDays = source.AlertRetentionDays,
			AbuseReportRetentionDays = source.AbuseReportRetentionDays,
			ActiveBlockRetentionDays = source.ActiveBlockRetentionDays,
			AttackStatRetentionDays = source.AttackStatRetentionDays,
			SessionIpCorrelationRetentionDays = source.SessionIpCorrelationRetentionDays,
			RdpConnectionFactRetentionDays = source.RdpConnectionFactRetentionDays,
			LogRetentionDays = source.LogRetentionDays,
			RetentionPolicy = source.RetentionPolicy,
			Backup = source.Backup,
			Decimation = source.Decimation,
		};

	// ── Internal model ───────────────────────────────────────────────────────────

	/// <summary>A validated, clamped mutation ready to be persisted.</summary>
	private sealed record ResolvedMutation(
		StorageOptions Storage,
		RetentionPolicyOptions Policy,
		List<EventRetentionWindowDto> EventWindows,
		bool EventWindowsReplaceAll);
}
