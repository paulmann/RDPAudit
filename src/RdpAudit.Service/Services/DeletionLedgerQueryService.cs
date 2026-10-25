/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DeletionLedgerQueryService.cs
// Project: RdpAudit.Service (RdpAudit.Service.Services)
// Purpose: Bounded, filtered, paged, read-only reader over EventDeletionLedger for the Database
//          tab's Ledger grid. Append-only table, newest first, every filter optional; the page size
//          is clamped server-side so a client can never ask the service to materialize the ledger.
//          Read-only by construction: the context is used with AsNoTracking and no write statement
//          is issued on any path.
// Depends: AuditDbContext, DeletionLedgerQueryRequest, DeletionLedgerEntryDto, IpcException
// Extends: Add a filter by extending DeletionLedgerQueryRequest and ApplyFilters here.

using System.Globalization;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Services;

/// <summary>Read-only paged reader over the append-only deletion ledger.</summary>
public sealed class DeletionLedgerQueryService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Page size used when the request does not ask for one.</summary>
	internal const int DefaultPageSize = 100;

	/// <summary>Upper bound on one page. The ledger is small, but a client must never be able to
	/// ask for an unbounded materialization.</summary>
	internal const int MaxPageSize = 1000;

	private readonly IDbContextFactory<AuditDbContext> _factory;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the reader over the database factory.</summary>
	public DeletionLedgerQueryService(IDbContextFactory<AuditDbContext> factory)
	{
		ArgumentNullException.ThrowIfNull(factory);
		_factory = factory;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Returns one page of ledger rows, newest first. An unparseable address filter is refused as
	/// invalid input; a store that cannot be read yields a page whose status is
	/// <see cref="IpcResultStatus.Unavailable"/>.
	/// </summary>
	/// <exception cref="IpcException">The request carries an address filter that is not hexadecimal.</exception>
	public async Task<DeletionLedgerPageDto> QueryAsync(
		DeletionLedgerQueryRequest request,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(request);

		int page = Math.Max(0, request.Page);
		int pageSize = request.PageSize <= 0 ? DefaultPageSize : Math.Min(request.PageSize, MaxPageSize);
		byte[]? ipBinary16 = ParseIpFilter(request.IpHex);
		DateTime fromUtc = request.FromUtc ?? DateTime.MinValue;
		DateTime toUtc = request.ToUtc ?? DateTime.MaxValue;
		if (toUtc < fromUtc)
		{
			throw new IpcException("GetDeletionLedger: ToUtc must not be earlier than FromUtc.");
		}

		DateTime queriedUtc = DateTime.UtcNow;
		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
			IQueryable<EventDeletionLedger> query = ApplyFilters(
				db.EventDeletionLedger.AsNoTracking(),
				request,
				ipBinary16,
				fromUtc,
				toUtc);

			long totalMatching = await query.LongCountAsync(cancellationToken).ConfigureAwait(false);

			List<DeletionLedgerEntryDto> items = await query
				.OrderByDescending(row => row.CreatedUtc)
				.ThenByDescending(row => row.Id)
				.Skip(page * pageSize)
				.Take(pageSize)
				.Select(row => new DeletionLedgerEntryDto
				{
					Id = row.Id,
					EventCode = row.EventCode,
					Scope = row.Scope,
					WindowStartUtc = row.WindowStartUtc,
					WindowEndUtc = row.WindowEndUtc,
					RowsDeleted = row.RowsDeleted,
					Trigger = row.Trigger,
					RuleVersion = row.RuleVersion,
					Reason = row.Reason,
					InitiatedBy = row.InitiatedBy,
					CreatedUtc = row.CreatedUtc,
				})
				.ToListAsync(cancellationToken).ConfigureAwait(false);

			// The address is hex-encoded in managed code: SQLite has no hex() projection that EF can
			// translate for a BLOB column, and the page is already bounded by MaxPageSize.
			List<byte[]?> addresses = await query
				.OrderByDescending(row => row.CreatedUtc)
				.ThenByDescending(row => row.Id)
				.Skip(page * pageSize)
				.Take(pageSize)
				.Select(row => row.IpBinary16)
				.ToListAsync(cancellationToken).ConfigureAwait(false);

			for (int index = 0; index < items.Count && index < addresses.Count; index++)
			{
				items[index].IpHex = addresses[index] is { Length: > 0 } bytes
					? Convert.ToHexString(bytes)
					: string.Empty;
			}

			DeletionLedgerPageDto dto = new()
			{
				Status = IpcResultStatus.Success,
				Items = items,
				TotalMatching = totalMatching,
				Page = page,
				PageSize = pageSize,
				HasMore = (long)(page + 1) * pageSize < totalMatching,
				QueriedUtc = queriedUtc,
			};

			dto.Message = string.Format(
				CultureInfo.InvariantCulture,
				"page={0} pageSize={1} returned={2} totalMatching={3} hasMore={4}",
				dto.Page,
				dto.PageSize,
				dto.Items.Count,
				dto.TotalMatching,
				dto.HasMore);
			return dto;
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			return new DeletionLedgerPageDto
			{
				Status = IpcResultStatus.Unavailable,
				Page = page,
				PageSize = pageSize,
				QueriedUtc = queriedUtc,
				Message = "The deletion ledger could not be read: " + ex.GetType().Name + ". See the service log.",
			};
		}
	}

	// ── Filtering ────────────────────────────────────────────────────────────────

	private static IQueryable<EventDeletionLedger> ApplyFilters(
		IQueryable<EventDeletionLedger> query,
		DeletionLedgerQueryRequest request,
		byte[]? ipBinary16,
		DateTime fromUtc,
		DateTime toUtc)
	{
		if (request.EventCode is { } eventCode)
		{
			query = query.Where(row => row.EventCode == eventCode);
		}

		if (request.Scope is { } scope)
		{
			query = query.Where(row => row.Scope == scope);
		}

		if (ipBinary16 is not null)
		{
			query = query.Where(row => row.IpBinary16 == ipBinary16);
		}

		if (request.FromUtc is not null)
		{
			query = query.Where(row => row.CreatedUtc >= fromUtc);
		}

		if (request.ToUtc is not null)
		{
			query = query.Where(row => row.CreatedUtc <= toUtc);
		}

		return query;
	}

	/// <summary>Parses the optional hexadecimal address filter. Null or blank means "no filter"; a
	/// non-hexadecimal value is refused rather than silently treated as "no filter", because a
	/// silently ignored filter reads as "the ledger has no rows for that address".</summary>
	private static byte[]? ParseIpFilter(string? ipHex)
	{
		if (string.IsNullOrWhiteSpace(ipHex))
		{
			return null;
		}

		try
		{
			return Convert.FromHexString(ipHex.Trim());
		}
		catch (FormatException ex)
		{
			throw new IpcException("GetDeletionLedger: IpHex is not a hexadecimal address.", ex);
		}
	}
}
