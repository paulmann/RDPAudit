/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : PagedEventReader.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Service implementation of Core's IPagedEventReader for the REST /events endpoint.
//          Opens a fresh AuditDbContext from the supplied (read-only) options for every call,
//          applies the normalized filters, counts the matching rows, pages with a deterministic
//          total order (TimeUtc DESC, Id DESC) and optionally returns the SQLite EXPLAIN QUERY
//          PLAN digest for the page query. Details are projected only when requested.
// Depends: RdpAudit.Core.Data, RdpAudit.Core.Models, RdpAudit.Core.RestApi, RdpAudit.Core.Util
// Extends: Add filters here only after extending PagedEventsQuery.Normalize.

using System.Data;
using System.Data.Common;
using System.Text;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.RestApi;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.RestApi;

public sealed class PagedEventReader : IPagedEventReader
{
	private readonly IDbContextFactory<AuditDbContext> _contextFactory;

	public PagedEventReader(IDbContextFactory<AuditDbContext> contextFactory)
	{
		_contextFactory = contextFactory ?? throw new ArgumentNullException(nameof(contextFactory));
	}

	public async Task<PagedEventPage> ReadPageAsync(PagedEventsQuery query, CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(query);
		PagedEventsQuery q = query.Normalize();

		await using AuditDbContext db = _contextFactory.CreateDbContext();
		IQueryable<RawEvent> filtered = ApplyFilters(db.RawEvents.AsNoTracking(), q);
		int total = await filtered.CountAsync(cancellationToken).ConfigureAwait(false);

		IQueryable<PagedEventRow> page = Project(
			filtered.OrderByDescending(e => e.TimeUtc).ThenByDescending(e => e.Id).Skip(q.Offset).Take(q.Limit),
			q.IncludeDetails);

		string[] plan = q.IncludeExplain
			? await ReadExplainPlanAsync(db, page, cancellationToken).ConfigureAwait(false)
			: Array.Empty<string>();

		List<PagedEventRow> rows = await page.ToListAsync(cancellationToken).ConfigureAwait(false);
		return new PagedEventPage
		{
			Offset = q.Offset,
			Limit = q.Limit,
			Total = total,
			Events = rows,
			ExplainPlan = plan,
		};
	}

	private static IQueryable<RawEvent> ApplyFilters(IQueryable<RawEvent> source, PagedEventsQuery q)
	{
		IQueryable<RawEvent> result = source;
		if (q.Channel is not null)
		{
			result = result.Where(e => e.Channel == q.Channel);
		}

		if (q.EventId.HasValue)
		{
			result = result.Where(e => e.EventId == q.EventId.Value);
		}

		if (q.SourceIp is not null)
		{
			result = result.Where(e => e.SourceIp == q.SourceIp);
		}

		if (q.UserNameContains is not null)
		{
			string pattern = SqlLikeEscaper.Contains(q.UserNameContains);
			result = result.Where(e => e.UserName != null && EF.Functions.Like(e.UserName, pattern, SqlLikeEscaper.EscapeString));
		}

		if (q.SinceUtc.HasValue)
		{
			result = result.Where(e => e.TimeUtc >= q.SinceUtc.Value);
		}

		if (q.ToUtc.HasValue)
		{
			result = result.Where(e => e.TimeUtc <= q.ToUtc.Value);
		}

		return result;
	}

	private static IQueryable<PagedEventRow> Project(IQueryable<RawEvent> source, bool includeDetails)
	{
		return source.Select(e => new PagedEventRow
		{
			Id = e.Id,
			EventId = e.EventId,
			Channel = e.Channel,
			TimeUtc = e.TimeUtc,
			IngestionSequence = e.IngestionSequence,
			EventLayer = e.EventLayer,
			SourceIp = e.SourceIp,
			SourceIpDerived = e.SourceIpDerived,
			SourceIpUnresolved = e.SourceIpUnresolved,
			UserName = e.UserName,
			Domain = e.Domain,
			SessionId = e.SessionId,
			LogonType = e.LogonType,
			LogonId = e.LogonId,
			AuthPackage = e.AuthPackage,
			Status = e.Status,
			ProcessName = e.ProcessName,
			CommandLine = e.CommandLine,
			ObjectName = e.ObjectName,
			AccessMask = e.AccessMask,
			Details = includeDetails ? e.Details : null,
		});
	}

	private static async Task<string[]> ReadExplainPlanAsync(
		AuditDbContext db,
		IQueryable pageQuery,
		CancellationToken cancellationToken)
	{
		string sql = StripParamDirectives(pageQuery.ToQueryString());
		DbConnection connection = db.Database.GetDbConnection();
		bool wasClosed = connection.State != ConnectionState.Open;
		if (wasClosed)
		{
			await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
		}

		try
		{
			using DbCommand command = connection.CreateCommand();
			// StripParamDirectives removes the leading ".param set" lines that the
			// Microsoft.Data.Sqlite provider emits in ToQueryString(); the remaining SELECT
			// still plans correctly because EXPLAIN QUERY PLAN never needs parameter values.
			// EXPLAIN only plans the statement - it never executes it, so there is no
			// injection surface from a user-supplied filter value.
#pragma warning disable CA2100 // Review SQL injection vulnerabilities
			command.CommandText = "EXPLAIN QUERY PLAN " + sql;
#pragma warning restore CA2100
			await using DbDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
			List<string> lines = [];
			while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
			{
				// EXPLAIN QUERY PLAN columns: id, parent, notused, detail.
				lines.Add(reader.IsDBNull(3) ? string.Empty : reader.GetString(3));
			}

			return [.. lines];
		}
		catch (Exception ex)
		{
			throw new InvalidOperationException("EXPLAIN QUERY PLAN failed for: " + sql, ex);
		}
		finally
		{
			if (wasClosed)
			{
				await connection.CloseAsync().ConfigureAwait(false);
			}
		}
	}

	private static string StripParamDirectives(string sql)
	{
		// The Microsoft.Data.Sqlite provider emits ".param set @name value" directives
		// before the SELECT. EXPLAIN QUERY PLAN does not accept them and does not need
		// the values: planning is value-independent, so drop the directives.
		StringBuilder builder = new(sql.Length);
		foreach (ReadOnlySpan<char> line in sql.AsSpan().EnumerateLines())
		{
			if (!line.TrimStart().StartsWith(".param", StringComparison.Ordinal))
			{
				builder.Append(line);
				builder.Append('\n');
			}
		}

		return builder.ToString();
	}
}
