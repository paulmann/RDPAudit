// File:    src/RdpAudit.Configurator/Services/LocalSessionEnrichmentProvider.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Read-only Configurator-side adapter that loads SessionIpCorrelation and
//          RdpConnectionFact rows from the local SQLite audit database and feeds the pure
//          LocalSessionEnricher so the Remote RDP Clients tab still populates Client IP and
//          Hist* fields even when the service IPC is unreachable. The provider never writes
//          and never throws — failures are returned through the LocalSessionEnrichmentReport
//          status so the UI can show "historical enrichment unavailable: <reason>" without
//          blowing up the page.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of <see cref="LocalSessionEnrichmentProvider.EnrichAsync"/>.</summary>
public sealed record LocalSessionEnrichmentReport(
	bool Available,
	string Status,
	LocalSessionEnrichmentResult? Result)
{
	public static LocalSessionEnrichmentReport Unavailable(string reason) =>
		new(false, reason, null);

	public static LocalSessionEnrichmentReport AppliedFrom(LocalSessionEnrichmentResult result, string source) =>
		new(true, source, result);
}

/// <summary>Read-only adapter that loads correlation / fact rows from the local SQLite DB and
/// feeds <see cref="LocalSessionEnricher"/>.</summary>
[SupportedOSPlatform("windows")]
public sealed class LocalSessionEnrichmentProvider
{
	/// <summary>Cap on rows read per table — the local enrichment view does not need the full
	/// history, and a guard keeps the page snappy on hosts with very large fact stores.</summary>
	public const int MaxRowsPerTable = 50_000;

	/// <summary>Try to enrich <paramref name="sessions"/> from the local SQLite DB. Sessions are
	/// modified in place when facts are available; failures populate the returned report's
	/// <see cref="LocalSessionEnrichmentReport.Status"/> with an operator-facing reason.</summary>
	public async Task<LocalSessionEnrichmentReport> EnrichAsync(
		IList<RdpSessionDto> sessions,
		CancellationToken ct = default)
	{
		ArgumentNullException.ThrowIfNull(sessions);

		string dbPath = ReadOnlyDb.DatabasePath;
		if (!File.Exists(dbPath))
		{
			return LocalSessionEnrichmentReport.Unavailable("RdpAudit DB not found at " + dbPath);
		}

		try
		{
			await using AuditDbContextOpen handle = await AuditDbContextOpen.OpenAsync(ct).ConfigureAwait(false);

			List<SessionIpCorrelation> correlations = await handle.Db.SessionIpCorrelations
				.AsNoTracking()
				.OrderByDescending(c => c.LastSeenUtc)
				.Take(MaxRowsPerTable)
				.ToListAsync(ct)
				.ConfigureAwait(false);

			List<RdpConnectionFact> facts = await handle.Db.RdpConnectionFacts
				.AsNoTracking()
				.OrderByDescending(f => f.LastSeenUtc)
				.Take(MaxRowsPerTable)
				.ToListAsync(ct)
				.ConfigureAwait(false);

			LocalSessionEnrichmentResult result = LocalSessionEnricher.Enrich(sessions, correlations, facts);

			if (correlations.Count == 0 && facts.Count == 0)
			{
				return LocalSessionEnrichmentReport.AppliedFrom(
					result,
					"local DB read OK; no correlation / fact rows present yet");
			}

			return LocalSessionEnrichmentReport.AppliedFrom(
				result,
				string.Format(System.Globalization.CultureInfo.InvariantCulture,
					"local DB facts applied to {0}/{1} active RDP rows (correlations={2}, facts={3})",
					result.HistoricalApplied,
					result.CandidateRdpSessions,
					correlations.Count,
					facts.Count));
		}
		catch (Exception ex)
		{
			return LocalSessionEnrichmentReport.Unavailable(
				"local DB read failed: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	/// <summary>Disposable wrapper around the read-only DB context so EnrichAsync can use
	/// <c>await using</c> for deterministic disposal.</summary>
	private sealed class AuditDbContextOpen : IAsyncDisposable
	{
		public Data.AuditDbContextWrapper Db { get; }

		private AuditDbContextOpen(Data.AuditDbContextWrapper db)
		{
			Db = db;
		}

		public static Task<AuditDbContextOpen> OpenAsync(CancellationToken ct)
		{
			ct.ThrowIfCancellationRequested();
			Data.AuditDbContextWrapper wrapper = new(ReadOnlyDb.Open());
			return Task.FromResult(new AuditDbContextOpen(wrapper));
		}

		public ValueTask DisposeAsync()
		{
			Db.Dispose();
			return ValueTask.CompletedTask;
		}
	}

	private static class Data
	{
		/// <summary>Thin wrapper that exposes the AuditDbContext sets we need without spilling
		/// the EF type across module boundaries.</summary>
		internal sealed class AuditDbContextWrapper : IDisposable
		{
			private readonly RdpAudit.Core.Data.AuditDbContext _ctx;
			public AuditDbContextWrapper(RdpAudit.Core.Data.AuditDbContext ctx)
			{
				_ctx = ctx;
			}

			public IQueryable<SessionIpCorrelation> SessionIpCorrelations => _ctx.SessionIpCorrelations;
			public IQueryable<RdpConnectionFact> RdpConnectionFacts => _ctx.RdpConnectionFacts;

			public void Dispose() => _ctx.Dispose();
		}
	}
}
