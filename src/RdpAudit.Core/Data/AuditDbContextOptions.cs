// File:    src/RdpAudit.Core/Data/AuditDbContextOptions.cs
// Module:  RdpAudit.Core.Data
// Purpose: Single source of truth for the EF Core warning policy applied to every
//          production / read-only AuditDbContext. RowLimitingOperationWithoutOrderByWarning
//          is escalated to a compile-at-query-time error: any Skip/Take that runs without a
//          deterministic prior ORDER BY (or whose order chain is destroyed by a later
//          Distinct) aborts the query instead of emitting an unstable page that changes
//          between runs and corrupts pagination. Every call site that paginates therefore
//          carries an explicit total order (timestamp + stable key tie-break).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace RdpAudit.Core.Data;

/// <summary>Centrally configured EF Core warning policy for the RdpAudit database context.</summary>
public static class AuditDbContextOptions
{
	/// <summary>Applies the query-quality warning policy to the supplied options builder.
	/// Configures EF Core to throw on <see cref="CoreEventId.RowLimitingOperationWithoutOrderByWarning"/>
	/// so an unpaged / non-deterministically paged query can never reach a production database.</summary>
	public static void ApplyWarningPolicy(DbContextOptionsBuilder optionsBuilder)
	{
		ArgumentNullException.ThrowIfNull(optionsBuilder);
		optionsBuilder.ConfigureWarnings(warnings => warnings.Throw(CoreEventId.RowLimitingOperationWithoutOrderByWarning));
	}
}
