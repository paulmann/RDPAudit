/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : SimpleOptionsMonitor.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: A fixed IOptionsMonitor for the product options the real product services read. The runner
//          builds one immutable RdpAuditOptions and hands it to the real retention engine, the real
//          backup service and the real compaction service, so the benchmark exercises product code with
//          a configuration it constructed deliberately - instead of standing up a host and a
//          configuration file for a measurement.
// Depends: Microsoft.Extensions.Options
// Extends: System.Object

using Microsoft.Extensions.Options;

namespace RdpAudit.StorageBenchmarks;

/// <summary>An <see cref="IOptionsMonitor{TOptions}"/> over one immutable value that never changes.</summary>
/// <typeparam name="TOptions">The options type the product services consume.</typeparam>
internal sealed class SimpleOptionsMonitor<TOptions> : IOptionsMonitor<TOptions>
{
	private readonly TOptions _value;

	/// <summary>Creates the monitor over <paramref name="value"/>, which it returns for every name.</summary>
	public SimpleOptionsMonitor(TOptions value)
	{
		ArgumentNullException.ThrowIfNull(value);
		_value = value;
	}

	/// <inheritdoc />
	public TOptions CurrentValue => _value;

	/// <inheritdoc />
	public TOptions Get(string? name) => _value;

	/// <summary>Always null: a fixed value never changes, so there is no change to observe.</summary>
	public IDisposable? OnChange(Action<TOptions, string?> listener) => null;
}
