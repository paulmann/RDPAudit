/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : RestApiLogForwarder.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Forwards log events of the inner REST API WebApplication to the service's logger
//          factory, keeping the Kestrel/route diagnostics on the service's existing Serilog
//          pipeline instead of the inner builder's own providers.
// Depends: Microsoft.Extensions.Logging
// Extends: none.

using Microsoft.Extensions.Logging;

namespace RdpAudit.Service.RestApi;

/// <summary>Forwards inner REST API logs to the service logger factory.</summary>
public sealed class RestApiLogForwarder : ILoggerProvider
{
	private readonly ILoggerFactory _target;

	public RestApiLogForwarder(ILoggerFactory target)
	{
		_target = target ?? throw new ArgumentNullException(nameof(target));
	}

	public ILogger CreateLogger(string categoryName)
		=> _target.CreateLogger(categoryName);

	public void Dispose()
	{
		// Owns nothing; the target factory belongs to the service host.
	}
}
