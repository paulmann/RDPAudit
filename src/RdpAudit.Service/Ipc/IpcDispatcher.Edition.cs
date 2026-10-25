/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : IpcDispatcher.Edition.cs
// Project: RdpAudit.Service (RdpAudit.Service.Ipc)
// Purpose: IPC handler of the GetEditionInfo command (ordinal 102). Answers from compile-time constants
//          only, so the Configurator can prove which binary it is talking to even when every other
//          subsystem is degraded (no database, no network, no provider).
// Extends: IpcDispatcher (partial)

using RdpAudit.Core.Editions;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Service.Ipc;

/// <summary>Edition handlers of the dispatcher (command 102).</summary>
public sealed partial class IpcDispatcher
{
	/// <summary>Builds the edition report for the running service binary.</summary>
	/// <remarks>Internal so the test project can assert the payload without standing up a host.</remarks>
	internal static EditionInfoDto GetEditionInfoHandler()
	{
		EditionInfoDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Edition = EditionContext.DisplayName,
			EditionOrdinal = (int)EditionContext.Current,
			ProductVersion = EditionContext.ProductVersion,
			License = EditionContext.LicenseName,
			MaxCrossHostHosts = EditionContext.MaxCrossHostHosts,
			BuildConstant = EditionContext.BuildConstantName,
		};

		foreach (EditionFeature feature in EditionMatrix.Features)
		{
			dto.Features.Add(new EditionFeatureDto
			{
				Feature = feature.ToString(),
				MinimumEdition = EditionMatrix.DisplayName(EditionMatrix.MinimumFor(feature)),
				Available = EditionContext.Allows(feature),
			});
		}

		dto.Message = string.Format(
			System.Globalization.CultureInfo.InvariantCulture,
			"{0} edition {1} ({2}); {3} of {4} gated capabilities enabled; cross-host budget {5} host(s).",
			dto.Edition,
			dto.ProductVersion,
			dto.BuildConstant,
			dto.Features.FindAll(f => f.Available).Count,
			dto.Features.Count,
			dto.MaxCrossHostHosts);

		return dto;
	}
}
