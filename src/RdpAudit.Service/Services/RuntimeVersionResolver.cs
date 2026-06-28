// File:    src/RdpAudit.Service/Services/RuntimeVersionResolver.cs
// Module:  RdpAudit.Service.Services
// Purpose: Resolves the runtime service version surfaced via IPC (ServiceStatus.Version) in a
//          way that is safe for single-file published assemblies. Does not call
//          Assembly.Location, which always returns an empty string for assemblies embedded in
//          a single-file app and triggers IL3000 during publish.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Reflection;

namespace RdpAudit.Service.Services;

/// <summary>Single-file-safe runtime version resolver. The order of precedence is:
/// (1) <see cref="AssemblyInformationalVersionAttribute"/> from the supplied assembly — this is
/// the SemVer set via <c>VersionPrefix</c> in <c>Directory.Build.props</c> or by <c>publish.ps1</c>;
/// (2) <see cref="FileVersionInfo"/> read from <see cref="Environment.ProcessPath"/> when that
/// path is set and exists — works for single-file published apps because the process image is
/// always on disk; (3) the assembly's own <see cref="AssemblyName.Version"/>. Never calls
/// <see cref="Assembly.Location"/>, which is empty for single-file embedded assemblies and
/// flagged by IL3000. Side-effect free and never throws.</summary>
internal static class RuntimeVersionResolver
{
	/// <summary>Resolves the runtime version for the supplied assembly using only single-file-safe
	/// reflection and process introspection. Exposed for testing.</summary>
	internal static string Resolve(Assembly assembly, string? processPath)
	{
		ArgumentNullException.ThrowIfNull(assembly);

		string? informational = assembly
			.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		if (!string.IsNullOrWhiteSpace(informational))
		{
			int plus = informational.IndexOf('+', StringComparison.Ordinal);
			return plus > 0 ? informational[..plus] : informational;
		}

		if (!string.IsNullOrWhiteSpace(processPath))
		{
			try
			{
				if (File.Exists(processPath))
				{
					FileVersionInfo info = FileVersionInfo.GetVersionInfo(processPath);
					if (!string.IsNullOrWhiteSpace(info.ProductVersion))
					{
						return info.ProductVersion!;
					}

					if (!string.IsNullOrWhiteSpace(info.FileVersion))
					{
						return info.FileVersion!;
					}
				}
			}
			catch (Exception)
			{
				// fall through to AssemblyName.Version
			}
		}

		return assembly.GetName().Version?.ToString() ?? "0.0.0";
	}

	/// <summary>Resolves the runtime version of the RdpAudit service assembly. Single-file safe.</summary>
	internal static string Resolve()
	{
		return Resolve(typeof(RuntimeVersionResolver).Assembly, Environment.ProcessPath);
	}

	/// <summary>Like <see cref="Resolve()"/> but preserves any SemVer build metadata (the <c>+sha</c>
	/// suffix). Used by the Tools Diag report so the operator can see exactly which commit produced the
	/// running service binary and compare it against the Configurator they launched. Returns the bare
	/// SemVer when no build metadata is present. Side-effect free and never throws.</summary>
	internal static string ResolveFull()
	{
		string? informational = typeof(RuntimeVersionResolver).Assembly
			.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		return string.IsNullOrWhiteSpace(informational) ? Resolve() : informational!;
	}
}
