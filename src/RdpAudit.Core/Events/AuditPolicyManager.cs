// File:    src/RdpAudit.Core/Events/AuditPolicyManager.cs
// Module:  RdpAudit.Core.Events
// Purpose: Provides the canonical list of auditpol subcategories required by RdpAudit and
//          executes auditpol.exe / SACL configuration when running on Windows with elevation.
//          Uses GUID subcategory identifiers for non-English Windows compatibility.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RdpAudit.Core.Interop;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Events;

/// <summary>Audit policy row required by RdpAudit, with current and required state.</summary>
public sealed record AuditPolicyRow(string Category, string Subcategory, string SubcategoryGuid, bool Success, bool Failure);

/// <summary>Outcome of a single audit-policy apply step.</summary>
public sealed record AuditPolicyApplyResult(string Subcategory, string SubcategoryGuid, int ExitCode, string? Error);

/// <summary>Provides the canonical list of auditpol subcategories required by RdpAudit and
/// executes auditpol.exe / SACL configuration when running on Windows with elevation.
/// Subcategory GUIDs are stable across Windows locales — English names are not.</summary>
public sealed class AuditPolicyManager
{
	// Well-known audit subcategory GUIDs (locale-invariant) — see Microsoft Audit Policy reference.
	public const string GuidLogon = "{0CCE9215-69AE-11D9-BED3-505054503030}";
	public const string GuidLogoff = "{0CCE9216-69AE-11D9-BED3-505054503030}";
	public const string GuidSpecialLogon = "{0CCE921B-69AE-11D9-BED3-505054503030}";
	public const string GuidOtherLogonLogoff = "{0CCE921C-69AE-11D9-BED3-505054503030}";
	public const string GuidCredentialValidation = "{0CCE923F-69AE-11D9-BED3-505054503030}";
	public const string GuidKerberosAuthService = "{0CCE9242-69AE-11D9-BED3-505054503030}";
	public const string GuidKerberosServiceTicket = "{0CCE9240-69AE-11D9-BED3-505054503030}";
	public const string GuidProcessCreation = "{0CCE922B-69AE-11D9-BED3-505054503030}";
	public const string GuidProcessTermination = "{0CCE922C-69AE-11D9-BED3-505054503030}";
	public const string GuidAuditPolicyChange = "{0CCE922F-69AE-11D9-BED3-505054503030}";
	public const string GuidFileSystem = "{0CCE921D-69AE-11D9-BED3-505054503030}";
	public const string GuidRegistry = "{0CCE921E-69AE-11D9-BED3-505054503030}";
	public const string GuidUserAccountManagement = "{0CCE9235-69AE-11D9-BED3-505054503030}";
	public const string GuidSecurityGroupManagement = "{0CCE9237-69AE-11D9-BED3-505054503030}";
	public const string GuidSecuritySystemExtension = "{0CCE9211-69AE-11D9-BED3-505054503030}";

	public static IReadOnlyList<AuditPolicyRow> RequiredRows { get; } = new List<AuditPolicyRow>
	{
		new("Logon/Logoff", "Logon", GuidLogon, true, true),
		new("Logon/Logoff", "Logoff", GuidLogoff, true, false),
		new("Logon/Logoff", "Special Logon", GuidSpecialLogon, true, false),
		new("Logon/Logoff", "Other Logon/Logoff Events", GuidOtherLogonLogoff, true, true),
		new("Account Logon", "Credential Validation", GuidCredentialValidation, true, true),
		new("Account Logon", "Kerberos Authentication Service", GuidKerberosAuthService, true, true),
		new("Account Logon", "Kerberos Service Ticket Operations", GuidKerberosServiceTicket, true, true),
		new("Detailed Tracking", "Process Creation", GuidProcessCreation, true, false),
		new("Detailed Tracking", "Process Termination", GuidProcessTermination, true, false),
		new("Policy Change", "Audit Policy Change", GuidAuditPolicyChange, true, true),
		new("Object Access", "File System", GuidFileSystem, true, true),
		new("Object Access", "Registry", GuidRegistry, true, true),
		new("Account Management", "User Account Management", GuidUserAccountManagement, true, true),
		new("Account Management", "Security Group Management", GuidSecurityGroupManagement, true, true),
		new("System", "Security System Extension", GuidSecuritySystemExtension, true, true),
	};

	/// <summary>Applies the required audit policy on Windows. No-op on non-Windows hosts.</summary>
	[SupportedOSPlatform("windows")]
	public IReadOnlyList<AuditPolicyApplyResult> ApplyAll()
	{
		List<AuditPolicyApplyResult> results = new(RequiredRows.Count);
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return results;
		}

		foreach (AuditPolicyRow row in RequiredRows)
		{
			string args = string.Format(CultureInfo.InvariantCulture,
				"/set /subcategory:{0} /success:{1} /failure:{2}",
				row.SubcategoryGuid,
				row.Success ? "enable" : "disable",
				row.Failure ? "enable" : "disable");
			(int code, string? err) = RunAuditpol(args);
			results.Add(new AuditPolicyApplyResult(row.Subcategory, row.SubcategoryGuid, code, err));
		}

		EnableProcessCmdLine();
		return results;
	}

	/// <summary>Reads the current Success/Failure flags for a subcategory by GUID.
	/// Primary path: AuditQuerySystemPolicy advapi32 API — fully locale-stable.
	/// Fallback path: parse <c>auditpol /r</c> CSV "Inclusion Setting" column
	/// using locale-tolerant heuristics. Returns null on failure.</summary>
	[SupportedOSPlatform("windows")]
	public static AuditPolicyState? ReadSubcategoryState(string guid)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(guid);

		AuditPolicyState? viaApi = ReadViaAuditQuerySystemPolicy(guid);
		if (viaApi is not null)
		{
			return viaApi;
		}

		return ReadViaAuditpolCsv(guid);
	}

	/// <summary>Reads the inclusion bits directly from the Windows audit subsystem.
	/// Locale-stable; requires SE_SECURITY_NAME (granted to Administrators).</summary>
	[SupportedOSPlatform("windows")]
	private static AuditPolicyState? ReadViaAuditQuerySystemPolicy(string guid)
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return null;
		}

		if (!Guid.TryParse(guid, out Guid parsed))
		{
			return null;
		}

		Guid[] ids = { parsed };
		IntPtr buffer = IntPtr.Zero;
		try
		{
			if (!NativeMethods.AuditQuerySystemPolicy(ids, 1, out buffer) || buffer == IntPtr.Zero)
			{
				return null;
			}

			NativeMethods.AUDIT_POLICY_INFORMATION info =
				Marshal.PtrToStructure<NativeMethods.AUDIT_POLICY_INFORMATION>(buffer);

			bool success = (info.AuditingInformation & NativeMethods.POLICY_AUDIT_EVENT_SUCCESS) != 0;
			bool failure = (info.AuditingInformation & NativeMethods.POLICY_AUDIT_EVENT_FAILURE) != 0;
			return new AuditPolicyState(success, failure);
		}
		catch (Exception)
		{
			return null;
		}
		finally
		{
			if (buffer != IntPtr.Zero)
			{
				NativeMethods.AuditFree(buffer);
			}
		}
	}

	/// <summary>Locale-tolerant parser for <c>auditpol /get /subcategory:{guid} /r</c> CSV output.
	/// Expected schema: <c>Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting</c>.
	/// The auditpol invocation is routed through the parse-stable English console
	/// (<c>cmd /d /c "chcp 437 >nul &amp; auditpol.exe /get /subcategory:{GUID} /r"</c>) so the
	/// header text and "Inclusion Setting" values are emitted in Latin-script form whenever the
	/// chcp pin takes effect; the keyword fallback still handles localized output if it doesn't.</summary>
	[SupportedOSPlatform("windows")]
	private static AuditPolicyState? ReadViaAuditpolCsv(string guid)
	{
		try
		{
			EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(
				TrustedEnglishConsoleTool.AuditpolGetSubcategoryCsv,
				new EnglishConsoleArgs { SubcategoryGuid = guid });

			System.Text.Encoding encoding = QwinstaConsoleEncoding.Resolve();
			ProcessStartInfo psi = new(spawn.Executable)
			{
				Arguments = spawn.Arguments,
				UseShellExecute = false,
				CreateNoWindow = true,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				StandardOutputEncoding = encoding,
				StandardErrorEncoding = encoding,
			};
			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return null;
			}

			string stdout = proc.StandardOutput.ReadToEnd();
			proc.WaitForExit(15_000);
			if (proc.ExitCode != 0)
			{
				return null;
			}

			string[] lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

			// Find the header line that names the columns; the GUID column index is stable but locale-named.
			int guidColumn = -1;
			int inclusionColumn = -1;
			int headerIndex = -1;
			for (int i = 0; i < lines.Length; i++)
			{
				string[] cells = SplitCsv(lines[i]);
				for (int c = 0; c < cells.Length; c++)
				{
					string cell = cells[c].Trim();
					if (cell.IndexOf("GUID", StringComparison.OrdinalIgnoreCase) >= 0)
					{
						guidColumn = c;
					}
					else if (cell.IndexOf("Inclusion", StringComparison.OrdinalIgnoreCase) >= 0
						|| cell.IndexOf("включения", StringComparison.OrdinalIgnoreCase) >= 0
						|| cell.IndexOf("Einbezug", StringComparison.OrdinalIgnoreCase) >= 0)
					{
						inclusionColumn = c;
					}
				}

				if (guidColumn >= 0 && inclusionColumn >= 0)
				{
					headerIndex = i;
					break;
				}
			}

			// Default to the canonical column layout if the header could not be parsed by name.
			if (guidColumn < 0 || inclusionColumn < 0)
			{
				guidColumn = 3;
				inclusionColumn = 4;
			}

			for (int i = headerIndex < 0 ? 0 : headerIndex + 1; i < lines.Length; i++)
			{
				string[] cells = SplitCsv(lines[i]);
				if (cells.Length <= Math.Max(guidColumn, inclusionColumn))
				{
					continue;
				}

				string cellGuid = cells[guidColumn].Trim();
				if (cellGuid.Length == 0
					|| !string.Equals(NormalizeGuid(cellGuid), NormalizeGuid(guid), StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				string inclusion = cells[inclusionColumn].Trim();
				return DecodeInclusion(inclusion);
			}

			return null;
		}
		catch (Exception)
		{
			return null;
		}
	}

	/// <summary>Decodes the localized "Inclusion Setting" text into success/failure flags.
	/// Treats the value as a bitfield first (some Windows builds emit numeric inclusion in /r output),
	/// then falls back to locale-tolerant keyword matching covering EN/RU/DE/FR/ES.</summary>
	internal static AuditPolicyState DecodeInclusion(string inclusion)
	{
		if (int.TryParse(inclusion, NumberStyles.Integer, CultureInfo.InvariantCulture, out int bits))
		{
			return new AuditPolicyState((bits & 1) != 0, (bits & 2) != 0);
		}

		string lower = inclusion.ToLowerInvariant();
		bool hasSuccess =
			lower.Contains("success", StringComparison.Ordinal)
			|| lower.Contains("успех", StringComparison.Ordinal)
			|| lower.Contains("erfolg", StringComparison.Ordinal)
			|| lower.Contains("succès", StringComparison.Ordinal)
			|| lower.Contains("éxito", StringComparison.Ordinal)
			|| lower.Contains("correcto", StringComparison.Ordinal);
		bool hasFailure =
			lower.Contains("failure", StringComparison.Ordinal)
			|| lower.Contains("отказ", StringComparison.Ordinal)
			|| lower.Contains("fehl", StringComparison.Ordinal)
			|| lower.Contains("échec", StringComparison.Ordinal)
			|| lower.Contains("fallo", StringComparison.Ordinal)
			|| lower.Contains("error", StringComparison.Ordinal);

		// "No Auditing" and the empty string both reduce to (false, false).
		return new AuditPolicyState(hasSuccess, hasFailure);
	}

	internal static string NormalizeGuid(string value)
	{
		string trimmed = value.Trim();
		return Guid.TryParse(trimmed, out Guid g) ? g.ToString("B", CultureInfo.InvariantCulture).ToUpperInvariant() : trimmed.ToUpperInvariant();
	}

	private static string[] SplitCsv(string line)
	{
		List<string> result = new();
		System.Text.StringBuilder current = new();
		bool inQuotes = false;
		for (int i = 0; i < line.Length; i++)
		{
			char c = line[i];
			if (c == '"')
			{
				inQuotes = !inQuotes;
				continue;
			}

			if (c == ',' && !inQuotes)
			{
				result.Add(current.ToString());
				current.Clear();
				continue;
			}

			current.Append(c);
		}

		result.Add(current.ToString());
		return result.ToArray();
	}

	private static (int Code, string? Error) RunAuditpol(string args)
	{
		try
		{
			ProcessStartInfo psi = new("auditpol.exe", args)
			{
				UseShellExecute = false,
				CreateNoWindow = true,
				RedirectStandardError = true,
				RedirectStandardOutput = true,
			};
			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return (-1, "auditpol.exe could not start");
			}

			string err = proc.StandardError.ReadToEnd();
			proc.WaitForExit(15_000);
			return (proc.ExitCode, proc.ExitCode == 0 ? null : err);
		}
		catch (Exception ex)
		{
			return (-1, ex.Message);
		}
	}

	private static void EnableProcessCmdLine()
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return;
		}

		try
		{
			ProcessStartInfo psi = new(
				"reg.exe",
				"add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" "
				+ "/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f")
			{
				UseShellExecute = false,
				CreateNoWindow = true,
			};
			using Process? proc = Process.Start(psi);
			proc?.WaitForExit(10_000);
		}
		catch
		{
			// Best-effort enable; errors surfaced via auditpol read-back.
		}
	}
}

/// <summary>Decoded auditpol /r inclusion bits for a subcategory.</summary>
public sealed record AuditPolicyState(bool Success, bool Failure);
