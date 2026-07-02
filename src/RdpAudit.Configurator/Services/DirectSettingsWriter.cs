// File:    src/RdpAudit.Configurator/Services/DirectSettingsWriter.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Fallback path for persisting a single scalar setting (currently: Diagnostics.DebugMode)
//          straight to appsettings.json on disk when the service's named-pipe IPC is unreachable.
//          SettingsPage's normal save path (SaveViaIpcAsync -> IpcCommand.SaveSettings) requires a
//          live service round-trip; when the pipe cannot be connected the save silently no-ops and
//          the Settings tab checkbox drifts out of sync with what is actually on disk -- the exact
//          symptom that left DebugMode=false on disk while the UI showed the box checked, so
//          RDPAudit_DEBUG_Log.txt / ipc-startup.log were never produced for a live troubleshooting
//          session. This writer performs the same atomic write pattern as
//          RdpAudit.Service.Services.SettingsManager.Save (write .tmp, File.Replace/Move) but is
//          intentionally scoped to a single boolean field: it must never touch secret fields
//          (ApiKey / Password), which SettingsManager alone knows how to protect via
//          ISecretProtector -- writing the whole document from the Configurator process would risk
//          persisting a plaintext secret if the operator had one open unmasked in the editor.
//          IConfiguration's reloadOnChange (registered in Program.cs) picks up the on-disk change on
//          its own the moment the service becomes reachable again, without requiring a restart.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json.Nodes;
using RdpAudit.Core.Config;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Fallback writer that persists Diagnostics.DebugMode directly to appsettings.json when
/// the service IPC pipe cannot be reached, so the Settings tab checkbox never silently drifts out
/// of sync with the on-disk value.</summary>
public static class DirectSettingsWriter
{
	/// <summary>Sets RdpAudit:Diagnostics:DebugMode in the appsettings.json at <paramref
	/// name="appSettingsPath"/> and writes it back atomically. Leaves every other field byte-for-byte
	/// untouched -- in particular, secret fields are never re-serialized through this path, so a
	/// protected envelope already on disk is preserved exactly as-is. Returns false (without
	/// throwing) when the file is missing, unreadable, or the write fails for any reason; callers
	/// should fall back to instructing the operator to retry once the service is reachable.</summary>
	public static bool TrySetDebugMode(string appSettingsPath, bool enabled, out string? error)
	{
		error = null;
		try
		{
			if (!File.Exists(appSettingsPath))
			{
				error = "appsettings.json not found at " + appSettingsPath + ".";
				return false;
			}

			string body;
			using (FileStream readStream = new(appSettingsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
			using (StreamReader reader = new(readStream))
			{
				body = reader.ReadToEnd();
			}

			JsonNode? root = JsonNode.Parse(body);
			if (root is null)
			{
				error = "appsettings.json parsed as null.";
				return false;
			}

			JsonNode? section = root[RdpAuditOptions.SectionName];
			if (section is null)
			{
				error = "appsettings.json missing required 'RdpAudit' section.";
				return false;
			}

			if (section["Diagnostics"] is not JsonObject diagnostics)
			{
				diagnostics = new JsonObject();
				section["Diagnostics"] = diagnostics;
			}

			diagnostics["DebugMode"] = enabled;

			string newBody = root.ToJsonString(JsonOptions.Indented);
			AtomicReplace(appSettingsPath, newBody);
			return true;
		}
		catch (Exception ex)
		{
			error = ex.GetType().Name + ": " + ex.Message;
			return false;
		}
	}

	/// <summary>Same write-tmp/replace pattern as SettingsManager.Save, scoped to a plain file write
	/// with no locking primitive needed here since the Configurator is a single-instance UI process
	/// (unlike the service, which serializes concurrent IPC saves behind its own gate).</summary>
	private static void AtomicReplace(string path, string body)
	{
		string tmp = path + ".tmp";
		string backup = path + ".bak";

		File.WriteAllText(tmp, body);
		if (File.Exists(path))
		{
			File.Replace(tmp, path, backup, ignoreMetadataErrors: true);
			try
			{
				File.Delete(backup);
			}
			catch (IOException)
			{
				// Best effort -- a leftover .bak file is harmless.
			}
		}
		else
		{
			File.Move(tmp, path);
		}
	}
}
