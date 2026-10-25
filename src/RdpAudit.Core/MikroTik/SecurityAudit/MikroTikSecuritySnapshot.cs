// File:    src/RdpAudit.Core/MikroTik/SecurityAudit/MikroTikSecuritySnapshot.cs
// Module:  RdpAudit.Core.MikroTik.SecurityAudit
// Purpose: The read-only picture of one router the audit works on: per-menu rows exactly as
//          RouterOS returned them (string values), the menus that could not be read with their
//          error text, the menus the device does not have at all, and the pasport fields. Building
//          the snapshot is the Service's job (HTTP); evaluating it is pure and lives in
//          SecurityAuditEvaluator, which is why the rules can be tested without a router.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;

namespace RdpAudit.Core.MikroTik.SecurityAudit;

/// <summary>Read-only RouterOS facts one audit run is evaluated against.</summary>
public sealed class MikroTikSecuritySnapshot
{
	private readonly Dictionary<string, List<IReadOnlyDictionary<string, string>>> _sections = new(StringComparer.Ordinal);
	private readonly Dictionary<string, string> _errors = new(StringComparer.Ordinal);
	private readonly HashSet<string> _unavailable = new(StringComparer.Ordinal);

	/// <summary>True when the device answered the read at all (the pasport fields are filled).</summary>
	public bool Reachable { get; private init; }

	public string DeviceName { get; private init; } = string.Empty;

	public string RouterOsVersion { get; private init; } = string.Empty;

	public string BoardName { get; private init; } = string.Empty;

	public string Uptime { get; private init; } = string.Empty;

	public DateTime CapturedUtc { get; private init; } = DateTime.UtcNow;

	/// <summary>Menus that answered with a parseable body, plus the ones that answered empty.</summary>
	public IReadOnlyDictionary<string, List<IReadOnlyDictionary<string, string>>> Sections => _sections;

	/// <summary>Menus that exist but could not be read: section key to error text. Each becomes S-00.</summary>
	public IReadOnlyDictionary<string, string> Errors => _errors;

	/// <summary>Menus the device does not have (package absent). Reported, never treated as compliant.</summary>
	public IReadOnlyCollection<string> UnavailableMenus => _unavailable;

	/// <summary>Rows of one menu; an unknown or empty menu yields an empty list, never null.</summary>
	public IReadOnlyList<IReadOnlyDictionary<string, string>> Rows(string key)
		=> _sections.TryGetValue(key, out List<IReadOnlyDictionary<string, string>>? rows) ? rows : [];

	/// <summary>First row of one menu, or an empty dictionary when the menu has no rows.</summary>
	public IReadOnlyDictionary<string, string> Single(string key)
	{
		IReadOnlyList<IReadOnlyDictionary<string, string>> rows = Rows(key);
		return rows.Count == 0 ? EmptyRow : rows[0];
	}

	private static readonly Dictionary<string, string> EmptyRow = new(StringComparer.Ordinal);

	/// <summary>True when the menu answered (even with zero rows).</summary>
	public bool Has(string key) => _sections.ContainsKey(key);

	/// <summary>True when the menu exists but the read failed — the rules over it must stay silent and S-00 must speak.</summary>
	public bool Failed(string key) => _errors.ContainsKey(key);

	/// <summary>True when the device does not implement the menu at all.</summary>
	public bool Missing(string key) => _unavailable.Contains(key);

	/// <summary>Adds (or replaces) the rows of one menu.</summary>
	public void AddRows(string key, List<IReadOnlyDictionary<string, string>> rows)
	{
		ArgumentNullException.ThrowIfNull(rows);
		_sections[key] = rows;
	}

	/// <summary>Records a menu that exists but could not be read.</summary>
	public void AddError(string key, string error)
	{
		_errors[key] = string.IsNullOrWhiteSpace(error) ? "unreadable" : error;
	}

	/// <summary>Records a menu the device does not have (package absent).</summary>
	public void AddUnavailable(string key) => _unavailable.Add(key);

	/// <summary>
	/// RouterOS 7 serialises booleans as true/false over REST and as yes/no in the console; comparing
	/// against one literal silently misses half the findings (measured on 7.23.1: /ip/service returns
	/// disabled=false, /ip/dns returns allow-remote-requests=true).
	/// </summary>
	public static bool Truthy(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}

		string text = value.Trim();
		return string.Equals(text, "yes", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(text, "true", StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>True when a row is present and not disabled.</summary>
	public static bool Enabled(IReadOnlyDictionary<string, string>? row)
		=> row is not null && row.Count > 0 && !Truthy(Field(row, "disabled"));

	/// <summary>Reads one field of a row, returning an empty string when absent.</summary>
	public static string Field(IReadOnlyDictionary<string, string> row, string name)
		=> row.TryGetValue(name, out string? value) ? value ?? string.Empty : string.Empty;

	/// <summary>Creates the pasport part of a snapshot; rows are added afterwards by the reader.</summary>
	public static MikroTikSecuritySnapshot CreatePasport(
		bool reachable,
		string deviceName,
		string routerOsVersion,
		string boardName,
		string uptime,
		DateTime capturedUtc) => new()
		{
			Reachable = reachable,
			DeviceName = deviceName ?? string.Empty,
			RouterOsVersion = routerOsVersion ?? string.Empty,
			BoardName = boardName ?? string.Empty,
			Uptime = uptime ?? string.Empty,
			CapturedUtc = capturedUtc,
		};

	/// <summary>An empty snapshot: nothing read, everything failed. Used when the router is unreachable.</summary>
	public static MikroTikSecuritySnapshot Empty(DateTime capturedUtc) => CreatePasport(
		reachable: false,
		deviceName: string.Empty,
		routerOsVersion: string.Empty,
		boardName: string.Empty,
		uptime: string.Empty,
		capturedUtc: capturedUtc);
}
