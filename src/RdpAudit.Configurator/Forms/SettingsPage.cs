// File:    src/RdpAudit.Configurator/Forms/SettingsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Editable view of the appsettings.json RdpAuditOptions block. Surfaces the global DEBUG
//          mode as a first-class persisted toggle (with a destructive-actions warning and a status
//          indicator), a category TreeView that navigates AND inline-edits the configuration sections,
//          and an advanced raw-JSON editor for full-document edits. Uses IPC SaveSettings to persist;
//          the service-side handler validates the document and writes atomically, then hot-reloads it.
// Extends: System.Windows.Forms.TabPage. To make a new scalar editable, no change is needed — every
//          JsonValue leaf is editable automatically. To support editing a new node KIND (e.g. inline
//          array editing), extend LeafRef / BeginInlineEdit / CommitInlineEdit and ParseScalar below.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.3

using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Util;

using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Editable view of the appsettings.json RdpAuditOptions block.</summary>
[SupportedOSPlatform("windows")]
public sealed class SettingsPage : TabPage
{
	private const string DebugWarningText =
		"DEBUG mode enables advanced diagnostics and destructive maintenance actions.";

	private readonly IpcClient _ipc;
	private readonly TextBox _editor;
	private readonly TreeView _tree;
	private readonly Button _load;
	private readonly Button _save;
	private readonly Button _restoreDefaults;
	private readonly CheckBox _debugToggle;
	private readonly Label _debugStatus;
	private readonly Label _debugWarning;
	private readonly Label _status;

	// Inline value editor: a borderless TextBox floated over the selected leaf node while editing.
	private readonly TextBox _inlineEditor;
	private TreeNode? _editingNode;

	private bool _dirty;
	private bool _suppressEditorEvents;
	private bool _committingInlineEdit;

	/// <summary>Identifies a scalar leaf within the configuration tree so an inline edit can be written
	/// back to the correct JSON node. <see cref="Category"/> is the section name (e.g. "Firewall"),
	/// <see cref="Key"/> is the scalar property name within that section.</summary>
	private sealed record LeafRef(string Category, string Key);

	public SettingsPage(IpcClient ipc)
	{
		_ipc = ipc;

		// --- Global DEBUG section (top) ----------------------------------------------------------
		Panel debugPanel = new() { Dock = DockStyle.Top, Height = 78, Padding = new Padding(6) };
		_debugToggle = new CheckBox
		{
			Text = "Enable global DEBUG mode",
			AutoSize = true,
			Location = new Point(8, 6),
		};
		_debugToggle.CheckedChanged += (_, _) => OnDebugToggleChanged();
		_debugStatus = new Label
		{
			AutoSize = true,
			Location = new Point(220, 8),
			Font = new Font(FontFamily.GenericSansSerif, 9, FontStyle.Bold),
		};
		_debugWarning = new Label
		{
			Text = "⚠ " + DebugWarningText,
			AutoSize = true,
			ForeColor = StatusWarning,
			Location = new Point(8, 30),
		};
		debugPanel.Controls.Add(_debugToggle);
		debugPanel.Controls.Add(_debugStatus);
		debugPanel.Controls.Add(_debugWarning);

		// --- Action buttons ----------------------------------------------------------------------
		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 36 };
		_load = new Button { Text = "Reload", Width = 110 };
		_save = new Button { Text = "Save (via IPC)", Width = 130 };
		_restoreDefaults = new Button { Text = "Restore defaults", Width = 150 };
		_load.Click += async (_, _) => await ReloadAsync().ConfigureAwait(true);
		_save.Click += async (_, _) => await SaveViaIpcAsync().ConfigureAwait(true);
		_restoreDefaults.Click += (_, _) => RestoreDefaults();
		buttons.Controls.AddRange(new Control[] { _load, _save, _restoreDefaults });

		_status = new Label { Dock = DockStyle.Top, Height = 24, Text = "Ready" };

		// --- Category tree + raw JSON editor (split) ---------------------------------------------
		_tree = new TreeView { Dock = DockStyle.Fill, HideSelection = false };
		_tree.AfterSelect += (_, e) => OnTreeSelect(e?.Node);
		_tree.NodeMouseDoubleClick += (_, e) => BeginInlineEdit(e?.Node);
		_tree.KeyDown += OnTreeKeyDown;
		_tree.BeforeCollapse += (_, e) =>
		{
			// Collapsing while editing would orphan the floating editor over a hidden node.
			if (_editingNode is not null)
			{
				e.Cancel = true;
			}
		};

		// Borderless overlay used for in-place editing of scalar leaf values.
		_inlineEditor = new TextBox
		{
			Visible = false,
			BorderStyle = BorderStyle.FixedSingle,
			Font = new Font(FontFamily.GenericMonospace, 9),
		};
		_inlineEditor.KeyDown += OnInlineEditorKeyDown;
		_inlineEditor.LostFocus += (_, _) => CommitInlineEdit(apply: true);
		_tree.Controls.Add(_inlineEditor);

		_editor = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ScrollBars = ScrollBars.Both,
			WordWrap = false,
			Font = new Font(FontFamily.GenericMonospace, 10),
		};
		_editor.TextChanged += (_, _) =>
		{
			if (_suppressEditorEvents)
			{
				return;
			}

			_dirty = true;
			UpdateStatus("Modified — unsaved changes.");
		};

		SplitContainer split = new()
		{
			Dock = DockStyle.Fill,
			Orientation = Orientation.Vertical,
			SplitterDistance = 280,
		};
		split.Panel1.Controls.Add(_tree);
		split.Panel1.Controls.Add(new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "Categories — double-click a value to edit (raw JSON on the right)",
			Font = new Font(FontFamily.GenericSansSerif, 8, FontStyle.Italic),
		});
		split.Panel2.Controls.Add(_editor);

		Controls.Add(split);
		Controls.Add(_status);
		Controls.Add(buttons);
		Controls.Add(debugPanel);

		HandleCreated += async (_, _) => await ReloadAsync().ConfigureAwait(true);
	}

	private async Task ReloadAsync()
	{
		_load.Enabled = false;
		UpdateStatus("Loading...");
		try
		{
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			if (settings is null)
			{
				SetEditorText(DefaultTemplate);
				UpdateStatus("Service unreachable — showing default template.");
				return;
			}

			JsonObject wrapped = new()
			{
				[Core.Config.RdpAuditOptions.SectionName] = settings.DeepClone(),
			};
			SetEditorText(wrapped.ToJsonString(JsonOptions.Indented));
			_dirty = false;
			UpdateStatus("Settings loaded over IPC.");
		}
		finally
		{
			_load.Enabled = true;
		}
	}

	private void RestoreDefaults()
	{
		SetEditorText(DefaultTemplate);
		_dirty = true;
		UpdateStatus("Default template loaded — review and Save to apply.");
	}

	private async Task SaveViaIpcAsync()
	{
		_save.Enabled = false;
		UpdateStatus("Saving...");
		try
		{
			using JsonDocument _ = JsonDocument.Parse(_editor.Text);
		}
		catch (JsonException ex)
		{
			UpdateStatus("Invalid JSON");
			MessageBox.Show("Invalid JSON: " + ex.Message, "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Error);
			_save.Enabled = true;
			return;
		}

		try
		{
			object? response = await _ipc.SendAsync<object>(IpcCommand.SaveSettings, _editor.Text).ConfigureAwait(true);
			if (response is null)
			{
				UpdateStatus("Service unreachable. Settings NOT saved.");
			}
			else
			{
				_dirty = false;
				UpdateStatus("Saved. Service will hot-reload from disk.");
			}
		}
		catch (Exception ex)
		{
			UpdateStatus("Save failed: " + ex.GetType().Name);
		}
		finally
		{
			_save.Enabled = true;
		}
	}

	/// <summary>Re-reads the editor JSON, rebuilds the category tree, and refreshes the DEBUG toggle /
	/// status indicator from the parsed document. Tolerant of in-progress invalid JSON.</summary>
	private void RefreshFromEditor()
	{
		JsonObject? root = TryParseRoot();
		RebuildTree(root);
		RefreshDebugIndicator(root);
	}

	private JsonObject? TryParseRoot()
	{
		try
		{
			JsonNode? parsed = JsonNode.Parse(_editor.Text);
			if (parsed is JsonObject obj && obj[Core.Config.RdpAuditOptions.SectionName] is JsonObject section)
			{
				return section;
			}

			return parsed as JsonObject;
		}
		catch (JsonException)
		{
			return null;
		}
	}

	private void RebuildTree(JsonObject? section)
	{
		_tree.BeginUpdate();
		try
		{
			_tree.Nodes.Clear();
			if (section is null)
			{
				_tree.Nodes.Add("(invalid JSON — fix the raw document on the right)");
				return;
			}

			TreeNode rootNode = new("RdpAudit");
			foreach (KeyValuePair<string, JsonNode?> category in section)
			{
				TreeNode catNode = new(category.Key);
				if (category.Value is JsonObject catObj)
				{
					foreach (KeyValuePair<string, JsonNode?> leaf in catObj)
					{
						string value = leaf.Value switch
						{
							JsonObject => "{…}",
							JsonArray arr => string.Format(CultureInfo.InvariantCulture, "[{0}]", arr.Count),
							null => "null",
							_ => leaf.Value.ToJsonString(),
						};
						TreeNode leafNode = catNode.Nodes.Add(
							string.Format(CultureInfo.InvariantCulture, "{0} = {1}", leaf.Key, value));

						// Only scalar values (JsonValue) are inline-editable; objects / arrays / null are left
						// without a Tag so BeginInlineEdit refuses to open the overlay over them.
						if (leaf.Value is JsonValue)
						{
							leafNode.Tag = new LeafRef(category.Key, leaf.Key);
						}
					}
				}

				rootNode.Nodes.Add(catNode);
			}

			_tree.Nodes.Add(rootNode);
			rootNode.Expand();
		}
		finally
		{
			_tree.EndUpdate();
		}
	}

	private void OnTreeSelect(TreeNode? node)
	{
		if (node is null)
		{
			return;
		}

		// Scroll the raw editor to the first occurrence of the selected category / key so the typed
		// view and the raw document stay in sync without a second editing surface to keep coherent.
		string token = node.Text.Split(' ')[0];
		int idx = _editor.Text.IndexOf("\"" + token + "\"", StringComparison.Ordinal);
		if (idx >= 0)
		{
			_editor.Select(idx, token.Length + 2);
			_editor.ScrollToCaret();
		}
	}

	private void OnTreeKeyDown(object? sender, KeyEventArgs e)
	{
		// F2 / Enter on a scalar leaf opens the inline editor, matching common tree-edit conventions.
		if (e.KeyCode is Keys.F2 or Keys.Enter && _editingNode is null)
		{
			BeginInlineEdit(_tree.SelectedNode);
			e.Handled = true;
			e.SuppressKeyPress = true;
		}
	}

	private void OnInlineEditorKeyDown(object? sender, KeyEventArgs e)
	{
		if (e.KeyCode == Keys.Enter)
		{
			CommitInlineEdit(apply: true);
			e.Handled = true;
			e.SuppressKeyPress = true;
		}
		else if (e.KeyCode == Keys.Escape)
		{
			CommitInlineEdit(apply: false);
			e.Handled = true;
			e.SuppressKeyPress = true;
		}
	}

	/// <summary>Opens the borderless overlay editor over a scalar leaf node, pre-filled with the current
	/// JSON value. No-op for category nodes, object/array/null leaves, or while another edit is active.</summary>
	private void BeginInlineEdit(TreeNode? node)
	{
		if (node?.Tag is not LeafRef leaf || _editingNode is not null)
		{
			return;
		}

		JsonObject? section = TryParseRoot();
		if (section is null)
		{
			UpdateStatus("Cannot edit: fix the raw JSON first.");
			return;
		}

		if (section[leaf.Category] is not JsonObject categoryObj || categoryObj[leaf.Key] is not JsonValue current)
		{
			UpdateStatus("Value is no longer a simple scalar — edit it in the raw JSON pane.");
			return;
		}

		_editingNode = node;

		// Position the overlay over the node's text bounds; raw JSON literal as the editable seed.
		Rectangle bounds = node.Bounds;
		_inlineEditor.Bounds = new Rectangle(
			bounds.X,
			bounds.Y,
			Math.Max(bounds.Width + 80, 140),
			_inlineEditor.PreferredHeight);
		_inlineEditor.Text = current.ToJsonString().Trim('"');
		_inlineEditor.Visible = true;
		_inlineEditor.BringToFront();
		_inlineEditor.Focus();
		_inlineEditor.SelectAll();
		UpdateStatus(string.Format(CultureInfo.InvariantCulture,
			"Editing {0}.{1} — Enter to commit, Esc to cancel.", leaf.Category, leaf.Key));
	}

	/// <summary>Closes the inline overlay. When <paramref name="apply"/> is true the typed text is parsed
	/// (bool / integer / floating-point / string, preserving the original JSON kind where possible) and
	/// written back into the configuration section, the raw editor is regenerated, and the tree rebuilt.</summary>
	private void CommitInlineEdit(bool apply)
	{
		if (_editingNode is null || _committingInlineEdit)
		{
			return;
		}

		_committingInlineEdit = true;
		try
		{
			TreeNode node = _editingNode;
			string typed = _inlineEditor.Text;

			_inlineEditor.Visible = false;
			_editingNode = null;

			if (!apply || node.Tag is not LeafRef leaf)
			{
				if (!apply)
				{
					UpdateStatus("Edit cancelled.");
				}

				return;
			}

			JsonObject? section = TryParseRoot();
			if (section is null || section[leaf.Category] is not JsonObject categoryObj
				|| categoryObj[leaf.Key] is not JsonValue currentValue)
			{
				UpdateStatus("Cannot apply edit: the underlying JSON changed. Use the raw pane.");
				return;
			}

			JsonValue parsed = ParseScalar(typed, currentValue);
			categoryObj[leaf.Key] = parsed;

			JsonObject wrapped = new()
			{
				[Core.Config.RdpAuditOptions.SectionName] = section.DeepClone(),
			};
			SetEditorText(wrapped.ToJsonString(JsonOptions.Indented));
			_dirty = true;
			UpdateStatus(string.Format(CultureInfo.InvariantCulture,
				"{0}.{1} updated — Save to apply.", leaf.Category, leaf.Key));
		}
		finally
		{
			_committingInlineEdit = false;
		}
	}

	/// <summary>Parses inline-editor text into a JSON scalar, preferring the kind of the original value:
	/// a boolean stays boolean, an integer stays integral, a number stays numeric; anything else (or a
	/// failed numeric parse for a previously numeric field) falls back to a JSON string.</summary>
	private static JsonValue ParseScalar(string text, JsonValue original)
	{
		string trimmed = text.Trim();

		// Preserve boolean fields.
		if (original.TryGetValue(out bool _))
		{
			if (bool.TryParse(trimmed, out bool b))
			{
				return JsonValue.Create(b)!;
			}
		}

		// Preserve numeric fields (integral first, then floating-point).
		bool originalIsNumber =
			original.TryGetValue(out long _) ||
			original.TryGetValue(out double _) ||
			original.TryGetValue(out int _);

		if (originalIsNumber)
		{
			if (long.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out long l))
			{
				return JsonValue.Create(l)!;
			}

			if (double.TryParse(trimmed, NumberStyles.Float, CultureInfo.InvariantCulture, out double d))
			{
				return JsonValue.Create(d)!;
			}
		}

		// Default: store as a JSON string (matches the original kind for string fields, and is a safe
		// fallback when a numeric field was given non-numeric text).
		return JsonValue.Create(trimmed)!;
	}

	private void RefreshDebugIndicator(JsonObject? section)
	{
		bool debug = section?["Diagnostics"] is JsonObject diag
			&& diag["DebugMode"] is JsonValue v
			&& v.TryGetValue(out bool b)
			&& b;

		_suppressEditorEvents = true;
		try
		{
			_debugToggle.Checked = debug;
		}
		finally
		{
			_suppressEditorEvents = false;
		}

		if (debug)
		{
			_debugStatus.Text = "DEBUG MODE ENABLED";
			_debugStatus.ForeColor = StatusDanger;
			_debugWarning.Visible = true;
		}
		else
		{
			_debugStatus.Text = "DEBUG mode off";
			_debugStatus.ForeColor = SystemColors.ControlText;
			_debugWarning.Visible = false;
		}
	}

	private void OnDebugToggleChanged()
	{
		if (_suppressEditorEvents)
		{
			return;
		}

		JsonObject? section = TryParseRoot();
		if (section is null)
		{
			UpdateStatus("Cannot toggle DEBUG: fix the raw JSON first.");
			return;
		}

		if (section["Diagnostics"] is not JsonObject diag)
		{
			diag = new JsonObject();
			section["Diagnostics"] = diag;
		}

		diag["DebugMode"] = _debugToggle.Checked;

		JsonObject wrapped = new()
		{
			[Core.Config.RdpAuditOptions.SectionName] = section.DeepClone(),
		};
		SetEditorText(wrapped.ToJsonString(JsonOptions.Indented), rebuildTree: false);
		RefreshDebugIndicator(section);
		_dirty = true;
		UpdateStatus("DEBUG toggled — Save to apply. " + DebugWarningText);
	}

	private void SetEditorText(string text, bool rebuildTree = true)
	{
		_suppressEditorEvents = true;
		try
		{
			_editor.Text = text;
		}
		finally
		{
			_suppressEditorEvents = false;
		}

		if (rebuildTree)
		{
			RefreshFromEditor();
		}
	}

	private void UpdateStatus(string text)
	{
		_status.Text = _dirty ? "● " + text : text;
	}

	private const string DefaultTemplate = """
{
	"RdpAudit": {
		"Monitoring": { "FilterLocalAddresses": true, "BatchSize": 100, "ChannelCapacity": 50000 },
		"Alerts": { "BruteForceThreshold": 10, "BruteForceWindowMinutes": 5 },
		"Storage": { "EventRetentionDays": 365 },
		"Logs": { "ViewDepthDays": 60, "RetentionDays": 60, "DefaultPageSize": 500 },
		"Diagnostics": { "DebugMode": false }
	}
}
""";
}
