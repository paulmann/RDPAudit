// File:    src/RdpAudit.Configurator/Services/SortableGrid.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Attaches type-aware, click-to-sort behaviour to a DataGridView whose DataSource is a
//          BindingList{T}. Sorting is delegated to RdpAudit.Core.Util.GridValueComparer so IP
//          addresses, dates, durations and numbers order naturally rather than lexicographically. The
//          comparison runs over the value each column actually renders (DataPropertyName), so display
//          columns such as "1d 02h 03m" sort correctly.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Reflection;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Wires type-aware header-click sorting onto a <see cref="DataGridView"/> bound to a
/// <see cref="BindingList{T}"/>.</summary>
public static class SortableGrid
{
	/// <summary>
	/// Enables click-to-sort on <paramref name="grid"/>. Each text column is set to programmatic sort
	/// mode; clicking a header re-orders <paramref name="source"/> in place using
	/// <see cref="GridValueComparer"/> over the property named by the column's
	/// <see cref="DataGridViewColumn.DataPropertyName"/>. Re-clicking the same column toggles direction.
	/// </summary>
	/// <param name="sortKeyByProperty">
	/// Optional map from a column's <see cref="DataGridViewColumn.DataPropertyName"/> to the name of a
	/// sibling property on <typeparamref name="T"/> that holds the *typed* value to sort by. Use this
	/// when a column renders a composite / decorated string that <see cref="GridValueComparer"/> cannot
	/// parse back to its natural type — e.g. a "Threat" column showing "70.0 (High)" should sort on the
	/// numeric <c>ThreatScore</c>. When a mapped property is found its value is compared with its own
	/// <see cref="IComparable"/> so the order is exact; otherwise the rendered string is used.
	/// </param>
	public static void Enable<T>(
		DataGridView grid,
		BindingList<T> source,
		IReadOnlyDictionary<string, string>? sortKeyByProperty = null)
	{
		ArgumentNullException.ThrowIfNull(grid);
		ArgumentNullException.ThrowIfNull(source);

		foreach (DataGridViewColumn col in grid.Columns)
		{
			if (!string.IsNullOrEmpty(col.DataPropertyName))
			{
				col.SortMode = DataGridViewColumnSortMode.Programmatic;
			}
		}

		string? sortedProperty = null;
		bool ascending = true;

		grid.ColumnHeaderMouseClick += (_, e) =>
		{
			if (e.ColumnIndex < 0 || e.ColumnIndex >= grid.Columns.Count)
			{
				return;
			}

			DataGridViewColumn clicked = grid.Columns[e.ColumnIndex];
			string property = clicked.DataPropertyName;
			if (string.IsNullOrEmpty(property))
			{
				return;
			}

			if (string.Equals(sortedProperty, property, StringComparison.Ordinal))
			{
				ascending = !ascending;
			}
			else
			{
				sortedProperty = property;
				ascending = true;
			}

			// Prefer an explicit typed sort key when the column renders a decorated string that cannot
			// be parsed back to its natural type. Falls back to the rendered property otherwise.
			string sortProperty = property;
			if (sortKeyByProperty is not null
				&& sortKeyByProperty.TryGetValue(property, out string? keyProperty)
				&& !string.IsNullOrEmpty(keyProperty))
			{
				sortProperty = keyProperty;
			}

			PropertyInfo? prop = typeof(T).GetProperty(sortProperty, BindingFlags.Public | BindingFlags.Instance);
			if (prop is null)
			{
				return;
			}

			bool typedKey = !string.Equals(sortProperty, property, StringComparison.Ordinal);
			List<T> items = new(source);
			int direction = ascending ? 1 : -1;
			items.Sort((a, b) =>
			{
				object? ao = prop.GetValue(a);
				object? bo = prop.GetValue(b);
				if (typedKey && ao is IComparable ac && bo is not null && bo.GetType() == ao.GetType())
				{
					return direction * ac.CompareTo(bo);
				}

				return direction * GridValueComparer.Compare(ao?.ToString(), bo?.ToString());
			});

			bool raise = source.RaiseListChangedEvents;
			source.RaiseListChangedEvents = false;
			source.Clear();
			foreach (T item in items)
			{
				source.Add(item);
			}
			source.RaiseListChangedEvents = raise;
			source.ResetBindings();

			foreach (DataGridViewColumn col in grid.Columns)
			{
				col.HeaderCell.SortGlyphDirection = SortOrder.None;
			}
			clicked.HeaderCell.SortGlyphDirection = ascending ? SortOrder.Ascending : SortOrder.Descending;
		};
	}
}
