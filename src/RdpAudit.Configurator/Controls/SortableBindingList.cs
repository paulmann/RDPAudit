// File:    src/RdpAudit.Configurator/Controls/SortableBindingList.cs
// Module:  RdpAudit.Configurator.Controls
// Purpose: BindingList<T> that supports column-header click sorting in a DataGridView with the correct
//          type semantics. Sorts by the bound property's natural CLR comparison (DateTime as time,
//          numeric as number, enum as ordinal, string ordinal) rather than by display text — so date
//          and count columns sort chronologically / numerically instead of lexicographically.
// Extends: System.ComponentModel.BindingList{T}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Generic;
using System.ComponentModel;

namespace RdpAudit.Configurator.Controls;

/// <summary>A <see cref="BindingList{T}"/> that supports typed header-click sorting in a DataGridView.</summary>
public sealed class SortableBindingList<T> : BindingList<T>
{
	private bool _isSorted;
	private PropertyDescriptor? _sortProperty;
	private ListSortDirection _sortDirection = ListSortDirection.Ascending;

	/// <summary>Creates an empty list.</summary>
	public SortableBindingList()
	{
	}

	/// <summary>Creates a list seeded from <paramref name="items"/>.</summary>
	public SortableBindingList(IEnumerable<T> items)
	{
		ArgumentNullException.ThrowIfNull(items);
		foreach (T item in items)
		{
			Add(item);
		}
	}

	/// <inheritdoc />
	protected override bool SupportsSortingCore => true;

	/// <inheritdoc />
	protected override bool IsSortedCore => _isSorted;

	/// <inheritdoc />
	protected override PropertyDescriptor? SortPropertyCore => _sortProperty;

	/// <inheritdoc />
	protected override ListSortDirection SortDirectionCore => _sortDirection;

	/// <inheritdoc />
	protected override void ApplySortCore(PropertyDescriptor prop, ListSortDirection direction)
	{
		ArgumentNullException.ThrowIfNull(prop);

		List<T> items = new(Items);
		items.Sort((a, b) =>
		{
			object? va = prop.GetValue(a);
			object? vb = prop.GetValue(b);
			int cmp = CompareValues(va, vb);
			return direction == ListSortDirection.Descending ? -cmp : cmp;
		});

		RaiseListChangedEvents = false;
		try
		{
			Items.Clear();
			foreach (T item in items)
			{
				Items.Add(item);
			}
		}
		finally
		{
			RaiseListChangedEvents = true;
		}

		_sortProperty = prop;
		_sortDirection = direction;
		_isSorted = true;
		OnListChanged(new ListChangedEventArgs(ListChangedType.Reset, -1));
	}

	/// <inheritdoc />
	protected override void RemoveSortCore()
	{
		_isSorted = false;
		_sortProperty = null;
	}

	private static int CompareValues(object? a, object? b)
	{
		if (a is null && b is null)
		{
			return 0;
		}
		if (a is null)
		{
			return -1;
		}
		if (b is null)
		{
			return 1;
		}
		if (a is IComparable cmp && a.GetType() == b.GetType())
		{
			return cmp.CompareTo(b);
		}
		return string.Compare(a.ToString(), b.ToString(), StringComparison.OrdinalIgnoreCase);
	}
}
