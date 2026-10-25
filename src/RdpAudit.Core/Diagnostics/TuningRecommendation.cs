/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : TuningRecommendation.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: One parameter the recommendation engine has an opinion about, together with the evidence
//          for that opinion. A recommendation is only useful to an operator who can check it, so it
//          always carries the rule that produced it, the measured inputs it consumed and the caveat
//          that bounds it. Three states are possible and they are not interchangeable: a value is
//          proposed, the measured evidence says the parameter should NOT be set this way, or the run
//          did not measure what the rule needs and therefore proposes nothing at all.
// Depends: System.Globalization
// Extends: Add a parameter by adding a rule to StorageTuningAdvisor; never emit a recommendation
//          whose Inputs do not name the measurements it used.

using System.Globalization;

namespace RdpAudit.Core.Diagnostics;

/// <summary>The three outcomes a tuning rule can have.</summary>
public enum RecommendationState
{
	/// <summary>The rule had every input it needs and proposes <see cref="TuningRecommendation.Value"/>.</summary>
	Recommended = 0,

	/// <summary>The rule had every input it needs and the measured evidence says the parameter should
	/// not be enabled as configured. <see cref="TuningRecommendation.Value"/> is null and
	/// <see cref="TuningRecommendation.Rationale"/> carries the refusal and what to do instead.</summary>
	Declined = 1,

	/// <summary>The rule was missing at least one measured input, so it proposes nothing.
	/// <see cref="TuningRecommendation.Inputs"/> names the metrics that were missing.</summary>
	InsufficientData = 2,
}

/// <summary>
/// One parameter, the measured evidence about it, and what the evidence implies.
/// </summary>
public sealed record TuningRecommendation
{
	/// <summary>Dotted configuration path of the setting (for example
	/// <c>RdpAudit:Storage:RetentionPolicy:DeleteBatchRows</c>), or a <c>Operations:</c> key when the
	/// advice is about an operating practice rather than a setting.</summary>
	public required string Parameter { get; init; }

	/// <summary>Which of the three outcomes this rule reached.</summary>
	public required RecommendationState State { get; init; }

	/// <summary>The proposed value, as it would be written into the settings fragment. Null unless
	/// <see cref="State"/> is <see cref="RecommendationState.Recommended"/>.</summary>
	public long? Value { get; init; }

	/// <summary>Unit of <see cref="Value"/> (for example <c>rows</c>, <c>ms</c>, <c>bytes</c>,
	/// <c>copies</c>). Null when no value is proposed.</summary>
	public string? Unit { get; init; }

	/// <summary>Name of the rule/formula, without numbers, so two runs can be compared by rule.</summary>
	public required string Rule { get; init; }

	/// <summary>The rule with this run's measured numbers substituted into it, in one sentence: the
	/// arithmetic an operator can redo by hand from the measurement table.</summary>
	public required string Rationale { get; init; }

	/// <summary>The measured inputs the rule consumed, one <c>metric = value unit</c> line each; or,
	/// for <see cref="RecommendationState.InsufficientData"/>, the metrics that were missing.</summary>
	public required IReadOnlyList<string> Inputs { get; init; }

	/// <summary>What bounds the recommendation: what it was measured on, what it assumes and when it
	/// should be re-measured. Never empty.</summary>
	public required string Caveat { get; init; }

	/// <summary>True when <see cref="Parameter"/> is a real settings key that can be merged into
	/// appsettings.json; false when the advice is operational and must not appear in the settings
	/// fragment.</summary>
	public bool IsConfigurationSetting { get; init; }

	/// <summary>Builds a rule that proposes a value.</summary>
	public static TuningRecommendation Recommended(
		string parameter,
		long value,
		string unit,
		string rule,
		string rationale,
		IReadOnlyList<string> inputs,
		string caveat,
		bool isConfigurationSetting = true)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(unit);
		return new TuningRecommendation
		{
			Parameter = parameter,
			State = RecommendationState.Recommended,
			Value = value,
			Unit = unit,
			Rule = rule,
			Rationale = rationale,
			Inputs = inputs,
			Caveat = caveat,
			IsConfigurationSetting = isConfigurationSetting,
		};
	}

	/// <summary>Builds a rule whose measured evidence says the parameter should not be set as asked.</summary>
	public static TuningRecommendation Declined(
		string parameter,
		string rule,
		string rationale,
		IReadOnlyList<string> inputs,
		string caveat,
		bool isConfigurationSetting = true)
		=> new()
		{
			Parameter = parameter,
			State = RecommendationState.Declined,
			Rule = rule,
			Rationale = rationale,
			Inputs = inputs,
			Caveat = caveat,
			IsConfigurationSetting = isConfigurationSetting,
		};

	/// <summary>Builds a rule that had no measured input to work from.</summary>
	public static TuningRecommendation Insufficient(
		string parameter,
		string rule,
		string rationale,
		IReadOnlyList<string> missingMetrics,
		bool isConfigurationSetting = true)
		=> new()
		{
			Parameter = parameter,
			State = RecommendationState.InsufficientData,
			Rule = rule,
			Rationale = rationale,
			Inputs = missingMetrics,
			Caveat = "No value is proposed. Re-run the benchmark so the missing measurement is taken, or set this parameter from operational experience instead.",
			IsConfigurationSetting = isConfigurationSetting,
		};

	/// <summary>One-line rendering of the value for the report's value column.</summary>
	public string DescribeValue()
		=> Value is { } value && Unit is { } unit
			? string.Format(CultureInfo.InvariantCulture, "{0} {1}", value, unit)
			: State switch
			{
				RecommendationState.Declined => "do not set (see rationale)",
				_ => "insufficient data",
			};
}
