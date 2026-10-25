/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageBenchmarkCli.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: Command-line parsing and help for the storage benchmark. Hand-rolled on purpose: the tool
//          has to run on an operator's machine with nothing but the shipped binaries, so it takes no
//          dependency a plain console application does not already have. Every rejection carries a
//          message that names the option and the accepted range, because the caller is an operator
//          deciding whether to trust this tool with a measurement, not a developer reading a stack.
// Depends: StorageBenchmarkOptions
// Extends: Add an option by adding its switch to TryParse and a line to HelpText; keep the parser free
//          of side effects so it stays testable.

using System.Globalization;

namespace RdpAudit.StorageBenchmarks;

/// <summary>Outcome of parsing a command line.</summary>
public sealed record StorageBenchmarkCliResult
{
	/// <summary>The parsed options, or null when the command line was rejected or help was requested.</summary>
	public StorageBenchmarkOptions? Options { get; init; }

	/// <summary>The rejection message, or null when nothing was rejected.</summary>
	public string? Error { get; init; }

	/// <summary>True when the caller asked for help.</summary>
	public bool ShowHelp { get; init; }
}

/// <summary>Parses the storage benchmark command line.</summary>
public static class StorageBenchmarkCli
{
	/// <summary>Usage text printed for <c>--help</c> and after a usage error.</summary>
	public const string HelpText = """
		RdpAudit storage benchmark — measures this machine's event-store machinery and recommends settings.

		Usage:
		  RdpAudit.StorageBenchmarks [options]

		Profiles:
		  --quick                 Fast profile: 200 000 rows, 16 codes, 2 samples.
		  --full                  Full profile (default): 1 000 000 rows, 64 codes, 5 samples.

		Options:
		  --store <dir>           Directory to build the benchmark store in. Default: a new temporary
		                          directory. If the directory already contains a database the run
		                          REFUSES to start unless --allow-existing-store is given.
		  --allow-existing-store  Accept a --store directory that already contains a database. The run
		                          then works on a COPY and never writes to the original file.
		  --rows <n>              Synthetic rows to seed (default: profile). Range: 5 000 .. 5 000 000.
		  --codes <n>             Distinct (event id, channel) codes to spread them over
		                          (default: profile). Range: 1 .. 256.
		  --samples <n>           Timed samples per repeated measurement (default: profile).
		                          Range: 1 .. 25.
		  --warmup <n>            Warm-up runs per repeated measurement (default: 1). Range: 0 .. 25.
		  --out <dir>             Report directory. Default: <work-root>\reports\<utc timestamp>.
		  --work-root <dir>       Parent for temporary working directories.
		                          Default: %TEMP%\RdpAudit.StorageBenchmarks.
		  --no-shards             Skip the shard-inclusive snapshot probe.
		  --help, -h, /?          Print this text.

		What it never does:
		  It applies nothing it recommends. It never writes to appsettings.json, the registry or any
		  live configuration, and it never reads or writes %ProgramData%\RdpAudit. It creates its own
		  temporary store, works there and removes it. It needs no administrator rights and no installed
		  Windows service.

		Exit codes:
		  0  the run completed and the report was written
		  1  the command line was rejected
		  2  the run refused to start (an existing store, or a path inside %ProgramData%\RdpAudit)
		  3  the run completed but at least one probe failed; the report says which
		""";

	/// <summary>Default work root, under the user's temporary directory.</summary>
	public static string DefaultWorkRoot => Path.Combine(Path.GetTempPath(), "RdpAudit.StorageBenchmarks");

	/// <summary>Parses <paramref name="args"/>. Never throws and never touches the filesystem.</summary>
	public static StorageBenchmarkCliResult Parse(string[] args)
	{
		ArgumentNullException.ThrowIfNull(args);

		bool quick = false;
		bool allowExistingStore = false;
		bool includeShards = true;
		int? rows = null;
		int? codes = null;
		int? samples = null;
		int? warmup = null;
		string? store = null;
		string? output = null;
		string workRoot = DefaultWorkRoot;

		for (int index = 0; index < args.Length; index++)
		{
			string argument = args[index];
			string name = argument;
			string? inlineValue = null;
			int separator = argument.IndexOf('=', StringComparison.Ordinal);
			if (separator > 0)
			{
				name = argument[..separator];
				inlineValue = argument[(separator + 1)..];
			}

			switch (name)
			{
				case "--help":
				case "-h":
				case "/?":
				case "-?":
					return new StorageBenchmarkCliResult { ShowHelp = true };

				case "--quick":
					quick = true;
					break;

				case "--full":
					quick = false;
					break;

				case "--allow-existing-store":
					allowExistingStore = true;
					break;

				case "--no-shards":
					includeShards = false;
					break;

				case "--store":
					if (!TryTakeValue(args, ref index, inlineValue, name, out string storeValue, out string? storeError))
					{
						return new StorageBenchmarkCliResult { Error = storeError };
					}

					store = storeValue;
					break;

				case "--out":
					if (!TryTakeValue(args, ref index, inlineValue, name, out string outValue, out string? outError))
					{
						return new StorageBenchmarkCliResult { Error = outError };
					}

					output = outValue;
					break;

				case "--work-root":
					if (!TryTakeValue(args, ref index, inlineValue, name, out string rootValue, out string? rootError))
					{
						return new StorageBenchmarkCliResult { Error = rootError };
					}

					workRoot = rootValue;
					break;

				case "--rows":
					if (!TryTakeInt(args, ref index, inlineValue, name, StorageBenchmarkOptions.MinRows, StorageBenchmarkOptions.MaxRows, out int rowsValue, out string? rowsError))
					{
						return new StorageBenchmarkCliResult { Error = rowsError };
					}

					rows = rowsValue;
					break;

				case "--codes":
					if (!TryTakeInt(args, ref index, inlineValue, name, StorageBenchmarkOptions.MinCodes, StorageBenchmarkOptions.MaxCodes, out int codesValue, out string? codesError))
					{
						return new StorageBenchmarkCliResult { Error = codesError };
					}

					codes = codesValue;
					break;

				case "--samples":
					if (!TryTakeInt(args, ref index, inlineValue, name, StorageBenchmarkOptions.MinSamples, StorageBenchmarkOptions.MaxSamples, out int samplesValue, out string? samplesError))
					{
						return new StorageBenchmarkCliResult { Error = samplesError };
					}

					samples = samplesValue;
					break;

				case "--warmup":
					if (!TryTakeInt(args, ref index, inlineValue, name, 0, StorageBenchmarkOptions.MaxSamples, out int warmupValue, out string? warmupError))
					{
						return new StorageBenchmarkCliResult { Error = warmupError };
					}

					warmup = warmupValue;
					break;

				default:
					return new StorageBenchmarkCliResult
					{
						Error = string.Format(
							CultureInfo.InvariantCulture,
							"'{0}' is not a recognised option. Run with --help to see the accepted options.",
							argument),
					};
			}
		}

		return new StorageBenchmarkCliResult
		{
			Options = new StorageBenchmarkOptions
			{
				Quick = quick,
				Rows = rows ?? (quick ? StorageBenchmarkOptions.QuickRows : StorageBenchmarkOptions.FullRows),
				Codes = codes ?? (quick ? StorageBenchmarkOptions.QuickCodes : StorageBenchmarkOptions.FullCodes),
				Samples = samples ?? (quick ? StorageBenchmarkOptions.QuickSamples : StorageBenchmarkOptions.FullSamples),
				WarmupRuns = warmup ?? 1,
				StoreDirectory = store,
				WorkRoot = workRoot,
				OutputDirectory = output,
				AllowExistingStore = allowExistingStore,
				IncludeShards = includeShards,
			},
		};
	}

	private static bool TryTakeValue(
		string[] args,
		ref int index,
		string? inlineValue,
		string name,
		out string value,
		out string? error)
	{
		value = string.Empty;
		error = null;

		if (inlineValue is { } inline)
		{
			if (string.IsNullOrWhiteSpace(inline))
			{
				error = name + " needs a value.";
				return false;
			}

			value = inline;
			return true;
		}

		if (index + 1 >= args.Length)
		{
			error = name + " needs a value.";
			return false;
		}

		index++;
		value = args[index];
		if (string.IsNullOrWhiteSpace(value))
		{
			error = name + " needs a value.";
			return false;
		}

		return true;
	}

	private static bool TryTakeInt(
		string[] args,
		ref int index,
		string? inlineValue,
		string name,
		int minimum,
		int maximum,
		out int value,
		out string? error)
	{
		value = 0;
		if (!TryTakeValue(args, ref index, inlineValue, name, out string text, out error))
		{
			return false;
		}

		if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value))
		{
			error = string.Format(CultureInfo.InvariantCulture, "{0} needs a whole number, not '{1}'.", name, text);
			return false;
		}

		if (value < minimum || value > maximum)
		{
			error = string.Format(
				CultureInfo.InvariantCulture,
				"{0} must be between {1} and {2}; {3} was given.",
				name,
				minimum,
				maximum,
				value);
			return false;
		}

		return true;
	}
}
