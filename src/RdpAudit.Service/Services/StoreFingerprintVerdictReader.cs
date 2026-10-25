/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : StoreFingerprintVerdictReader.cs
// Project: RdpAudit.Service (RdpAudit.Service.Services)
// Purpose: The one read of the store-fingerprint chain verdict and the anomaly marker. The Database tab's
//          overview and the Diagnostic tab both build their integrity section from this call, so the two
//          tabs cannot disagree about a tamper verdict - which matters more here than anywhere else in the
//          product: a verdict that reads `chain-broken` on one tab and `ok` on another is worse than a
//          verdict only one tab shows, because it teaches the operator to distrust both.
//          The reader deliberately does NOT decide what a failure means. It reads and returns; the caller
//          applies its own policy (the overview degrades to partial with a warning, the diagnostics section
//          fails and is recorded in the section timings). Swallowing an I/O failure here would flatten
//          "the marker could not be read" and "there is no marker" into the same value.
// Depends: StoreFingerprintStore, StoreFingerprintDocument, StoreFingerprintChainVerdict
// Extends: A new chain state is added in StoreFingerprintChainVerdict, not here; this file only carries
//          the value it returns plus the two timestamps.

using System.Text.Json;
using RdpAudit.Core.Integrity;

namespace RdpAudit.Service.Services;

/// <summary>What a reader learned about the fingerprint chain and the anomaly marker. Every field is a
/// recorded observation; nothing here runs a check or a comparison.</summary>
/// <param name="ChainState">The reported chain state (<c>ok</c>, <c>missing</c>, <c>unreadable</c>,
/// <c>chain-broken</c>, <c>interrupted</c> or <c>unverified</c>), or null when no chain state could be
/// reported at all - which callers must render as unknown, never as a pass.</param>
/// <param name="ChainEntryCount">How many entries the readable chain holds; 0 when nothing was read.</param>
/// <param name="ChainMessage">The chain verdict in full, including every finding behind a non-Ok state.</param>
/// <param name="MirrorAvailable">Whether the chain's key facts are mirrored outside the integrity folder;
/// null when the chain was not verified.</param>
/// <param name="CleanShutdownUtc">When the clean-shutdown fingerprint was captured, or null.</param>
/// <param name="PeriodicUtc">When the last periodic fingerprint was captured, or null.</param>
/// <param name="AnomalyMarkerPresent">True when the anomaly marker file is present.</param>
/// <param name="AnomalyDetail">The marker's text, truncated to the report budget; null when absent.</param>
public sealed record StoreFingerprintVerdictRead(
	string? ChainState,
	int ChainEntryCount,
	string? ChainMessage,
	bool? MirrorAvailable,
	DateTime? CleanShutdownUtc,
	DateTime? PeriodicUtc,
	bool AnomalyMarkerPresent,
	string? AnomalyDetail);

/// <summary>Reads the fingerprint-chain verdict and the anomaly marker for every surface that shows them.</summary>
public static class StoreFingerprintVerdictReader
{
	/// <summary>Upper bound on the anomaly detail carried into a snapshot. A marker is written by this
	/// product and is short, but the file is on disk and therefore untrusted input.</summary>
	public const int MaxAnomalyDetailChars = 2000;

	/// <summary>Reads the chain (through <paramref name="fingerprints"/> when the host provided it) and the
	/// anomaly marker at <paramref name="markerPath"/>.
	/// <para>
	/// The chain directory and the marker are read from the paths the STORE reports, not re-derived by the
	/// caller, so a host with a non-default layout reports what it actually wrote.
	/// </para>
	/// <para>
	/// A host that did not provide the fingerprint store falls back to the pre-B19 document when one exists:
	/// the two timestamps are still shown, and the state is reported as <c>unverified</c> - "the chain was
	/// never verified here" - instead of being left null, so an older installation is not silently promoted
	/// to either "ok" or "missing".
	/// </para>
	/// </summary>
	public static StoreFingerprintVerdictRead Read(
		string fingerprintPath,
		string markerPath,
		StoreFingerprintStore? fingerprints)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(fingerprintPath);
		ArgumentException.ThrowIfNullOrWhiteSpace(markerPath);

		string? chainState = null;
		int entryCount = 0;
		string? chainMessage = null;
		bool? mirrorAvailable = null;
		DateTime? cleanShutdownUtc = null;
		DateTime? periodicUtc = null;

		if (fingerprints is not null)
		{
			StoreFingerprintChainVerification chain = fingerprints.ReadAndVerify();
			chainState = StoreFingerprintChainVerdict.NameOf(chain.State);
			entryCount = chain.EntryCount;
			chainMessage = chain.Message;
			mirrorAvailable = fingerprints.AlarmMirrorAvailable;
			cleanShutdownUtc = chain.LastCleanShutdown?.Fingerprint.CapturedUtc;
			periodicUtc = chain.LastPeriodic?.Fingerprint.CapturedUtc;
		}
		else if (File.Exists(fingerprintPath))
		{
			StoreFingerprintDocument? document =
				JsonSerializer.Deserialize<StoreFingerprintDocument>(File.ReadAllText(fingerprintPath));
			cleanShutdownUtc = document?.LastCleanShutdown?.CapturedUtc;
			periodicUtc = document?.LastPeriodic?.CapturedUtc;
			chainState = StoreFingerprintChainVerdict.Unverified;
			chainMessage =
				"The fingerprint chain was not verified: this host did not provide the fingerprint store, so "
				+ "only the pre-B19 document was read. Treat the timestamps as unverified.";
		}

		bool markerPresent = false;
		string? markerDetail = null;
		if (File.Exists(markerPath))
		{
			markerPresent = true;
			string marker = File.ReadAllText(markerPath);
			markerDetail = marker.Length <= MaxAnomalyDetailChars ? marker : marker[..MaxAnomalyDetailChars];
		}

		return new StoreFingerprintVerdictRead(
			chainState,
			entryCount,
			chainMessage,
			mirrorAvailable,
			cleanShutdownUtc,
			periodicUtc,
			markerPresent,
			markerDetail);
	}
}
