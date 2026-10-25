// File:    tests/RdpAudit.Configurator.Tests/MutationOutcomeReportingTests.cs
// Module:  RdpAudit.Configurator.Tests
// Purpose: Regression coverage for the way the Configurator reports list mutations. The historic
//          shape wrapped every blocklist / whitelist call in a bare catch and reduced the outcome to
//          `payload is not null`, which reported three different situations identically: a transport
//          failure, a service-side rejection, and a mutation the service completed WITHOUT a payload.
//          The third case is the dangerous one — IpcCallOutcome.SuccessNoPayload deserializes to null,
//          so a block that was really installed was shown to the operator as "FAILED". These tests pin
//          the opposite contract: success is decided by the outcome, never by payload presence, and the
//          cause of a failure survives to the status line instead of being swallowed.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using Xunit;

namespace RdpAudit.Configurator.Tests;

public sealed class MutationOutcomeReportingTests
{
	private static IpcCallResult<JsonElement?> Result(
		IpcCallOutcome outcome,
		string? error = null) => new(
			IpcCommand.AddToBlocklist,
			outcome,
			value: default,
			error,
			errorType: outcome is IpcCallOutcome.Success or IpcCallOutcome.SuccessNoPayload ? null : "Test",
			startUtc: DateTime.UtcNow,
			durationMs: 12,
			timeoutMs: 30_000,
			pipeConnected: outcome != IpcCallOutcome.ConnectFailed,
			responseReceived: outcome is IpcCallOutcome.Success
				or IpcCallOutcome.SuccessNoPayload
				or IpcCallOutcome.ServiceError);

	/// <summary>
	/// The regression that started this: a service-side success with an empty payload must not be
	/// mistaken for a failure. A mutation command legitimately returns nothing, and the operator must
	/// be told the block was installed rather than sent to re-check a block that already exists.
	/// </summary>
	[Fact]
	public void SuccessWithoutPayload_IsStillASuccess()
	{
		IpcCallResult<JsonElement?> call = Result(IpcCallOutcome.SuccessNoPayload);

		Assert.Null(call.Value);
		Assert.True(call.IsSuccess);
		Assert.Equal("OK", call.Headline());
	}

	[Fact]
	public void SuccessWithPayload_IsASuccess()
	{
		IpcCallResult<JsonElement?> call = Result(IpcCallOutcome.Success);

		Assert.True(call.IsSuccess);
		Assert.Equal("OK", call.Headline());
	}

	/// <summary>Every failure mode must stay distinguishable, and must carry its cause.</summary>
	[Theory]
	[InlineData(IpcCallOutcome.ConnectFailed, "service unreachable")]
	[InlineData(IpcCallOutcome.Timeout, "timed out")]
	[InlineData(IpcCallOutcome.TransportError, "transport error")]
	public void FailureOutcomes_AreNotSuccess_AndNameTheirCause(IpcCallOutcome outcome, string expectedFragment)
	{
		IpcCallResult<JsonElement?> call = Result(outcome, error: "detail-from-transport");

		Assert.False(call.IsSuccess);
		Assert.Contains(expectedFragment, call.Headline(), StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// A service-side rejection must surface the service's own message. The bare catch that used to sit
	/// here discarded exactly this text, leaving the operator with a bare "FAILED".
	/// </summary>
	[Fact]
	public void ServiceError_KeepsTheServiceMessage()
	{
		IpcCallResult<JsonElement?> call = Result(
			IpcCallOutcome.ServiceError,
			error: "address is already present in the blocklist");

		Assert.False(call.IsSuccess);
		Assert.Contains("already present", call.Headline(), StringComparison.Ordinal);
	}

	/// <summary>
	/// Guards the exact reasoning behind the fix: "no payload" and "no success" are independent facts,
	/// so no caller can re-introduce a payload-presence check as the success criterion.
	/// </summary>
	[Fact]
	public void PayloadPresence_IsIndependentOfSuccess()
	{
		IpcCallResult<JsonElement?> successNoPayload = Result(IpcCallOutcome.SuccessNoPayload);
		IpcCallResult<JsonElement?> serviceError = Result(IpcCallOutcome.ServiceError, "boom");

		Assert.Null(successNoPayload.Value);
		Assert.True(successNoPayload.IsSuccess);

		Assert.Null(serviceError.Value);
		Assert.False(serviceError.IsSuccess);
	}

	/// <summary>The B3 trap: a command without its own declared timeout silently inherits the default,
	/// which is why the status line prints the effective value it ran with.</summary>
	[Fact]
	public void RoundTripCarriesTheEffectiveTimeoutAndDuration()
	{
		IpcCallResult<JsonElement?> call = Result(IpcCallOutcome.Success);

		Assert.Equal(30_000, call.TimeoutMs);
		Assert.Equal(12, call.DurationMs);
		Assert.Contains("timeout=30000ms", call.TraceLine, StringComparison.Ordinal);
	}
}
