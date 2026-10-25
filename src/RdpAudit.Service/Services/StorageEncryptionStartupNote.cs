// Version: 1.0.0
// File:    src/RdpAudit.Service/Services/StorageEncryptionStartupNote.cs
// Module:  RdpAudit.Service.Services
// Purpose: Carries the non-fatal outcome of the encryption-at-rest assertion from configuration load to the
//          point where the logging pipeline is up. The assertion itself happens before the host is built
//          (it must fail closed before anything opens the store), but Serilog is not configured until later -
//          so the message travels as a value instead of being logged into a pipeline that does not exist yet.
// Depends: none
// Extends: System.Object

namespace RdpAudit.Service.Services;

/// <summary>The operator-visible note produced by the encryption-at-rest assertion at start-up, or null when
/// the configured mode needs no comment.</summary>
/// <param name="Warning">Message to log once the logging pipeline is available; null when there is nothing
/// to say (the default <c>None</c> mode).</param>
public sealed record StorageEncryptionStartupNote(string? Warning);
