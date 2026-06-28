# RdpAudit.Core

The shared library that holds all data contracts, options, and platform-agnostic helpers.

## Public surface

- `Models/` — `RawEvent`, `Session`, `Address`, `Alert`, `Bookmark`, `DbProp`, plus `AlertSeverity` and `SessionStatus` enums.
- `Data/` — `AuditDbContext`, `IEntityTypeConfiguration<T>` rows, `SqlitePragmaInterceptor`, `AuditDbInitializer`.
- `Config/` — `RdpAuditOptions` (root), `MonitoringOptions`, `AlertOptions`, `FirewallOptions`, `StorageOptions`, `DiagnosticsOptions`.
- `Events/` — `EventCatalog`, `EventDescriptor`, `EventXmlParser`, `RawEventDto`, `BookmarkStore`, `AuditPolicyManager`, `IAlertContext`, `IAlertRule`, `AlertRuleBase`.
- `Ipc/` — `IpcCommand`, `IpcRequest`, `IpcResponse`, `IpcException`, `IpcConstants`, `ServiceStatus`.
- `Interop/` — declarations only (`NativeMethods.cs`), `[LibraryImport]`-style P/Invoke.
- `Util/` — `IpClassifier`, `JsonOptions`, `PathSafety`.

## Extension points

| To add… | …extend |
|---------|---------|
| A new entity | a new `Models/<Name>.cs` + `Data/Configurations/<Name>Configuration.cs`; `AuditDbContext` picks it up automatically via `ApplyConfigurationsFromAssembly`. |
| A new event id | add a new `EventDescriptor` row to `EventCatalog.All`. |
| A new IPC command | add to `IpcCommand` enum (append only — never reuse retired values) and handle it in `IpcDispatcher` (Service). |
| A new alert rule | implement `IAlertRule` (or extend `AlertRuleBase`) in the Service project; register in `AlertRuleRegistration`. |

## LLM contract

Any future change to this project must:

- Preserve the absence of OS-specific dependencies. The only Windows-only file is `Interop/NativeMethods.cs`.
- Add unit tests in `RdpAudit.Core.Tests` for new helpers in `Util/` or `Events/` parsers.
- Run `dotnet test tests/RdpAudit.Core.Tests` before opening a PR.
- Avoid raw SQL; use EF Core LINQ or `ExecuteDeleteAsync` for bulk deletes.

## Required tests before modifying

- `IpClassifierTests` — every modification to `IpClassifier` must keep all theory cases green.
- `EventXmlParserTests` — XXE prohibition must remain (DTD set to `Prohibit`).
- `EventCatalogTests` — adding events must keep the catalog distinct on (channel, eventId).
