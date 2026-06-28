# RdpAudit — Architecture Overview

RdpAudit is a Windows RDP security monitoring solution targeting `net8.0-windows` x64. It is composed of three projects:

| Project | Type | Purpose |
|---------|------|---------|
| `RdpAudit.Core` | class library (`net8.0-windows`) | EF Core entities and DbContext, options, IPC contracts, alert framework abstractions, IP classification, event XML parsing |
| `RdpAudit.Service` | Windows worker service | Captures Windows events via `EventLogWatcher`, normalises and persists to SQLite, evaluates alert rules, hosts the named-pipe IPC server, performs daily maintenance |
| `RdpAudit.Configurator` | WinForms app | Prerequisites checks, audit policy management, service control, settings editor, **live database events tab** |

## Layering rules

- `Core` has zero references to `Service` / `Configurator` and contains no UI.
- `Service` and `Configurator` depend on `Core` only.
- All times in the database are UTC. The Configurator displays local time only at the UI boundary.

## File header convention

Every C# file in this repository begins with a structured header:

```csharp
// File:    <relative path>
// Module:  <namespace>
// Purpose: <one-line description>
// Extends: <parent type>
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
```

When introducing a new file, copy this header verbatim and fill in the fields.

## Required defaults

- Tabs (not spaces) for indentation.
- `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` is enabled in `Directory.Build.props` and **must not** be suppressed.
- Nullable reference types are enabled solution-wide.
- All P/Invoke declarations live in `RdpAudit.Core/Interop/NativeMethods.cs` and use `[LibraryImport]` (no `[DllImport]`).
- All OS handles are wrapped in a `SafeHandle` subclass — never bare `IntPtr`.

## LLM extension contract

When a future automated agent modifies this codebase, it must:

1. Preserve the project dependency graph (Core → no deps; Service & Configurator → Core only).
2. Keep every C# file's structured header intact.
3. Run `dotnet test` for `RdpAudit.Core.Tests` and `RdpAudit.Service.Tests` after every functional change.
4. For any change to a major block, also update the corresponding Markdown file in this directory.
