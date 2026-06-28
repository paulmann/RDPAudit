# Publishing RdpAudit

`publish.ps1` at the repo root builds `RdpAudit.Service` and `RdpAudit.Configurator` as self-contained, single-file, win-x64 executables under `./publish/Service` and `./publish/Configurator`. Requires PowerShell 7+.

## Typical usage

```powershell
pwsh -NoProfile -File .\publish.ps1
```

Optional parameters:

| Parameter        | Default   | Purpose                                                                 |
|------------------|-----------|-------------------------------------------------------------------------|
| `-Version`       | `1.0.0`   | Passed to `dotnet publish` as `-p:VersionPrefix`.                       |
| `-Configuration` | `Release` | `dotnet publish -c` value.                                              |
| `-Force`         | off       | Terminate RdpAudit processes that are running from the publish folder. |
| `-Verbose`       | off       | Print per-step diagnostics (process inspection, retry attempts, …).    |
| `-SelfTest`      | off       | Run the script's structural invariants and exit. No publish, no delete. |

## Before publishing

Close `RdpAudit.Configurator` first. If the installed service is running, stop it (`sc.exe stop RdpAudit`) — its EXE under `publish\Service` is locked while running.

If you forget, `publish.ps1` detects the lock and prints an actionable diagnostic. Pass `-Force` to terminate the blocking processes automatically; `-Force` only ever kills processes named `RdpAudit.Configurator` / `RdpAudit.Service` **whose executable path is inside the publish folder**. Anything outside that folder is reported and skipped, never killed.

## Diagnostics

### `-Verbose`

Surfaces:

- how many `RdpAudit.Configurator` and `RdpAudit.Service` processes were found system-wide;
- which were confirmed as blockers (path under publish root) and which were skipped (path outside publish root);
- which could not be inspected (access denied, exited mid-scan, native error reading `Process.Path`) — these are recorded as **inspection failures**, never as blockers, and never killed;
- each `Remove-Item` retry attempt (up to 5, with backoff).

### `-SelfTest`

Validates the script's structural invariants without publishing or deleting anything:

1. `Format-LockingProcess` formats a confirmed blocker correctly.
2. `Format-InspectionFailure` formats an inspection record (including null PID).
3. `Format-LockingProcess` rejects records that lack `ExePath` at parameter-binding time (cannot crash with "property cannot be found").
4. `Get-ProcessesUsingPath` returns `Count == 0` for an unrelated path (no array double-wrap regression).
5. No `$pid` / `$PID` / `$Pid` assignments in the script source (collides with the read-only automatic).
6. The script parses cleanly under the PowerShell parser.
7. Confirmed blockers and inspection failures are kept in separate lists.

```powershell
pwsh -NoProfile -File .\publish.ps1 -SelfTest
```

Run this whenever `publish.ps1` is modified.

## Failure output

If deletion still fails after retries, the thrown error contains:

- target path and attempt count;
- the confirmed blocker list (process name, PID, EXE path);
- the inspection-failure list (process name, PID-or-`?`, reason);
- underlying exception type, message, and (for `IOException`) the locked file name;
- likely causes and concrete next-step commands.

## Design invariants (do not regress)

- **Single, validated shape for blockers.** Confirmed blockers are hashtables with exactly `ProcessName`, `ProcessIdValue`, `ExePath`, all non-empty. They are created only through `New-ConfirmedBlocker`, which validates inputs.
- **Inspection failures never reach blocker logic.** They live in `$script:InspectionFailures` and are formatted by a separate function with separate parameters.
- **Formatters take scalars, not objects.** `Format-LockingProcess` and `Format-InspectionFailure` declare mandatory `[string]` / `[int]` parameters. A malformed input fails at parameter binding, never at runtime property access — even under `Set-StrictMode -Version Latest`.
- **No `return ,$arr.ToArray()` patterns.** `Get-ProcessesUsingPath` emits its result via `Write-Output -NoEnumerate` against a `List[hashtable]`. This avoids the classic PowerShell double-wrap where the caller's `@(...)` produces a one-element outer array containing the inner empty array — the regression that previously caused `Format-LockingProcess` to be invoked on an empty array literal.
- **`-Force` is scoped.** Only kills processes named `RdpAudit.Configurator` / `RdpAudit.Service` whose normalized `Process.Path` starts with the publish root. Processes with unreadable paths are never killed.
- **No assignments to `$pid`.** PowerShell variable names are case-insensitive; `$pid` is a read-only automatic. All process-id locals use `$processIdValue`.

## Windows quick reference

```powershell
# Refresh the branch
git fetch origin
git reset --hard origin/main

# Validate the script before running it
pwsh -NoProfile -File .\publish.ps1 -SelfTest

# Publish, terminating any blocking RdpAudit processes from the publish folder
pwsh -NoProfile -File .\publish.ps1 -Force -Verbose
```
