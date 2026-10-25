# 88 - Database Backup and Restore

Status: implemented in stage 2b (server side + service layer) and stage 3 (the Configurator
`Database` tab that drives it, plus the scratch-restore IPC command). This page documents what exists
on disk and over IPC today.

Related: `docs/50-ipc.md` (ordinals 85-87), `docs/40-options.md` (`BackupOptions`),
`docs/20-service.md` (startup behaviour), `docs/87-information-density-retention.md`.

---

## 1. What a database snapshot is

A snapshot is one **consistent online copy of the live SQLite evidence store**, taken while the
service keeps running, plus a manifest that makes the copy self-describing and verifiable.

```
%ProgramData%\RdpAudit\Backups\<yyyyMMdd-HHmmss>\
├── manifest.json            <- what was copied, from where, with which digests and row counts
├── db\
│   └── rdpaudit.db          <- the database copy (DELETE journal, self-contained)
└── actions\                 <- only when the shard tree was included (Backup.IncludeShards / request)
    └── ...                  <- copy of %ProgramData%\RdpAudit\actions
```

Two snapshots taken inside the same UTC second get a bounded collision suffix
(`20260914-103045-01`); the earlier snapshot is never overwritten.

The `Backups` folder is shared with the pre-existing **settings** snapshots
(`docs/30-configurator.md`), which use `appsettings.json` + `metadata.json` in a snapshot directory of
the same shape. One snapshot directory may therefore describe both scopes. Database retention never
deletes a directory that carries the settings scope - see §5.

### The mechanism, and why

The copy uses the **SQLite online backup API** (`SqliteConnection.BackupDatabase` over
`sqlite3_backup_*`), not `VACUUM INTO`:

* **Consistency under an active writer.** The pages are copied inside a read transaction on the
  source. If the live writer commits while the copy runs, SQLite **restarts the copy from the
  beginning**, so the artifact is always a transactionally consistent image of one committed state -
  never a mixture of two. That restart-on-write behaviour is the property this feature depends on and
  the reason the backup API was chosen.
* **Committed WAL content is included.** The copy reads through the write-ahead log, so rows that
  were acknowledged but not yet checkpointed are in the snapshot. No checkpoint is forced on the live
  database and no writer is paused.
* **Cost.** The destination needs room for one database image and the work is a page copy, not a
  defragmentation rewrite.

`VACUUM INTO` was rejected: it produces a defragmented rewrite (more I/O and more transient space for
the same recovery value), it requires the destination file not to pre-exist, and it documents no
writer-restart guarantee. A **full `VACUUM` on the live database is never issued** by this feature.

After the copy the snapshot is normalised to `journal_mode = DELETE`, so it is a single self-contained
file that any tool can open read-only - including the verifier on a machine where it cannot write.
The snapshot is assembled in a sibling `<timestamp>.partial` directory and only renamed into its final
name **after the manifest is durable**. A directory that exists is therefore a snapshot that completed.

### The manifest

`manifest.json` (`DatabaseBackupManifest`, schema version 1) records:

| Field | Meaning |
|---|---|
| `manifestVersion` | Manifest schema version. A reader refuses any other version. |
| `kind` | `Manual` (operator/IPC) or `PreMigration` (taken by the schema initializer). |
| `createdUtc` | When the snapshot was taken. |
| `databasePath` | Absolute path of the live database that was copied. |
| `databaseBytes` / `databaseSha256` | Size and SHA-256 of the copy. |
| `lastAppliedMigration` / `appliedMigrationCount` | EF schema state at the moment of the copy. |
| `productVersion` | Build that produced the snapshot. |
| `shardsIncluded` / `shardsDirectory` / `shardFileCount` / `shardBytes` | Shard-tree scope, when copied. |
| `rowCounts` | Row counts of the key evidence tables **inside the snapshot**. A table that does not exist in that schema is absent rather than reported as zero, so "empty" stays distinguishable from "not counted". |

A manifest that is empty, malformed, of another schema version, or missing the creation instant and
the SHA-256 is reported as **unreadable** and refused; it is never partially interpreted.

### What a snapshot is not

* The shard-tree copy (`IncludeShards`) is a **best-effort file copy**, not a transactional snapshot:
  shards are appended by the live service while the copy runs, so a shard written during the copy can
  be captured truncated. The database in the same snapshot is transactionally consistent. Re-check the
  shard tree after restoring a pair.
* A snapshot is not encrypted. Encryption at rest is a separate workstream and is not part of this
  feature; protect the backup root with the same ACLs as the store itself.

---

## 2. Creating a snapshot

Three ways, all producing the same artifact:

| Trigger | When | Kind |
|---|---|---|
| Schema initializer | Automatically, before pending EF migrations are applied | `PreMigration` |
| `CreateDatabaseBackup` (IPC 85) | Operator action | `Manual` |

Creating is refused, with the reason and no artifact, when:

* there is **no database file yet** (a store that was never created holds no evidence);
* the destination volume cannot hold the copy plus `Backup.MinFreeDiskBytesBeforeBackup`;
* the backup root cannot be created (unwritable path, a file where a directory is expected);
* the copy fails its `PRAGMA quick_check` - the working directory is discarded, never published.

Free space is checked **before** the first byte is written, because failing halfway through a
multi-gigabyte copy leaves a full disk and a slow failure instead of a clear message.

---

## 3. Verifying a snapshot

`VerifyDatabaseBackup` (IPC 87) and `DatabaseSnapshotVerifier` run the same checks, in this order:

1. the snapshot directory exists and its name is a snapshot timestamp;
2. `manifest.json` is present and parses as a manifest of a version this build writes;
3. `db\rdpaudit.db` exists;
4. its **SHA-256 equals the digest recorded at snapshot time**;
5. `PRAGMA quick_check` on the copy reports `ok`;
6. the copy's `__EFMigrationsHistory` is compared with the migrations of the running binaries.

Each failure is its own verdict, because the operator's next action differs:

| Verdict | Meaning |
|---|---|
| `Ok` | Every check passed; the snapshot may be restored. |
| `SnapshotMissing` | No such snapshot (or the directory name is not a snapshot name). |
| `ManifestUnreadable` | The manifest is missing, malformed or of a foreign schema version. |
| `DatabaseMissing` | The manifest is readable but the database copy is gone. |
| `HashMismatch` | The copy was modified or damaged after it was taken; both digests are reported. |
| `QuickCheckFailed` | The copy is structurally unsound. |
| `SchemaIncompatible` | The copy is sound but its schema is **ahead of** the running binaries, so restoring it would be a downgrade. |
| `Unreadable` | The copy could not be opened at all. |

Verification is strictly read-only: the copy is opened read-only, and nothing under the snapshot is
written, moved or deleted.

---

## 4. Restoring

### Into a scratch directory (safe, no service stop)

`DatabaseBackupService.RestoreToDirectoryAsync` verifies the snapshot first and refuses to write a
single byte when it does not pass. It then copies the database (and the shard tree, when the snapshot
carries one) into the target directory through a staging file that is moved into place, so a
half-written target is never visible under the final name. The live store is not touched: point the
service at the restored copy, or inspect it, at your convenience.

### Over the live store (service stopped)

`DatabaseRestoreService` (Configurator service layer, no WinForms) performs the in-place restore. It
needs the Windows service stopped, and refuses to continue when it is still running:

1. verify the snapshot (including the schema check against the installed binaries - a snapshot from a
   newer build is refused, because the service would refuse to start against it anyway);
2. stop the service;
3. rename the live `rdpaudit.db` and its `-wal` / `-shm` sidecars to
   `rdpaudit.db.<yyyyMMdd-HHmmss>.bak` (the same convention the guided database reset uses);
4. copy the snapshot database onto the freed name;
5. write a restore receipt (`<pre-state>.bak.restore.json`: operator identity, snapshot, digest,
   verdict, target, pre-state path);
6. start the service.

Every step before the copy is reversible: if a sidecar cannot be moved aside the restore aborts and
the original database name is restored, and if the copy fails the pre-state database is put back. A
WAL left behind next to a replaced database is how a restore corrupts the store it was meant to
recover, so that case is treated as fatal rather than tolerated.

The receipt is the audit record: a restore replaces the very database that would normally hold the
`OperationLog` row.

### After a restore

* The restored database is a clean pre- or post-upgrade state; the service migrates it forward on the
  next start if its schema is behind the binaries.
* `PRAGMA quick_check` on the restored file, and compare its row counts with the manifest - that is
  the restore drill.
* Delete the `.bak` pre-state file only once the restored store has been verified in use. It is a real
  database file: an accidental `rdpaudit.db.*.bak` in the store directory will be picked up by nothing
  (the service reads `rdpaudit.db`), and no backup retention ever deletes it.

---

## 5. Retention

`Backup.RetentionCopies` (default 5) bounds how many **database** snapshots are kept. After a
successful snapshot the retention walks the backup root newest first and removes the oldest database
snapshots beyond the limit.

Retention is deliberately narrow:

* only directories whose name is a snapshot timestamp **and** that carry a readable database manifest
  (or a `db\rdpaudit.db`) are candidates;
* a directory that also carries the **settings** scope (`metadata.json` or `appsettings.json`) is never
  deleted - the settings feature owns its lifecycle - and the report says it was skipped and why;
* `rdpaudit.db.*.bak` files are never touched: retention removes directories only;
* abandoned `<timestamp>.partial` working directories older than one hour are removed, because they
  can only come from a snapshot that was interrupted before it was published;
* every removal and every skip is reported in the result (`RetentionDeleted` / `RetentionSkipped`) and
  logged.

Retention never runs when the snapshot itself was refused or failed.

---

## 5a. UI access (stage 3)

The Configurator `Database` tab (`Forms/DatabasePage.cs`) is the operator surface for everything above:

| UI action | IPC | Notes |
|---|---|---|
| `Create snapshot` | 85 `CreateDatabaseBackup` | With an optional best-effort shard-tree copy (checkbox with a tooltip stating the truncation risk). Shows the resulting path, size, SHA-256, the snapshot-count delta and what retention removed or skipped. |
| Snapshot grid + `Refresh list` | 86 `ListDatabaseBackups` | Created (UTC), name, database size, snapshot size, manifest validity, kind, shard scope, product version, last applied migration. An invalid manifest is shown as invalid with its reason, never as a missing snapshot. |
| `Verify selected` | 87 `VerifyDatabaseBackup` | Renders the verdict, both digests and the `quick_check` outcome. |
| `Restore to folder…` | 90 `RestoreDatabaseBackupToDirectory` | The safe restore: the snapshot is verified server-side and a failed verification writes nothing; the copy lands in the folder the operator picked and the live store is untouched. Audited with the invoking identity. |
| `Restore over live database…` | none - `DatabaseRestoreService` | Elevation + confirmation + typed phrase `RESTORE OVER LIVE DATABASE`. Runs the stop/snapshot-aside/swap/start sequence from §4 and reports the pre-state `.bak` path; after a success the operator is offered a verification of the snapshot that was used. |
| Danger Zone: `Back up and reset database…` | none - `DatabaseResetService` | DEBUG mode + elevation + confirmation + typed phrase `RESET RDP AUDIT DATABASE`. Without a migration-failure marker the page says the scenario does not apply instead of resetting a healthy store. |
| Maintenance: `quick_check`, `integrity_check`, `foreign_key_check`, WAL checkpoints, `incremental_vacuum`, `optimize` | 89 `RunDatabaseMaintenance` | Read-safe. Progress and a monospace report per action. |

### Why there is no `VACUUM` button

A full `VACUUM` rewrites the entire database file and holds the SQLite writer for the duration of that
rewrite - minutes on a multi-gigabyte evidence store - which the no-freeze rule forbids on a live
database. The maintenance surface therefore has **no full-VACUUM member at all** (`DatabaseMaintenanceKind`
does not define one, and the request validator refuses every value outside the defined set), and the
Configurator offers no such button; its tooltip points here. Space that deletions already released is
reclaimed with the bounded `PRAGMA incremental_vacuum` action instead, and the snapshot itself is taken
through the SQLite online backup API (§1), which never issues a VACUUM either.

## 6. Mandatory pre-migration snapshot

`AuditDbInitializer` takes **one** snapshot per migration session - immediately before the first
pending migration, not one per migration - through the same engine described above. The snapshot is
restorable to exactly the pre-upgrade schema, and its manifest records that state.

If that snapshot cannot be taken, **no migration is attempted**:

* a recovery marker (`migration-failure.marker.json`, `failureKind: PreMigrationBackupFailed`) is
  written next to the database, carrying the reason, the directory the snapshot was expected in, the
  database path and operator guidance;
* the initializer throws `DatabaseInitializationBlockedException`;
* `DatabaseInitializationWorker` stops the host cleanly with exit code **20260815**
  (see `docs/20-service.md`).

The store stays at its pre-migration schema. The operator fixes the cause (free space, or a writable
`Backup.BackupDirectory`) and starts the service again. The documented escape hatch is
`Backup.PreMigrationBackupEnabled: false`, which migrates without a rollback point and logs a warning
saying so.

**One exception:** a brand new installation has no database file yet, so there is no pre-migration
state to preserve and no snapshot is attempted. Requiring one there would make a fresh install unable
to start. Once the file exists, every later migration is covered.

---

## 7. Downgrade guard

Before anything else touches the schema, `AuditDbInitializer` compares the migrations recorded in
`__EFMigrationsHistory` with the migrations the running binaries define (the pure
`SchemaCompatibility.Evaluate`; see `docs/20-service.md` for the startup contract).

| Situation | Verdict | Behaviour |
|---|---|---|
| No history table, or an empty history | `Compatible` | Normal start; a new database is not an error. |
| Every applied migration is known | `Compatible` | Normal start; pending migrations are applied. |
| At least one applied migration is unknown | `DatabaseAheadOfBinaries` | **Refused**: marker + exit code 20260816. |
| History holds an entry that cannot be a migration id | `HistoryInvalid` | **Refused**: marker + exit code 20260816. |
| History could not be read at all | `HistoryUnavailable` | Logged as a warning; the start continues and any real schema problem surfaces when the database is used. |

An older binary never silently opens a newer store: downgrading the binaries while keeping the
upgraded database is not supported. The refusal message names the unknown migrations and the recovery
paths: install the matching build, restore the snapshot taken before the upgrade, or let the
Configurator back the database up and start from a fresh one.

**This guard is always on.** It is the one behaviour in this feature that does not depend on any
option, by design: a silent downgrade is exactly the failure it exists to prevent. Everything else in
this page is inert until `Backup.Enabled` or the automatic pre-migration snapshot applies.

---

## 8. Rollback of this feature

| Change | How to roll back |
|---|---|
| `Backups\<timestamp>\` snapshots | Delete the directories. Nothing in the service reads them; the live store does not reference them. |
| `Backup.PreMigrationBackupEnabled: true` (default) | Set it to `false` to migrate without taking a snapshot (you lose the rollback point for the upgrade). |
| `Backup.Enabled` / `RetentionCopies` | Set `Enabled: false`; retention only runs after a successful snapshot, so nothing is deleted once the surface is off. |
| A snapshot restored over the live store | Stop the service, delete `rdpaudit.db`, rename `rdpaudit.db.<stamp>.bak` back to `rdpaudit.db`, delete any `-wal`/`-shm`, start the service. The restore receipt names the pre-state file. |
| This feature's code | It is additive: no existing ordinal, contract or default changed except the two always-on/documented ones (downgrade guard, pre-migration snapshot). Removing the `CreateDatabaseBackup`/`ListDatabaseBackups`/`VerifyDatabaseBackup` handlers leaves every earlier command untouched. |

---

## 9. Operator-visible summary

* A snapshot is **not** an export and **not** a settings backup: it is the evidence store itself,
  with a digest and a manifest.
* `Backup.Enabled: false` (the default) means *no automatic backup folder grows and the snapshot
  commands refuse to run* - it does **not** disable the pre-migration snapshot or the downgrade guard.
* With the defaults, the first thing an operator sees is one `Backups\<timestamp>` directory after the
  first schema upgrade. That directory is the rollback point for that upgrade.
* Nothing in this feature deletes a settings snapshot, a shadow-policy snapshot or a
  `rdpaudit.db.*.bak` file.

## Offline compaction — the only operation that shrinks the file

The online purge path deliberately runs **no** full `VACUUM`. A `VACUUM` rebuilds the entire database
inside a single write transaction, so on a multi-gigabyte evidence store it can hold the single SQLite
writer for minutes and stall ingestion — the freeze the no-freeze rule forbids. What the online path does
instead, after its delete transaction commits, is exactly two bounded steps:

1. `PRAGMA wal_checkpoint(TRUNCATE)` — moves committed frames into the main file and empties the `-wal`
   sidecar.
2. `PRAGMA incremental_vacuum(5000)` — hands already-freed pages back to the filesystem, without
   rewriting the file. The page budget is the same ceiling the maintenance surface uses, so the reclaim
   step can never hold the writer longer than a maintenance pass the operator already accepts.

The incremental vacuum only releases anything when the store's auto-vacuum mode is `INCREMENTAL`. Stores
this build creates are: `SqlitePragmaInterceptor` applies `PRAGMA auto_vacuum = INCREMENTAL` **before**
`journal_mode = WAL` on every connection, and SQLite honours the mode only while a store still has no pages
— `journal_mode = WAL` is the statement that creates page 1 (B27; `AutoVacuumModeTests` pins both halves).
On a store created by an older build, or in any other mode, the statement is a documented no-op and the
freed space stays inside the file until that store is rewritten offline. The purge report therefore never
claims the file shrank: it reports the freelist depth before and after, the pages actually released
(derived from those two readings, **not** from the statement's result set — `PRAGMA incremental_vacuum(N)`
returns no rows at all whether it released nothing or thousands of pages, unlike `wal_checkpoint`, which
returns one), and — when nothing was released — states that the store is not in incremental auto-vacuum
mode and that an offline compaction is the only way to shrink it.

The Database tab's **Overview** reports the same two facts for the store as it stands: the `auto_vacuum`
mode, the page accounting (`page_size`, `page_count`, `freelist_count`, and `page_size × freelist_count`
reclaimable bytes — a lower bound, not a promise) and one sentence that says whether online release is
possible on that store and, when it is not, that only the offline rewrite returns the space.

The operation that *does* shrink the file is the Configurator's **Database ▸ Danger Zone ▸
`Compact database (offline)…`** (`DatabaseCompactService`), which requires the service to be stopped:

1. stop the service and refuse if it is still running;
2. `PRAGMA wal_checkpoint(TRUNCATE)` so every committed frame is part of the copy;
3. `VACUUM INTO` a copy next to the store — the live file is only read;
4. **normalise the copy's auto-vacuum mode to `INCREMENTAL`.** `VACUUM INTO` carries the source's mode over
   (measured: a copy of a mode-NONE store is itself mode NONE), so without this step a legacy store would be
   compacted straight back into the very mode whose online reclamation is a no-op, and the next purge would
   release nothing again. The copy is rewritten with `PRAGMA auto_vacuum = INCREMENTAL; VACUUM;` on one
   connection. Cost, measured on SQLite 3.41.2: one full `VACUUM` over the *already compacted* copy — 0.66 s
   on a 57 MB store, file size unchanged within 0.1% — plus room for a second copy of it, so the step
   demands at least twice the copy's size free on the volume and refuses below that, naming both numbers. A
   copy that still does not report `INCREMENTAL` afterwards refuses the swap: swapping in a store whose mode
   contradicts the report would defeat the purpose of the pass. A copy that already carries `INCREMENTAL`
   (the normal case for a store this build created) is not rewritten at all, and the log says so;
5. verify the copy: `PRAGMA quick_check`, the applied migration list, the per-table row counts against the
   source, and `PRAGMA foreign_key_check`. This runs **after** step 4, so it proves the file that is about
   to be swapped in. **Any** mismatch refuses the swap and leaves the store untouched, because the purpose
   of the operation is to shrink the file and never to change what is in it — the auto-vacuum mode is the
   one header setting this operation changes deliberately, and no evidence row depends on it;
6. swap the copy in atomically through `LiveDatabaseSwap` — the same rename/sidecar/staging mechanics the
   restore path uses, so the two operations cannot drift apart — keeping the pre-compaction file as a
   timestamped `.bak` plus a `.compact.json` receipt;
7. restart the service.

The report names the mode the store reported before the operation and the mode of the file that replaced it,
and the `.compact.json` receipt records both (`autoVacuumModeBefore` / `autoVacuumModeAfter`), so an
operator can verify on disk that a legacy store really left mode `NONE` instead of taking the log's word for
it. A store whose mode cannot be read is reported as `unknown` rather than guessed.

The Configurator opens no pooled connection in this path: a pooled handle would keep a lock on the file it
is about to rename.

`CompactDatabase` (IPC ordinal 93) exists so that a client asking the *running* service to compact the
store receives that explanation instead of either a silent no-op or, far worse, a full VACUUM inside the
service. It always answers `Refused` and reports the store's page accounting (page size, page count,
freelist depth, `page_size × freelist_count` reclaimable bytes) **plus its `auto_vacuum` mode** — the mode
is what tells the operator whether an offline pass is merely worth stopping the service for or the only way
this store will ever release free pages. See `docs/50-ipc.md`.

## After a restore

Every restore runs `PRAGMA foreign_key_check` against the restored file before the service is restarted,
and the outcome is written into the restore receipt. A snapshot can be byte-consistent and still carry
rows whose parents were removed by the peer that produced it, and a referential violation is fixable
while the service is still stopped.

### A restore is an observed offline change, by design

Restoring an older snapshot changes the store while the service is stopped, which is exactly what the
offline-tamper detector watches for. Expect the next start to report it, and read that as the feature
working rather than as an alarm about an attack:

* the ledger can be shorter than the baseline recorded at the last clean shutdown (`LedgerShrank`);
* per-table row counts can fall (`RowsRemovedWhileStopped`);
* the database file's last-write time is newer than the baseline (`DatabaseModifiedOffline`).

The detail text on each of those observations names a restore as the benign explanation. The
**fingerprint chain** itself is not damaged by a restore: it is the baseline, and the restore adds a record
whose state differs from it. What the chain *does* report is deliberate interference with the chain files
themselves — a deleted record (`Missing`), an edited or re-ordered one (`ChainBroken`) or an unreadable
record or sealed tip (`Unreadable`). A captured record that was cut short between being appended and the tip
being re-sealed is reported as `Interrupted` instead of `ChainBroken`: a restore is not the only thing that
stops a service abruptly. The chain, its five states and its honesty limits are documented in
`docs/41-data-model.md` under "Store fingerprint (a file chain, not a table)".
