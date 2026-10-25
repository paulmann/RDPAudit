# 89 — Encryption at rest: decision record

Status: **decision taken, implementation deferred. No data is encrypted in this iteration.**
Requirements: R25, Addendum B §S1. Related: `docs/88-database-backup-and-restore.md` (backup and restore
of the store and the shard tree), `docs/41-data-model.md` (what the store contains), `docs/40-options.md`
(`Storage:Encryption`).

## 1. What the problem actually is

The evidence store holds, as plain files under `%ProgramData%\RdpAudit`:

* `rdpaudit.db` (+ `-wal`, `-shm`) — every raw event, every authentication attempt and its outcome, every
  RDP connection fact, every session/IP correlation, the alert history and the addresses observed;
* `actions\*.rdpshard` — the per-source event shards;
* `Backups\<timestamp>\` — full copies of the above, including the pre-migration snapshots.

Today the only encrypted material in the product is the secret store (API keys, tokens) through
`DpapiSecretProtector` / `ProtectedEnvelope`, plus per-file integrity digests in backup manifests. The
store itself is protected by NTFS ACLs and by the fact that the volume is normally BitLocker-protected —
which is an **operator assertion the product cannot verify**.

The threat this addresses is therefore narrow and specific: **an attacker or a curious insider who has
read access to the files but not to the running service.** Full admin compromise of the host is not in
scope for any option below, because every key that the service can read unattended can be read by an
attacker with the same rights.

## 2. Options

| Option | What it protects | What it does not | Write cost | Ops cost | Key handling |
|---|---|---|---|---|---|
| **A. Status quo (ACLs only)** | Nothing against file-level read | Everything: a copied `.db` is readable anywhere | None | None | None |
| **B. Volume-managed (BitLocker / hardware-encrypted volume)** | A stolen disk, an offline image, a volume mounted read-only outside the OS | A live host: everything is transparently readable while the volume is unlocked. Nothing about the shard tree as separate protection — it lives on the same volume | Measured near zero for SQLite WAL workloads; the OS encrypts blocks | Volume encryption must be provisioned, escrowed and recovered; the product cannot confirm it did | OS-managed (TPM/PIN/startup key). No key material in the product |
| **C. SQLCipher (page-level, SQLite keyed)** | A copied `.db`, a copied `-wal`/`-shm`: unreadable without the key. Protection travels with the file | The shard tree (`actions\*.rdpshard`) — a separate format that SQLCipher does not touch — and `Backups\` copies of the shards | Real and non-trivial: every page read and write goes through AES; expect a measurable throughput cost on the ingest path and a larger WAL churn. Numbers must be measured on a ≥1 GB fixture before this is enabled, not assumed | Key provisioning, rotation, escrow, and a **hard recovery question**: without the key the store is unrecoverable, and losing it destroys the evidence | Product-managed: key generated once, wrapped by `ISecretProtector` (DPAPI machine scope today, TPM-backed later), never in `appsettings.json`, logs, IPC responses or diagnostics |
| **D. Both** | A copied file **and** a copied disk | Nothing on a live host | C's cost, on top of B | B's plus C's | Both; recovery requires both |

## 3. Decision

**Chosen for the current release: A + B, with C deferred and the seam in place.**

Reasoning, in order of weight:

1. **C cannot be adopted partially.** Enabling SQLCipher changes the on-disk format of the database. That
   is a migration, a restore-compatibility problem (every existing snapshot and pre-migration backup is
   plain SQLite), a key-management problem, and — most importantly — a *recovery* problem: a lost key is a
   lost audit trail, and the product must not create an unrecoverable evidence store by default.
2. **C does not protect the shards.** The per-IP shard files are a separate binary format outside SQLite.
   A configuration where the database is encrypted and the raw per-source evidence is not would be a
   half-measure that reads, in the operator's own settings file, as if the evidence were protected. Any
   SQLCipher work must be paired with a shard-format change, which the project's own rules forbid doing
   silently.
3. **B is already the operative protection in a real deployment** and costs nothing to keep. The product's
   honest contribution is to stop implying something it cannot verify: the option exists, it accepts
   `VolumeManaged`, and it warns explicitly that the volume's state is an operator assertion
   (`StorageEncryptionGuard`).
4. **What the product does do, and that does reduce exposure today**, is already shipped and independent of
   encryption: explicit storage ACLs with inheritance disabled and no `Users` ACE (`docs/88`,
   `StorageAclPolicy`), a mandatory pre-migration snapshot, a downgrade guard, `foreign_key_check` after
   restore, hash-chained deletion accounting and offline-modification detection. Those are the controls
   that keep a *running* host honest; encryption is the control for a *stolen file*.

## 4. The seam as implemented

`RdpAudit:Storage:Encryption`:

```json
"Encryption": {
  "Mode": "None",
  "KeySecretName": "",
  "KeyRotationDays": 0
}
```

* `Mode` — `None` (default, today's behaviour) | `VolumeManaged` | `SqlCipher`.
* `KeySecretName` — the **name** of the secret that would hold the database key, resolved through the
  existing `ISecretProtector` abstraction. Never the key itself: no key material may appear in
  `appsettings.json`, logs, IPC responses or diagnostics.
* `KeyRotationDays` — the intended rotation interval; unused until a mode is implemented.

Behaviour:

* `None` — nothing is asserted and nothing is encrypted.
* `VolumeManaged` — accepted, with a start-up warning stating that the product performs no encryption of
  its own and cannot verify the volume's state.
* `SqlCipher` — **refuses to start** with an actionable message. Running with plain-text files under a
  setting named "encryption" is the one failure mode this option must never have: the operator would make
  decisions on a false assurance taken from the product's own settings file. The refusal is asserted twice
  — once in `Program` before the host is built, and again in `AuditDbInitializer` immediately before the
  store would be opened — so an alternative host wiring cannot bypass it.
* Any value that is not a defined member is also refused, so a hand-edited numeric override cannot select
  "no encryption" by accident.

## 5. What an implementation of C would have to deliver

Recorded here so the next iteration starts from the decision rather than from the analysis:

1. **Key provisioning and escrow.** A key generated on first use, wrapped by `ISecretProtector` (DPAPI
   machine scope; TPM-backed when available), with a documented recovery path and a documented way to
   re-wrap on a host rebuild.
2. **Rotation.** `PRAGMA rekey` against the live store, in a maintenance window, with a pre-rekey snapshot
   and a verify-after-rekey step. Key material never logged; rotation recorded as an `OperationLog` row.
3. **Migration path for existing stores.** `sqlcipher_export` (or an equivalent) into a new file, verified
   with `quick_check` and row counts against the source, then the same atomic swap the restore and
   compaction already use (`LiveDatabaseSwap`). The plain-text original is retained as the operator's
   undo until they delete it.
4. **Shard-tree decision.** Either a documented "the shards stay plain and why", or a format-versioned
   encrypted shard layout with a reader that still accepts the previous version (the project's rule for
   any shard-format change).
5. **Backup and restore compatibility.** A snapshot of an encrypted store is encrypted; the manifest must
   record the encryption mode and version so a restore into a build without the key fails loudly instead
   of producing a store that cannot be opened. Pre-migration snapshots of plain stores must remain
   restorable.
6. **Measured cost.** Retention-pass and ingest throughput on a ≥1 GB fixture, with and without the mode,
   reported as numbers rather than as "acceptable".
7. **A decision on the default.** Encrypting by default changes every existing installation's format; the
   recommendation to state explicitly is whether `SqlCipher` is opt-in forever or becomes the default for
   new installs.

## 6. Operational consequence of this decision (operator-visible)

* Nothing changes by default: an existing installation keeps plain-text files and behaves exactly as before.
* Setting `Mode=VolumeManaged` produces a start-up warning that the volume's state is unverified; the
  Database tab's overview reports the mode it is running under (`EncryptionMode`) so the effective setting
  is visible next to the store's size and retention state.
* Setting `Mode=SqlCipher` on a build that does not implement it stops the service with an explicit message
  naming the mode, the reason and this document. It never silently downgrades.
