# Offline audit retention and recovery

Porter's audit-kit worker remains bounded and best effort. The runtime writes to
one validated file descriptor; it does not watch path changes or rotate files.
The helper in `tools/audit-retention.py` is an offline operator tool, not a service
endpoint or background worker. It only inspects file metadata; it never reads
journal contents or opens the session database for writing.

## Plan, stop, apply, restart

Use an owner-only data directory and owner-only regular database/journal files.
Run the helper as the service user or a trusted administrator able to preserve
its UID/GID. Keep the default 30-day policy only if it matches the deployment's
retention requirements; set `--keep-days` explicitly for the chosen policy.

```sh
set -e
python3 tools/audit-retention.py --directory /var/lib/porter --rotate --keep-days 30
docker compose -f examples/compose.yml stop porter
python3 tools/audit-retention.py --directory /var/lib/porter --rotate --keep-days 30 --apply --stopped
docker compose -f examples/compose.yml up -d porter
```

The first command is a metadata-only dry run. Check that the stop actually
completed before applying changes. `--stopped` is an operator acknowledgement,
not process detection or a lock. The helper cannot inspect another container's
open descriptors. Never run it concurrently with Porter or another retention
process. Do not use `copytruncate`, live file replacement, or a second writer.
All examples assume the same Compose environment and persistent data directory
as the deployment. Use `--journal` and `--database` for different basenames.

Applied rotation creates a timestamped archive without overwriting an existing
archive, creates an empty mode-0600 journal with the original UID/GID, and then
removes expired archives. Only exact `<journal>.YYYYMMDDTHHMMSSffffffZ` names
created by this convention are eligible. Age comes from the UTC archive name,
not modified time. The current journal, database, and unrelated files are never
retention candidates. Symlinks, database aliases, active-journal aliases,
non-private files and ownership mismatches are rejected before deletion.

The helper restores the old journal if creating the new private file fails and
the path is still available. If another writer has claimed the path or a later
operation fails, leave the service stopped and inspect the files manually; an
error does not mean every earlier action was rolled back. The original archive
is preserved when restoration cannot be completed. This is not a transactional
or power-loss-durable rotation protocol. Backups and off-host audit exports are
separate infrastructure operations.

After restart, verify the private management readiness endpoint, the new file's
permissions/ownership, and fresh records from a normal login start or logout.
Verify an existing session still works. Check `porter_audit_dropped_total` and
`porter_audit_write_failures_total`. Do not restore an old session database to
repair the audit destination: doing so may revive sessions revoked after that
snapshot. Roll back application versions against the current database as in
`deployment.md`.

## Storage failures

For a queue drop, inspect write throughput and queue pressure. For write failures,
inspect permissions, mount access, free space and backing storage before changing
queue size. Audit errors do not fail authentication or readiness. Counters report
loss; they do not contain the missing records. Preserve existing journals and
report the affected interval rather than claiming a complete audit history.
Runtime logs intentionally omit raw storage errors and request secrets. Repair
using private host-level diagnostics; do not add raw paths, contacts or tokens to
public metrics or alerts.

Run `python3 -m unittest discover -s tests/audit -v` for dry-run, retention,
collision, alias, permissions and restoration checks. The Go operations tests
verify that restart writes into the new journal, keeps the old archive intact,
and preserves session deadlines. Existing audit saturation/write-failure and
production upgrade tests remain required.
