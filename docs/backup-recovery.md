# Offline database backup and recovery

Recovery is different from a compatible binary rollback. Keep the **current**
database for a binary rollback. An old database snapshot can contain sessions and
pending callbacks revoked after its creation; restoring it verbatim can revive
those credentials. The separate offline recovery tool always discards all login
state before publishing a restored database. All users must log in again.

## Build and back up

Build the operator tool from a reviewed checkout. It is not included in the
production image and has no network endpoint:

```sh
go build -trimpath -o /private/operator/porter-recovery ./tools/recovery
```

Stop Porter, confirm it has exited, then run as the service user in a trusted
local filesystem. Source and destination parent directories must already exist
with owner-only permissions. Database files must be regular, owner-only files;
symlink sources and existing destinations are refused. Ancestor directories and
all path mutations must be controlled by the operator. Do not use network
filesystems, hostile shared parents, or change paths concurrently with the tool.

```sh
/private/operator/porter-recovery backup \
  --source /var/lib/porter/porter.db \
  --destination /private/backups/porter-20261110.db --stopped
```

`--stopped` records operator intent. A read-only bbolt open also holds its shared
advisory lock through the snapshot; an active Porter writer prevents backup.
The snapshot uses bbolt's transaction writer, verifies the supported bucket
structure, and is published without overwriting an existing file. The command
prints only `sha256=<digest>`. Store that digest separately in a trusted backup
inventory, with the source version, configuration revision and backup time.
A digest detects corruption; it does not authenticate a maliciously replaced
backup and inventory. Protect both, including offline encryption and off-host
storage according to the deployment's controls.

Back up the exact private configuration and mounted secrets through existing
secret-management procedures. Retain audit journals separately with their private
permissions and retention policy. This tool copies only the session database;
it does not package credentials or claim complete audit recovery. Restart the
original service and check readiness after backup.

## Restore in isolation

Stop traffic and Porter. Preserve the current database and audit evidence. Restore
into a **new, isolated** owner-only directory, using the digest from the trusted
inventory. Never restore over the live database or use a downloaded digest as the
only evidence of authenticity.

```sh
/private/operator/porter-recovery restore \
  --source /private/backups/porter-20261110.db \
  --destination /private/recovery/porter.db \
  --sha256 <trusted-64-character-sha256> --stopped
```

The source stays read-only. Restore checks its digest and database structure,
creates a private temporary copy, removes and recreates all three authentication
buckets (`sessions`, `families`, `transactions`), then atomically publishes the
new file without overwriting any existing destination. It rejects unknown bucket
schemas instead of claiming compatibility with a future release. The original
snapshot is unchanged. The resulting file belongs to the invoking user; set the
service UID/GID while Porter is stopped before deployment. No secret or record
contents, filenames or underlying OS errors are printed on failure.

Temporary writes are synced before publication and the destination directory is
synced afterward. A late filesystem error may leave the published output present;
inspect it privately and do not retry over it. This is a local POSIX operator
procedure, not a transactional backup orchestration or an automatic failover.

Validate configuration and mounts with `check-config` and `doctor` using the
service UID. Start one instance against the recovered database on an isolated
network. Verify readiness, rejection of old session cookies and pending callback
states, fresh login and persistent logout, and Stargate's existing header and
identity policy before restoring traffic. Do not connect real provider credentials
to an untrusted recovery environment. Restoring a configuration must not silently
restore obsolete identity bindings or revoked provider applications.

## Acceptance

`go test -race ./tools/recovery` exercises the actual Porter store: a snapshot
predating logout, mandatory login-state invalidation, fresh login and persistent
revocation, live-writer refusal, unchanged source, checksum mismatch, corruption,
unknown schema, unsafe paths/permissions, no overwrite and redacted diagnostics.
The regular Go workflow runs this suite; the production upgrade/rollback,
provider single-attempt exchange, browser and Nginx boundary suites remain required.
