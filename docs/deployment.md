# Production deployment and upgrade acceptance

Porter owns one bbolt database from one process. Use a single replica and a
persistent writable data mount. The production image runs as UID/GID 65532,
contains only the application and distroless runtime, and supports a read-only
root filesystem with all Linux capabilities dropped. Its data directory remains
writable; no shell or HTTP client is required inside the image.

## Deploy

Use `examples/compose.yml` with an immutable image digest. Set `PORTER_IMAGE`,
`PORTER_CONFIG_FILE`, and `PORTER_DATA_DIR` in the Compose environment. These
variables configure Compose mounts and image selection, not Porter configuration.
Create the host data directory owned by UID/GID 65532 with mode 0700. Give the
configuration file UID/GID 65532 and mode 0600 so the container can read it, then
mount it read-only. Do not commit a populated private configuration.

Set `listen` to `:8083`, `database` to `/data/porter.db`, and
`operations.audit_file` to `/data/porter-audit.jsonl` in the JSON configuration.
Set the public URL to the HTTPS origin served by the trusted reverse proxy and
configure administrator-verified bindings. Use the Nginx example's private auth
subrequest, header replacement, credential stripping, and identity output rules.
The Compose example publishes only the public listener on host loopback. Terminate
TLS at the trusted proxy. It does not publish the management port.

Keep management on container loopback when it has no key. If a separate monitoring
network needs access, explicitly bind management to a private container interface
and set a distinct management key. Restrict network reachability and protect HTTP
credentials with a trusted private network or TLS proxy. Do not route management
endpoints through the public application proxy. Distroless has no shell; use an
external probe from an authorized monitoring peer rather than an in-container
shell healthcheck.

Before serving traffic, run the image's `version --json`, `check-config`, and
`doctor` commands with the same mounts and identity as the service. Add
`doctor --network` only when a credential-free Stargate readiness probe is wanted.
Probe the management `/readyz` externally and validate the Nginx trust boundary.
Readiness does not prove platform credentials or Stargate authorization mappings.

## Upgrade and rollback

1. Record the running image digest and build metadata. Keep a copy of the exact
   private configuration outside source control. Reserve time for a single-process
   stop/start; two Porter instances must not open the same database concurrently.
2. Stop Porter gracefully, allowing at least 20 seconds before forced termination.
   Once the process has exited, take a consistent backup of the database and retain
   the audit journal with their private permissions. Do not copy a live bbolt file
   as an ordinary filesystem backup.
3. Start the candidate digest with the same database, keys, bindings, public URL,
   and data ownership. These P0 enhancements introduce no session schema migration.
   Check readiness and verify an existing session before returning traffic.
4. Verify logout, a subsequent restart, and the rejection of revoked/expired
   sessions. Review audit loss counters and the journal's final flushed records.
5. To roll back this compatible release, stop the candidate and start the previous
   digest against the **current** database and unchanged configuration. Do not
   restore the pre-upgrade snapshot during a routine rollback: it predates logout
   and binding revocations performed after the upgrade. Backup recovery is a
   separate operation requiring an explicit session invalidation plan.

Keep owner-only audit permissions during retention and rotation. The writer holds
an open descriptor: rotate externally and restart to open a new journal. Changing
an identity binding intentionally invalidates affected sessions; restoring an old
binding does not restore their revoked login families.

## Repeatable production acceptance

Run from a checkout with Docker available:

```sh
python3 tests/production.py
```

The test pins the baseline to merged PR #2 (`bdf69d4600cba5cf55b8df65247e7f4ea1f5899d`).
It builds the real baseline production image and compiles test-only fixtures
against both the baseline and candidate store/config packages. The baseline
fixture writes synthetic sessions, revoked and expired records, and pending
one-use login transactions. Neither helper is copied into the production image. The candidate is built from the
current source tree with version, commit, and build date metadata.

The suite starts the baseline, upgrades to the candidate, restarts it, and rolls
back to the baseline against the same isolated volume. It checks existing-session
identity, logout persistence, expired/revoked rejection, unchanged absolute expiry,
pending transaction contents and one-use consumption by both implementations,
live session expiry without a restart, binding reconciliation, private audit
permissions and flush, startup rejection of read-only data volumes and unsafe
audit files, log/audit redaction, management key isolation,
public management-route rejection, and fail-closed `/auth` in identity-only mode.
It uses a read-only root filesystem, no capabilities, no-new-privileges, the
production image's default non-root user, and loopback-only published test ports.
Configuration uses a separate read-only volume with no writable alias in the
service container. Temporary containers, volumes, and image tags are removed
after the run.

To validate another candidate checkout without changing the baseline:

```sh
python3 tests/production.py --candidate-context /absolute/path/to/porter
```

A different baseline can be selected with `--baseline <commit>`; it must provide
compatible fixture APIs. CI fetches full history and runs the pinned baseline on
pull requests and main pushes. The suite builds images for the local Docker
architecture; cross-architecture packaging is not covered. No real provider
credentials or live Stargate deployment are involved. Provider protocol, Chrome,
and Nginx trust-boundary tests remain separate required checks.
