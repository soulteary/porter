# Startup configuration and mounted secrets

Porter accepts the existing inline JSON keys and optional file sources:

- `proxy_key_file` instead of `proxy_key`;
- `stargate_secret_file` instead of `stargate_secret`;
- `operations.key_file` instead of `operations.key`;
- `providers.<name>.client_secret_file` instead of `client_secret` for GitHub,
  Google, WeChat and QQ.

Omit the inline field when using its file source. A non-empty inline value and
non-empty file source are mutually exclusive and produce a validation error,
not a fallback. Existing inline-only configurations remain valid. Provider client
IDs, namespaces, bindings, contacts, public origins and session settings retain
their current validation. The resolved management key must still differ from
proxy and Stargate credentials. File sources do not introduce key sharing or a
multiple-key grace period.

Paths are resolved relative to the selected JSON file, or used as absolute paths.
Files are read once at startup through the same `config.Load` path used by
`serve`, `check-config` and `doctor`. Failed file reads, permissions and content
validation stop startup before session storage or audit initialization. Diagnostics
name the affected configuration field, not the configured path, OS error or
secret. No command prints a resolved configuration.

## Files and mounts

Each file must be a readable regular UTF-8 file containing a single secret, with
at most 8192 bytes including a terminal line ending. Porter removes exactly one
LF or CRLF ending. It does not trim surrounding spaces or accept additional
lines. Existing secret validation remains in force; for example proxy, management
and Stargate credentials still need at least 32 characters.

Supported modes are 0400/0600 and 0440/0640. Group read is for a dedicated service
fsGroup; group write, all access by other users, and executable bits are rejected.
The operating system must allow the service UID/GID to read the file. Projected
Secret symlinks are supported: Porter opens the configured path once and checks
the descriptor it actually reads. FIFOs, directories and oversized files are
rejected. Mount the containing Secret directory read-only, separate from the
writable database/audit directory. No credential values belong in command-line
arguments, image layers, environment variables, logs or checked-in files.

`examples/porter.secrets.example.json` contains references only. For a container,
mount private files at `/run/secrets`, readable by UID/GID 65532 or the dedicated
service group. With projected mounts use a compatible defaultMode/fsGroup rather
than world-readable defaults. Mounting the directory permits the platform to
replace symlink targets; such replacement takes effect only on the next Porter
start. The service does not watch or reload files in a running process.

## Configuration source precedence

cli-kit resolves the JSON path in this order:

1. Explicit `-config` / `--config`.
2. Non-empty `PORTER_CONFIG_FILE`.
3. `porter.json`.

The container default command already includes `-config /etc/porter/porter.json`.
To select the file through `PORTER_CONFIG_FILE`, override that command with
`serve` so an explicit image flag does not take precedence.

No other environment variables override JSON fields or secret contents. The
existing `porter -config ...` invocation still works. `version` and `--version`
ignore configuration and secret sources entirely. `check-config` reads files and
validates the resolved values but creates no database, audit writer or listener.
`doctor` retains its temporary directory probes and optional credential-free
Stargate readiness check; it does not initialize runtime storage.

cli-kit's path-resolution helper is reused with whitespace trimming disabled.
Its password-file helper is not used: that helper reads without Porter's size
bound and trims all whitespace, which would change secret semantics.

## Rollout and rollback

First deploy the same credential values through files and verify `check-config`
and `doctor` using the service mounts and identity. Stop/start the single process
and verify an existing session, management scrape, and Stargate authorization.
Changing the source representation does not change binding revisions, session
records, absolute deadlines, or revocation state. No database migration is needed.

To change a key value, coordinate the consuming proxy/Stargate/monitoring
configuration and restart Porter; the running process continues using the value
it loaded. Old proxy credentials are rejected after restart, while an otherwise
valid session remains valid with the new proxy credential. Session logout and
binding revocations remain effective across restarts. Rotating a provider secret
still requires the platform's own application configuration and does not change
the provider client namespace.

Before rolling back to a binary without file-source support, select a preserved
private inline configuration with equivalent values and remove unsupported
`*_file` fields. Do not restore an older database. Keep the mounted-secret and
configuration backups under the same private operational controls as other
credentials. See `deployment.md` for compatible binary rollback and revocation
preservation.
