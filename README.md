# Porter

Porter is an external identity gateway written in Go. It supports GitHub OAuth,
Google OpenID Connect, WeChat website QR login, and QQ website login.

Porter owns upstream authentication and its browser sessions. It exports a
configured internal identity to a trusted reverse proxy, or delegates authorization
to Stargate when configured. Stargate continues to
resolve trusted phone/mail headers through Warden and enforce access. Herald
retains its OTP/TOTP role. No changes to those repositories are required.

This initial implementation supports **one process and one public origin**.
Sessions and login transactions are persisted in an owner-only bbolt database.
There is no OIDC server, automatic registration, email-based account merging,
self-service binding, cross-domain session exchange, or MFA orchestration.
A successful Porter login is not a Warden authorization decision.

## Run

Go 1.27.3 or later is required.

1. Register an application with each provider you intend to enable.
2. Copy `examples/porter.example.json` to a private configuration file.
3. Set credentials, a random proxy key of at least 32 characters, and the actual
   public origin. Configure administrator-verified identity bindings.
4. Register `https://YOUR_HOST/callback/PROVIDER` as each application's callback.
5. Run `go run ./cmd/porter serve -config /path/to/porter.json` behind an HTTPS proxy.
   The existing `porter -config ...` invocation remains supported.

Only configured providers are enabled. Google discovery must succeed at startup.
Use `openssl rand -hex 32` to generate the proxy key. The example contains placeholders,
not working credentials. Do not commit the real configuration or database.

`public_url` must be an origin without a path or query. Host casing and default
ports are normalized to the browser's Origin representation. `landing_url` must share
that origin, because the session cookie is host-only. Production cookies use the
`__Host-` prefix, Secure, HttpOnly, SameSite=Lax and Path=/.
`development: true` permits loopback HTTP and uses unprefixed, non-Secure cookies;
validation requires a loopback public URL and a loopback listener (default
`127.0.0.1:8083`).

The config is loaded once. Restart to apply binding changes; existing sessions
carry a fingerprint of the exact binding. Editing or removing that binding
invalidates its sessions, and startup reconciliation deletes those sessions so a
later configuration rollback cannot revive them. Database persistence does not
extend absolute deadlines. Sessions and pending transactions from the initial
PR implementation require a new login after this storage change; no database
reset is required.

## Identity bindings

Each binding explicitly maps `(provider, namespace, subject)` to an internal
`user_id` and exactly one Warden phone or mail. The namespace is the configured
provider client ID. Subjects are opaque and case-sensitive:

| Provider | Subject | Upstream flow |
| --- | --- | --- |
| GitHub | Numeric user ID, not login name | Authorization code with S256 PKCE; authenticated `/user` lookup |
| Google | Verified ID token `sub` | OIDC authorization code with S256 PKCE and nonce |
| WeChat | Website application's `openid` | `snsapi_login` QR authorization and server-side code exchange |
| QQ | Application's `openid` | Authorization code, token exchange, `/me` with matching client ID |

Do not obtain subjects by accepting an unverified browser claim. Provision mappings
from a trusted administrative process and independently verify ownership of both
accounts. No user profile email or UnionID is used to create or merge bindings.
WeChat UnionID and QQ UnionID are intentionally not required.

The mapped phone/mail must resolve to the intended Warden account. On `/auth`,
Porter requires exactly one `X-Auth-User` and `X-Forwarded-User` from Stargate, both
matching the configured internal `user_id`. A reassigned contact, missing identity
header or ambiguous response is rejected before any authorization headers are
returned. Porter does not grant roles. `/identity` reports only the configured
identity; downstream apps must use `/auth` and Stargate's authorization headers.

## HTTP API

- `GET /login`: provider selection and logout form.
- `POST /login/{github|google|wechat|qq}`: start a login. Requires the exact public
  `Origin`; creates a five-minute browser-bound transaction. One outstanding login
  per browser is supported; starting again revokes the previous pending login.
  A 200 HTML response navigates separately to the provider, keeping external
  redirects out of the form submission's CSP scope. The login page uses
  `Referrer-Policy: same-origin` to preserve its forms' Origin header; navigation
  and callback responses retain `no-referrer`.
- `GET /callback/{provider}`: consume the transaction, authenticate upstream,
  require a configured binding, rotate the session and redirect to the fixed
  landing URL. No client-supplied return URL is accepted.
- `GET /auth`: private proxy authorization check. Requires
  `Authorization: Bearer <proxy_key>`, the browser session cookie, Stargate settings,
  and original request context: `X-Forwarded-Uri`, `X-Forwarded-Method`,
  `X-Forwarded-Host` and `X-Forwarded-Proto`. The proxy must overwrite these headers.
  Host and scheme must match `public_url`; URI must be a local request target.
  Returns only allowlisted authorization headers after a matching Stargate success.
  Returns 401 for invalid proxy credentials or missing/expired/revoked sessions,
  403 for changed bindings or a mismatched Stargate identity, and 503 for missing
  Stargate configuration, invalid request context, storage or dependency failures.
  Stargate 401/403 are preserved; redirects are rejected. It never redirects.
- `GET /identity`: private identity-only export, with the same proxy credential
  and session requirements. Returns `X-Porter-User-ID` and one configured contact.
  This endpoint does not authorize access and is not used by the Nginx example.
- `POST /logout`: exact-origin request; revoke the session and pending login
  family, including a callback already exchanging a code, and clear both cookies. It does not revoke upstream grants or sign out of the provider.
- `GET /healthz`: process liveness only, not provider or directory readiness.

All responses use `Cache-Control: no-store`. Provider errors are not reflected.
Upstream access tokens are used only within the callback request, never persisted.
State and session database keys are SHA-256 hashes of random 256-bit values.
Transactions are consumed atomically before exchange; failures require a new login.
Session creation and account switching are atomic. A revoked login family cannot
issue a session; authorization rechecks session validity after the Stargate call.
There are no automatic code-exchange retries.

## Stargate integration

See `examples/nginx.conf` for a same-origin Nginx `auth_request` arrangement:

1. Nginx checks Porter through one private subrequest, passing the session cookie
   and a proxy credential. It overwrites the original URI, method, host and scheme
   from its own request variables, including for non-GET application requests.
2. Porter validates the session and identity binding. With `stargate_url` and
   `stargate_secret` configured, it sends the configured contact and original
   request context to Stargate's
   `/_auth` endpoint, using `X-Stargate-Header-Auth` and `Accept: application/json`.
3. Stargate resolves the contact through Warden. Porter returns success only after
   Stargate succeeds, copying an explicit allowlist of authorization headers.
4. Nginx overwrites application identity headers with that result.

Enable `HEADER_AUTH_ENABLED=true`, set `HEADER_AUTH_SHARED_SECRET`, and configure
Warden on Stargate. Porter uses Stargate's default secret header
`X-Stargate-Header-Auth`. No browser cookie, password or arbitrary client identity
header is forwarded to Stargate, preventing fallback to an unrelated login path.
The example requires both Stargate settings. Without them `/auth` fails closed
with 503; `/identity` is the separate identity-only interface.

Keep Porter, Stargate and Warden backends off the public network. Use HTTPS for
`stargate_url` across untrusted networks. Non-loopback HTTP is rejected unless
`allow_insecure_stargate: true` explicitly permits a private plaintext connection.
The container-network example opts in; remove that opt-in when using HTTPS.
The example assumes Stargate's default `USER_HEADER_NAME`. Porter forwards only
`X-Forwarded-User`, `X-Auth-User`, `X-Auth-Email`, `X-Auth-Phone`, `X-Auth-Name`,
`X-Auth-Role` and `X-Auth-Scopes`. `Set-Cookie`, redirects and shared secrets are
never returned. The two identity headers must identify the bound user, not the
generic value `authenticated`. Custom identity header names require an explicit
code change.
Stargate/Herald step-up flows are not orchestrated by this initial implementation;
external login must not be treated as verified email evidence or MFA.

The Nginx file requires DNS, certificate, secret and upstream replacement. Tests
exercise the delegated Stargate boundary with local HTTP fixtures. They do not
establish a live provider or Warden deployment.

## Operations

Porter uses `audit-kit/v2`, `logger-kit/v3`, `health-kit/v4`, `metrics-kit/v3`,
`version-kit/v4` and `preflight-kit`. Authentication decisions stay in the
existing gateway; instrumentation receives only fixed action/reason/provider
names, a generated request ID and an internal user ID when known.

### Management listener

Management endpoints are served on a **separate listener**, default
`127.0.0.1:9093`. They are not added to the public authentication server or the
Nginx application route. Keep that listener private.

- `GET /healthz`: process liveness; dependency failure does not change liveness.
- `GET /readyz`: draining state, a read-only bbolt structural probe, latest
  maintenance result and, when configured, Stargate's `/readyz` status.
- `GET /metrics`: HTTP/authentication outcomes, audit loss/queue and Go/process
  metrics from a private Prometheus registry.
- `GET /version`: version, commit, build date and runtime metadata.

Without `operations.key`, the listener must bind to loopback and every request
must come directly from a loopback peer with a loopback/localhost Host.
Non-loopback Host values are rejected to prevent DNS rebinding. Forwarded IP
and Host headers are ignored.
A non-loopback listener requires a separate key of at least 32 characters:
`Authorization: Bearer <operations.key>`. When a key is configured, it is required
on loopback too. Query parameters and the proxy credential are not alternative
management authentication methods. Configuration rejects a management key equal
to `proxy_key` or `stargate_secret`.

`operations.listen`, `operations.key`, `operations.audit_file`,
`operations.log_level`, `operations.audit_queue_size` and
`operations.probe_timeout_seconds` are optional JSON fields under `operations`.
Defaults are loopback port 9093, no key, `porter-audit.jsonl` beside the database,
`info`, 1024 records and two seconds. Queue capacity is limited to 65536 records;
probe timeout must be between one and ten seconds.

The storage probe does not create, extend, consume or revoke records. Its result
proves read access and required bucket presence, not every possible future write.
A blocked read is limited to one outstanding probe. Readiness returns 503 for a
critical failure or graceful shutdown. In identity-only mode the unconfigured
Stargate check is disabled; readiness is not proof that `/auth` can authorize.
The Stargate probe sends no credentials or identity, rejects redirects, and does
not call `/_auth`. It does not prove that shared secrets, directory mappings or a
provider application are correct. Provider token endpoints are never probed.

### Logging and audit

Structured JSON logs use fixed route/action/result/reason fields and a generated
`X-Request-ID`; a client-supplied request ID is not trusted. Routine successful
`/auth` and `/identity` checks are debug-level logs; login and logout are info-level,
and rejections are warnings. There is no runtime log-level mutation endpoint.

The audit journal is owner-only JSON Lines. It records login starts, callback
success/failure, logout, rate limits and failed access/identity checks. Successful
access checks are counted in metrics but are not appended on every business
request. Records contain internal user IDs when already known, never external
subjects, email/phone, raw URLs, query strings, cookies, authorization headers,
user agents, upstream response bodies or tokens.

Audit delivery is best-effort through one worker and a bounded queue. Queue
rejections increment `porter_audit_dropped_total`; failed writes increment
`porter_audit_write_failures_total` and emit a generic error. Queue depth is
`porter_audit_queue_length`. Failures do not change authentication results or
turn a rejection into success. Graceful shutdown stops both listeners and drains
the audit queue; this is not a transactional outbox or a power-loss durability
guarantee. Runtime audit failure does not fail readiness; monitor the loss counters.

Provision an owner-writable audit directory. Existing audit files must be regular
files with no group/other permissions, and must not alias the session database.
The writer retains the verified file descriptor and rejects a symbolic-link
destination. The service does not silently chmod existing files. Arrange log retention and
rotation externally; restart after rotating the journal so the new file is opened.
Logs and metrics do not contain account identifiers; the private audit journal
can contain internal user IDs. Metric routes, methods, actions, reasons and
providers use bounded application-owned labels, not request paths or subjects.

### Commands and deployment checks

```sh
porter version --json
porter check-config -config /path/to/porter.json --json
porter doctor -config /path/to/porter.json --json
porter doctor -config /path/to/porter.json --network --json
```

`version` (also `--version`) does not load configuration. `check-config` validates
syntax and rules without opening the database, creating an audit writer or
starting a listener. Configuration failures report safe rule messages, not
private paths, unknown JSON field names or values.

`doctor` uses preflight-kit to check directory create/remove access, existing
file modes and whether the audit destination aliases the database. It creates
and removes temporary probe files in configured directories, but does not open
or reconcile the database or create the journal. A missing private data file is
a warning on first deployment. Network access is off unless `--network` is set;
that flag adds only the bounded Stargate readiness request. Results redact
internal paths and dependency response/error contents. Error findings exit nonzero;
warnings alone do not. Neither command establishes a real login.

Mount a private persistent directory for the database. Do not share a database
between replicas, place it on a network filesystem, or run multiple writers.
bbolt takes an exclusive process lock. Back up the database only while Porter is
stopped or through an appropriate bbolt snapshot procedure. An expired record is
rejected even before the minute-by-minute cleanup removes it.

Login starts are still limited to 30 per minute per direct network peer.
Forwarded client IP headers are ignored. Behind a proxy this is a shared limit;
apply an additional client limit at the edge. Each database bucket has a
10,000-record cap. Capacity exhaustion returns 503 without bypassing authentication.

Disable query-string logging for callback URLs and upstream HTTP instrumentation:
WeChat and QQ require credentials/tokens in some protocol query parameters.
Do not log request URLs, cookies, config contents or authorization headers.
Porter rejects upstream redirects instead of forwarding credentials to another host.

### Build metadata and upgrade

```sh
docker build -t porter . \
  --build-arg VERSION=v0.1.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

For a native build, set `main.version`, `main.commit` and `main.buildDate` with
`go build -ldflags`. Unspecified values remain `dev`/`unknown`; no release version
is inferred. The non-root image still runs the public service on port 8083.
Mount config at `/etc/porter/porter.json`, a writable private data directory at
`/data`, and use `/data/porter.db`. Management port 9093 remains loopback-only
unless explicitly reconfigured with a management key. Do not publish it as a
public application route. HTTP management access requires a trusted private
network or separate TLS termination.

Before upgrading, provision the audit path and reserve the management listener;
run `check-config` and `doctor`. A journal that cannot be opened or a management
listener that cannot bind prevents startup. Existing authentication records,
namespace/binding rules, session deadlines, revocations and Stargate headers are
unchanged. No database reset or session migration is required for this phase.
Configuration still loads once at startup. Rollback requires removing the new
`operations` configuration section before using a previous strict config parser;
retain the database and audit journal.

## Validation

```sh
go test -race ./...
go vet ./...
go build ./cmd/porter
```

Tests cover local provider responses, cryptographically signed Google tokens,
transaction binding and single consumption, session persistence/expiry/revocation,
configuration rejection, logout/exchange races, mapping reconciliation, original
request forwarding, identity mismatches and closed storage failures. The safety
suite runs with the observation wrapper enabled. Additional tests cover journal
loss/redaction/draining, management isolation, bounded readiness, command side
effects, graceful shutdown and version output.

Chromium acceptance submits the real HTML forms, intercepts only provider
authorization navigation, and checks callbacks, secure cookies and logout:

```sh
PORTER_CHROME=/path/to/google-chrome go test ./internal/gateway -run TestBrowserForms -count=1 -v
```

This test requires Node.js 22 or later and an isolated Chrome/Chromium binary;
it is enabled explicitly in Linux CI. Provider exchange fixtures are separate
from browser navigation fixtures. Real provider credentials,
application approval and callbacks are still required for live acceptance.

The Nginx integration test runs the actual configuration and Porter handler over
local TLS, with simulated Stargate and business upstreams. It checks forged
headers, original POST routing, contact reassignment and dependency failure:

```sh
docker build -f tests/nginx.Dockerfile -t porter-nginx-check .
docker run --rm porter-nginx-check
```

Both browser and Nginx acceptance tests run in CI. Neither test establishes a
live provider authorization or a deployment against a real Warden directory.

## Protocol references

- [GitHub OAuth web flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [WeChat website login](https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html)
- [QQ authorization code](https://wiki.connect.qq.com/使用authorization_code获取access_token)
- [QQ OpenID](https://wiki.connect.qq.com/获取用户openid_oauth2-0)

## License

Apache-2.0. See [LICENSE](LICENSE).
