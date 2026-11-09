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
5. Run `go run ./cmd/porter -config /path/to/porter.json` behind an HTTPS proxy.

Only configured providers are enabled. Google discovery must succeed at startup.
Use `openssl rand -hex 32` to generate the proxy key. The example contains placeholders,
not working credentials. Do not commit the real configuration or database.

`public_url` must be an origin without a path or query. `landing_url` must share
that origin, because the session cookie is host-only. Production cookies use the
`__Host-` prefix, Secure, HttpOnly, SameSite=Lax and Path=/.
`development: true` permits loopback HTTP and uses unprefixed, non-Secure cookies;
it must not be used for a remotely accessible deployment.

The config is loaded once. Restart to apply binding changes; existing sessions
are resolved against the new bindings on every check. Removing a binding disables
that external identity. Database persistence does not extend absolute deadlines.

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

The mapped phone/mail must resolve to the intended Warden account. Warden remains
its authority: coordinate contact reassignment with mapping updates. Porter does
not validate that directory relationship or grant roles. `X-Porter-User-ID` is a
mapping label, not evidence that Warden has authorized that ID. Downstream apps
must use Stargate's authorization headers, not Porter headers.

## HTTP API

- `GET /login`: provider selection and logout form.
- `POST /login/{github|google|wechat|qq}`: start a login. Requires the exact public
  `Origin`; creates a five-minute browser-bound transaction. One outstanding login
  per browser is supported; starting again replaces the transaction cookie.
- `GET /callback/{provider}`: consume the transaction, authenticate upstream,
  require a configured binding, rotate the session and redirect to the fixed
  landing URL. No client-supplied return URL is accepted.
- `GET /auth`: private proxy identity check. Requires
  `Authorization: Bearer <proxy_key>` and the browser session cookie. Returns 200
  with `X-Porter-User-ID` and exactly one of `X-User-Mail` / `X-User-Phone`.
  With `stargate_url` and `stargate_secret` configured, it instead calls Stargate
  server-to-server and returns only allowlisted authorization headers on success.
  Stargate 401/403 responses are preserved; redirects and other failures become 503.
  Returns 401 for missing/expired sessions or invalid proxy credentials, 403 for
  removed bindings, and 503 for storage failures. It does not redirect.
- `POST /logout`: exact-origin request; revoke the local session and clear the
  cookie. It does not revoke upstream grants or sign out of the provider.
- `GET /healthz`: process liveness only, not provider or directory readiness.

All responses use `Cache-Control: no-store`. Provider errors are not reflected.
Upstream access tokens are used only within the callback request, never persisted.
State and session database keys are SHA-256 hashes of random 256-bit values.
Transactions are consumed atomically before exchange; failures require a new login.
There are no automatic code-exchange retries.

## Stargate integration

See `examples/nginx.conf` for a same-origin Nginx `auth_request` arrangement:

1. Nginx checks Porter through one private subrequest, passing the session cookie
   and a proxy credential.
2. Porter validates the session and identity binding. With `stargate_url` and
   `stargate_secret` configured, it sends the configured contact to Stargate's
   `/_auth` endpoint, using `X-Stargate-Header-Auth` and `Accept: application/json`.
3. Stargate resolves the contact through Warden. Porter returns success only after
   Stargate succeeds, copying an explicit allowlist of authorization headers.
4. Nginx overwrites application identity headers with that result.

Enable `HEADER_AUTH_ENABLED=true`, set `HEADER_AUTH_SHARED_SECRET`, and configure
Warden on Stargate. Porter uses Stargate's default secret header
`X-Stargate-Header-Auth`. No browser cookie, password or arbitrary client identity
header is forwarded to Stargate, preventing fallback to an unrelated login path.
The example requires both optional Stargate settings; without them `/auth` proves
only the mapped external identity and must not be used as a business access gate.

Keep Porter, Stargate and Warden backends off the public network. Use HTTPS for
`stargate_url` across untrusted networks; HTTP is accepted for private deployments.
The example assumes Stargate's default `USER_HEADER_NAME`. Porter forwards only
`X-Forwarded-User`, `X-Auth-User`, `X-Auth-Email`, `X-Auth-Phone`, `X-Auth-Name`,
`X-Auth-Role` and `X-Auth-Scopes`. `Set-Cookie`, redirects and shared secrets are
never returned. Custom identity header names require an explicit code change.
Stargate/Herald step-up flows are not orchestrated by this initial implementation;
external login must not be treated as verified email evidence or MFA.

The Nginx file requires DNS, certificate, secret and upstream replacement. Tests
exercise the delegated Stargate boundary with local HTTP fixtures. They do not
establish a live provider or Warden deployment.

## Operations

Mount a private persistent directory for the database. Do not share a database
between replicas, place it on a network filesystem, or run multiple writers.
bbolt takes an exclusive process lock. Back up the database only while Porter is
stopped or through an appropriate bbolt snapshot procedure. An expired record is
rejected even before the minute-by-minute cleanup removes it.

Login starts are limited to 30 per minute per direct network peer. Forwarded
client IP headers are ignored. Behind a proxy this is a shared limit; apply an
additional client limit at the edge. Each database bucket has a 10,000-record cap.
Capacity exhaustion returns 503 and does not bypass authentication.

Disable query-string logging for callback URLs and upstream HTTP instrumentation:
WeChat and QQ require credentials/tokens in some protocol query parameters.
Do not log request URLs, cookies, config contents or authorization headers.
Porter rejects upstream redirects instead of forwarding credentials to another host.

`docker build -t porter .` builds a non-root Linux image. Mount the config at
`/etc/porter/porter.json` and an owner-writable data directory at `/data`; use
`/data/porter.db` as the database path. TLS terminates at the proxy.

## Validation

```sh
go test -race ./...
go vet ./...
go build ./cmd/porter
```

Tests cover local provider responses, cryptographically signed Google tokens,
transaction binding and single consumption, session persistence/expiry/revocation,
configuration rejection, and closed storage failures. Real provider credentials,
application approval and callbacks are still required for live acceptance.

## Protocol references

- [GitHub OAuth web flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [WeChat website login](https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html)
- [QQ authorization code](https://wiki.connect.qq.com/使用authorization_code获取access_token)
- [QQ OpenID](https://wiki.connect.qq.com/获取用户openid_oauth2-0)

## License

Apache-2.0. See [LICENSE](LICENSE).
