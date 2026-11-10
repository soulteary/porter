# Protocol and persistent-session security acceptance

The protocol/session fuzz workflow uses synthetic local adapters and disposable
bbolt files. It never reads production configuration or sends authorization codes
to a real provider. Normal Go tests run the seed corpus under the race detector;
Release gates and PR/main fuzz jobs spend 20 seconds per target with two workers, and weekly jobs
spend two minutes per target. These are bounded exploration budgets, not proof
that every protocol or concurrency state has been covered.

- `FuzzProviderResponseSingleExchange` feeds all four adapters status/body pairs.
  The token endpoint must be called exactly once, including automatic-auth-style
  rejection. Invalid Google signatures cannot authenticate, successful identities
  retain their provider/client namespace, and errors cannot disclose fixture
  credentials. A local transport forbids every non-fixture destination.
- `FuzzCallbackSingleUse` mutates raw query strings and cookie headers across all four provider routes.
  Eligible callbacks must succeed once, so an adapter that rejects everything
  cannot satisfy the oracle. Cookie binding is checked with an independent
  cookie-count oracle, including duplicate-cookie seed cases. It checks
  browser/state binding, duplicate-parameter rejection, replay prevention and
  session-cookie attributes. Its adapter counts exchanges but performs no HTTP.
- `FuzzSessionRevocationAcrossRestart` compares store operations to a small state
  model across consumption, issuance, logout, binding removal and restart. It
  checks persistent revocation and unchanged absolute expiry. Direct store calls
  deliberately avoid depending on browser parsing to test persistence separately.

The four-provider concurrency acceptance pauses an exchange, sends a parallel
callback, revokes the browser through logout, then releases the exchange. No
session may be issued, and reopening the database must not allow late issuance
or another exchange. A second test starts 16 callbacks together for each provider:
exactly one must win and its session must remain usable after database reopen.
The release publishing job requires the protocol/session fuzz workflow.
This does not change the running service's configuration.

```sh
go test -race ./...
go test ./internal/provider -run '^$' -fuzz '^FuzzProviderResponseSingleExchange$' -fuzztime 20s -parallel 2
go test ./internal/gateway -run '^$' -fuzz '^FuzzCallbackSingleUse$' -fuzztime 20s -parallel 2
go test ./internal/store -run '^$' -fuzz '^FuzzSessionRevocationAcrossRestart$' -fuzztime 20s -parallel 2
```

Retain only synthetic crash reproducers under `internal/*/testdata/fuzz`; CI
uploads them on failure for 14 days. Reproduce, minimize and review a failure
before changing a validator or corpus expectation. Do not weaken a negative
assertion to make a corpus pass. Real provider applications, QR interaction,
network behavior and Stargate/Warden interoperability need their separate
controlled acceptance. The shared-adapter concurrency test also sends 16 distinct codes per provider
to a real local HTTP server returning 401, and requires exactly one request for
each code. Existing wire-level single-attempt tests remain required:
HTTP/1 only for code exchange, no connection reuse, no redirects, no oauth2 auth
style probing, and rejection of unknown retry-capable transports.
