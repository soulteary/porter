# DingTalk browser login

Porter owns the browser transaction and session. Herald-DingTalk remains a
notification adapter and is not called by this login path. Use the hosted
DingTalk consent page; embedded QR SDKs and client-side login are outside scope.

Register an independent test application with the exact HTTPS callback:
`https://YOUR_HOST/callback/dingtalk`. Configure:

```json
{
  "providers": {
    "dingtalk": {
      "client_id": "TEST_CLIENT_ID",
      "client_secret_file": "/run/secrets/dingtalk-client-secret"
    }
  },
  "bindings": [{
    "provider": "dingtalk",
    "namespace": "TEST_CLIENT_ID",
    "subject": "ADMINISTRATOR_VERIFIED_OPEN_ID",
    "user_id": "INTERNAL_USER_ID",
    "mail": "VERIFIED_WARDEN_CONTACT"
  }]
}
```

This is a configuration fragment; retain the existing public origin, data path,
proxy credential and Stargate configuration. Secret files must follow
`secret-files.md`. Restart to apply configuration changes.

The fixed permission scope is `openid`. The subject is the authenticated user
information response's `openId`, scoped in Porter by the configured client ID.
There is no fallback to enterprise `userId`, `unionId`, phone or email. Verify the
identifier against the selected application's actual response before provisioning
bindings. This does not assert enterprise membership or grant a role. An unbound
user is rejected. Reusing notification app credentials is not required.

The callback accepts exactly one `authCode`, with the existing browser-bound
state and transaction cookie. `code`, mixed aliases and duplicates are rejected.
The transaction is consumed before exchange. Errors require a new login; do not
retry or replay the authorization-code request. Token exchange uses JSON at
`https://api.dingtalk.com/v1.0/oauth2/userAccessToken`; user lookup uses
`https://api.dingtalk.com/v1.0/contact/users/me` with the
`x-acs-dingtalk-access-token` header. No token is put in the URL or persisted,
and no refresh flow is added. Errors do not expose upstream response bodies.

References:
- https://opensource.dingtalk.com/developerpedia/docs/develop/permission/token/browser/get_user_app_token_browser/
- https://open.dingtalk.com/document/orgapp/dingtalk-retrieve-user-information

## Acceptance

Run `go test -race ./...` and the existing security-fuzz workflow. The callback
fuzzer and concurrent single-winner/logout tests now include DingTalk. Transport
failure tests require one token request and zero redirect-target requests for
401, 429, 503, timeout, disconnect and redirect responses.

Live acceptance requires the independent application and private credentials:
confirm the callback and openId namespace, successful scan/consent, cancellation,
wrong state, unbound identity denial, replay denial without a second exchange,
logout/restart rejection and both Stargate identity headers matching the static
internal user. Retain only sanitized check results and source/image identities.
No live platform or target deployment result is claimed by synthetic tests.
Existing session/store/recovery and nine publishing gates remain mandatory.
