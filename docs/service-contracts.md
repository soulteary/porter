# Real service contracts

Run `python3 tests/contracts.py --evidence service-contracts.json` on a Docker host.
The harness builds Porter's production image and a separate test peer, then runs
real Stargate 1.3.6 and Warden 1.6.3 images pinned by multi-platform digest. It uses
synthetic bindings, directory users and session records. No provider application
or production configuration is loaded.

The tests cover the Porter -> Stargate -> Warden delegation path, both identity
headers, role propagation, forged client headers, valid-session/no-proxy and valid-proxy/no-session denials,
wrong proxy keys, invalid forwarded context, direct unauthenticated access,
contact reassignment, inactive directory users, upstream outage/recovery and logout
across Porter restart.
Directory changes restart only the test Warden and Stargate to avoid conflating
cache lifetime with identity enforcement. This does not measure live cache
invalidation latency. No browser credential or upstream cookie may appear in the
proxy authorization response. The peer inventories every response header name
and count, including empty sensitive headers, instead of filtering the response
before checking the allowlist. Denials must contain no identity headers.
The release publishing job requires this service contract workflow.

Each service runs with 0.5 CPU, 256 MiB and 128 PIDs, a read-only root filesystem,
dropped capabilities and no privilege escalation. The Docker network is internal;
no service port is published. Test-only configuration is written to private local
environment files and removed after startup. The initializer is a separate image
and is never included in the production image. Cleanup addresses only randomly
named resources created by the run.

For an authorized target host, transfer native prebuilt images and pass
`--porter-image IMAGE --peer-image IMAGE` to avoid compiling there. Those images
are retained for the operator; resources created by the harness are removed.
The JSON evidence contains image identities and successful checks, not session
values or provider secrets. CI retains it for 14 days.

This is service contract acceptance, not real GitHub, Google, WeChat or QQ login.
Those flows still require dedicated test applications and approved callback URLs.
Do not publish this synthetic fixture as a public login endpoint or reuse existing
production secrets to make the tests pass.

The [2026-11-10 target ARM64 run](evidence/service-contracts-arm64-2026-11-10.json)
passed the identity, denial, directory-change, upstream outage/recovery and
persistent logout checks. The existing application containers retained their IDs
and health. The candidate uses unchanged production sources at the recorded
commit; the evidence contains no live provider application result.
