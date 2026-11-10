# Capacity and failure baseline

Porter remains a single-process service with one local bbolt database. Each of
transactions, browser families and sessions has a 10,000-record admission cap.
Expired records count until cleanup; expiry is checked on reads even before
cleanup. Startup and minute-by-minute maintenance prune expired records. bbolt
may retain allocated disk pages after deletion, so pruning is not disk compaction.
Do not increase caps or run a second writer as an incident workaround.

A full bucket returns 503 and does not bypass authentication. Even an account
switch at a full session bucket can be refused: the cap is checked inside the
existing transaction and failure rolls back any earlier deletion. The old session
and its absolute expiry remain intact. A callback already consumed before an
upstream exchange is not reusable when session issuance later fails. The user
must start a new login after capacity is restored; never replay the code exchange.

## Repeatable baseline

Run against a disposable checkout and local filesystem:

```sh
go test -race ./...
go test ./internal/store -run '^$' -bench 'Benchmark(SessionRead|LoginLogout)$' \
  -benchmem -benchtime=100x -count=3
```

Record the commit, Go version, CPU/architecture, filesystem/storage, container
limits, concurrency and benchmark output. Session reads measure the real indexed
store and JSON validation; login/logout includes durable bbolt transactions.
The fixed synthetic identity and bounded key set do not contact any provider or
measure real OAuth latency. Compare candidates on the same host. No universal
latency SLA or production sizing claim is derived from this microbenchmark.
Use private host-level disk/memory monitoring alongside Porter's bounded metrics.

The regression suite fills actual buckets to their caps in one fixture transaction,
then checks admission failure, atomic rollback, expiry cleanup, restored login,
logout, and callback single use. Existing failure tests cover bounded HTTP pools,
slow upstream cancellation, audit queue drops/write errors, blocked readiness
probes, storage failure, and graceful stop/restart. The production acceptance suite
checks hardened container operation and persistent revocation across rollback.

## Response and resource planning

- Budget disk for database growth, current journal, retained audit archives and
  backup staging; alert through host infrastructure before space is exhausted.
  Do not delete the active database or restore an old backup to make room.
- Login starts are limited to 30/minute per direct peer. A proxy shares this budget;
  keep per-client controls at the trusted edge and ignore untrusted forwarded IPs.
- Preserve the existing outbound total timeout and 32 connections per host. Slow
  upstreams must release blocked calls on timeout/cancellation, with no code retry.
- Inspect maintenance/readiness failures and audit loss counters separately.
  Audit is best effort; loss must not change successful authentication or readiness.
- Allow at least 20 seconds for container termination. Check the final audit flush,
  private readiness and existing sessions after restart. A forced kill is not a
  successful graceful-shutdown acceptance.

Fault injection uses isolated local test servers and synthetic records only.
Do not fill a production database, revoke real users, exhaust a host disk, or send
synthetic authorization codes to live providers as a capacity test.

## Initial local sample

At the capacity implementation `5d88a9e` on 2026-11-10, Go 1.27.3,
macOS 26.5.1/arm64, Apple M5, default GOMAXPROCS 10, a local working directory,
and default durable bbolt writes, three 100-iteration runs produced:

```text
BenchmarkSessionRead-10       15266 / 4306 / 2927 ns/op
                             1460 / 1667 / 1624 B/op; 16 allocs/op
BenchmarkLoginLogout-10       36418128 / 37482243 / 48594948 ns/op
                             82514 / 82751 / 83133 B/op; 264 allocs/op
```

These short runs include scheduling and storage variance and were collected
while other local verification was active. They establish a reproducible starting
sample, not an isolated throughput limit, percentile distribution or capacity
recommendation. Repeat on the target Linux filesystem and deployment limits
before making sizing decisions.

The connection-pool test requires 32 simultaneously occupied upstream slots and
64 calls attempting acquisition before cancellation. It rejects both an undersized
pool and requests exceeding the cap; merely seeing one timed-out request is not
accepted as evidence of saturation.
