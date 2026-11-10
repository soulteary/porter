# Linux recovery acceptance

`tests/linux.py` runs a bounded synthetic workload and the offline recovery tool
against the production image. Run only on an authorized Linux Docker host with
capacity for a 0.5 CPU / 256 MiB candidate. Test helpers have the same limits.
No real provider application, production database or production key is needed.

Build the three images as shown in `.github/workflows/linux-recovery.yml`, then run:

```sh
python3 tests/linux.py --porter-image porter-linux:candidate \
  --fixture-image porter-linux:fixture --recovery-image porter-linux:recovery \
  --evidence linux-evidence.json
```

The harness creates randomly named volumes and containers. HTTP and management
ports bind only to loopback. Cleanup removes only resources created by the run;
prebuilt images are retained for the operator. The fixture and recovery binaries
are separate images and are never added to the production image.

The workload offers 10 identity reads per second for 20 seconds with four workers.
The evidence records successful request latency percentiles, startup readiness and
backup/restore command durations. These measurements are an initial host-specific
baseline, not a throughput limit, incident RTO or RPO commitment. Set operational
objectives from representative workloads and the actual backup schedule.

A snapshot is taken with Porter stopped. A session is then revoked in the source,
after which the older snapshot is restored into a new private volume. Every old
session and pending transaction must be invalid; an HTTP callback carrying its
original transaction cookie must fail. A newly seeded synthetic session is accepted,
logged out, and remains invalid after restart. Restore deliberately requires users
to sign in again. Runtime authentication and provider exchange code are unchanged.

For a shared host, capture the IDs and health of the existing application containers
before and after the run. Do not restart them, attach their networks, mount their
volumes, reuse their keys or modify proxy routing. Transfer prebuilt native images
when compiling on the host would create unwanted load. Keep evidence free of
cookies, tokens, database pages and application configuration. CI retains the
sanitized JSON for 14 days; retain operator evidence under the site's own policy.

Live provider authorization, browser redirect/QR behavior, complete incident
response timing and production workload capacity are outside this synthetic drill.

## Recorded target-host run

The [2026-11-10 ARM64 evidence](evidence/linux-arm64-2026-11-10.json) records
200 successful reads at 10 offered QPS: p50 25.133 ms, p95 35.979 ms and
p99 39.337 ms. Backup and restore commands took 0.342 s and 0.314 s;
restored readiness took 0.371 s. The existing application containers retained
their IDs and health across the drill. These are single-run observations on a
shared host under the stated container limits, not service-level objectives.
