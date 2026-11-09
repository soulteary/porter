# Monitoring and incident response

The examples in `examples/monitoring` use Porter's existing private management
endpoints and exported series. No authentication endpoint or token exchange is
probed. No new runtime metrics, logging fields, or authorization behavior are
introduced.

## Connect a trusted monitoring peer

Load `porter.rules.yml` from Prometheus and adapt `prometheus.yml` to the actual
private service addresses. The sample uses a separate blackbox exporter for
`/readyz`. Mount the management key read-only at
`/run/secrets/porter-management-key` in both monitoring processes. Configure the
same distinct key in Porter and explicitly bind management to the private
interface. Keep the public application proxy and port separate. Use a trusted
private network, or configure HTTPS and CA verification when crossing that boundary.

Do not use the proxy key, Stargate secret, provider secret, or a URL query
parameter for monitoring authentication. Credential values belong in mounted
files, not targets, labels, alert annotations, checked-in configuration, or shell
arguments. Match mounted file ownership to the monitoring process.

The blackbox exporter is a privileged monitoring component: its `/probe` endpoint
accepts caller-supplied targets and the configured module can attach the management
credential. Permit access only from Prometheus on an isolated monitoring network;
do not publish port 9115 or expose it to application clients. Scrape targets are
administrator-owned configuration. Preserve redirect rejection. The module uses
a four-second deadline inside a five-second scrape timeout; adjust both together
if Porter uses a longer configured readiness deadline.

Check `/metrics` scrape authentication separately from readiness. An exporter
outage is not proof of a Porter dependency outage. Identity-only readiness is
healthy when Stargate is not configured; it does not prove `/auth` can authorize
or that platform credentials work. Keep the existing browser/provider and Nginx
acceptance checks as release gates.

## Rules and response

- `PorterScrapeUnavailable`: inspect process state, authorized network access and
  the management key before restarting or changing credentials.
- `PorterReadinessFailed`: inspect read-only storage access, maintenance errors,
  draining state and configured Stargate readiness. Do not treat `/healthz` as
  readiness and do not probe OAuth token endpoints to diagnose this alert.
- `PorterReadinessProbeUnavailable`: repair the exporter or its private network.
- `PorterAuditDropped`: inspect queue pressure and backing storage throughput.
  Increasing capacity is not a substitute for fixing a stalled destination.
- `PorterAuditWriteFailed`: inspect mount permissions, free space and storage
  health. Preserve the current database. Counters show loss, not recoverable audit
  content. Audit failure does not alter authentication or readiness.
- `PorterLoginCallbackFailureRate`: compare bounded provider and reason labels.
  The sample threshold is 20% for five minutes with at least 20 callbacks per
  five-minute window. Ordinary unauthenticated access checks and rate limits are
  excluded. User cancellations and unlinked identities may still contribute;
  investigate before classifying the cause as provider failure.
- `PorterAuthenticationLatency`: investigate storage or upstream delays. The
  example uses p95 above two seconds for five minutes, with at least 20 requests
  per window, for authorization and callback paths. Tune for the deployment; this
  is not a declared service-level objective.

Counters use `increase` so process restarts do not become false loss alerts.
Queue depth is available as `porter_audit_queue_length`; size it against the
configured queue capacity rather than assuming a universal saturation threshold.
Metrics use `porter_request_duration_seconds_*` (without an `http` subsystem),
fixed paths, and bounded labels. Avoid account IDs, contacts and raw URLs in
operator-added dimensions. Prometheus retention, alert routing, notification
credentials and dashboard access remain infrastructure configuration.

## Validate changes

```sh
docker build -f tests/monitoring/Dockerfile --target rules -t porter-monitoring .
docker run --rm porter-monitoring check config --syntax-only /etc/prometheus/prometheus.yml
docker run --rm porter-monitoring test rules porter.test.yml
docker build -f tests/monitoring/Dockerfile --target blackbox -t porter-blackbox-check .
docker run --rm porter-blackbox-check --config.file=/etc/blackbox_exporter/config.yml --config.check
```

CI checks syntax, firing, minimum-volume suppression, normal access denials,
rate-limit exclusion, resets, latency and healthy cases. Tool images are pinned
to explicit versions. Configuration syntax validation does not read deployment
credential files or contact the sample targets; validate mount access and actual
scrapes separately from the trusted monitoring environment.
