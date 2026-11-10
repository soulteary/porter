# Private monitoring and key restart acceptance

Run `python3 tests/operations.py` from a disposable checkout with Docker. The
suite uses real Porter, Prometheus and blackbox images, synthetic credentials and
an isolated persistent volume. It creates two internal Docker networks, binds
management/exporter/Prometheus listeners only to the monitoring interface, and
publishes no ports. Uncredentialed test peers in the application network must
reach the public application listener but cannot reach any monitoring listener,
either through the application address or across Docker's bridge isolation.
Never relax these assertions to accommodate a deployment with public management.

The repository's monitoring examples are copied into a test-only image. The
suite changes private target addresses, file locations, scrape/evaluation
intervals (five seconds) and alert hold times (two seconds). It does not replace
the real alert expressions or shorten production hold times. Existing promtool
unit tests continue to validate production timing and thresholds separately.

A mode-0440 management credential is mounted read-only into monitoring processes
with an explicitly dedicated UID/GID. The source volume directory is mode 0750;
Porter's private JSON remains owner-only. No production credentials are used. Mounted synthetic management keys are written
at runtime, and their values must not appear in URLs, Prometheus labels or
command arguments. Fixture values are predictable by design; the test-only
initializer and its image must never be deployed as production components.
The initializer is not included in the production image.

Acceptance covers:

- Real authenticated `/metrics` scrapes and `/readyz` blackbox probes.
- Network/interface isolation, absence of published ports, public management-route
  rejection and rejection of proxy credentials by management.
- A changed mounted management key leaving the running Porter's loaded key intact.
  Credential mismatch causes scrape/readiness alerts; the exporter remains up.
- Coordinated stop/start loading the new key, rejecting the old one, restoring
  actual scrapes and resolving the alerts in the same running Prometheus instance.
  A rule evaluation after recovered scrapes is required; rebuilding monitoring
  cannot substitute for alert resolution. An existing session survives; logout
  still revokes it. Identity-only `/auth` remains fail-closed.
- An exporter outage causing its own alert, followed by exporter recovery.
- Absence of synthetic keys, cookies, provider secrets and contacts from container
  logs and queried operational labels.

Containers, networks, volumes and temporary image tags are removed afterward.
Failures include redacted container diagnostics. The suite requires real Docker
bridge isolation and local named-volume permissions; it does not assert equivalent
isolation for arbitrary container-compatible runtimes or host-network mode.
No live provider, Stargate deployment, notification service or production secret
is contacted. Full provider/browser/Nginx tests remain release requirements.

## Apply the design to a deployment

Use infrastructure-owned private networks/firewalls and a distinct management
credential. The blackbox `/probe` API accepts arbitrary targets and attaches the
module credential: allow only the trusted Prometheus peer to reach it. A private
port alone is insufficient if untrusted applications share its network. Restrict
Prometheus access as well. The monitoring processes have independent network namespaces and remain alive
while Porter restarts. This acceptance topology is not a production Compose template.

Deploying alert routing, paging credentials, persistent Prometheus retention,
TLS, dashboards and network policy remains an infrastructure responsibility.
Validate these settings in the trusted deployment environment. Do not infer that
readiness proves platform credentials, identity binding correctness or Stargate
authorization. Follow `secret-files.md` for coordinated key changes and
`deployment.md` for compatible rollback against the current database.
