# Release verification and supply chain

Ordinary pull requests and main pushes run read-only supply-chain checks on native
Linux amd64 and arm64 runners. Each builds the digest-pinned production image,
checks architecture, non-root identity and build metadata, then emits a CycloneDX
SBOM and a complete Trivy vulnerability report. Fixable HIGH/CRITICAL findings
fail the job. Unfixed findings remain visible in the full report and require
operator assessment; the gate does not claim absence of all vulnerabilities.
Scanner errors and unavailable vulnerability databases fail rather than passing.
The native arm64 job also runs the production startup/upgrade/rollback suite;
amd64 service acceptance runs in the existing production workflow.
Reports are retained as workflow artifacts for 14 days. No provider credentials,
production configuration, registry publishing tokens or OIDC permissions are
available to these PR jobs. Fork PRs use `pull_request`, never `pull_request_target`.

Direct Action references, production and acceptance base images, BuildKit, QEMU
binfmt and the SBOM generator are pinned to immutable commits/digests. Version
comments aid review. Dependabot opens reviewable Go, Action and root Dockerfile
updates weekly; pinned helper/test images must also be reviewed when updating
tooling. Do not auto-merge digest changes or treat a digest as proof of trust.
Trivy's installer is pinned and its binary version is explicit; its installation
step checks upstream release checksums. Vulnerability data intentionally refreshes.

## Publish a reviewed version

Before the first release, a repository administrator must configure the `release`
environment with required reviewers, restrict release tag creation/movement using
repository rulesets, and grant the workflow access to the GHCR package. The
workflow checks that a required-reviewer policy exists and refuses publication
otherwise. These repository settings are not provisioned by this change.

Create a version tag such as `v0.2.0` only after reviewing and merging its commit.
Tag pushes run supply-chain verification for both native architectures, the full
Go/browser/Nginx authentication checks, monitoring rules, audit retention and the
production baseline upgrade/rollback suite. Publishing waits for these jobs and
the protected environment. The tag must name a main ancestor and match the
workflow's version pattern. Only the publishing job gets package-write,
attestation-write and OIDC permissions. No cloud or production credentials are
required. Tags and workflow dispatch are not created by the PR checks.

The publishing job builds amd64/arm64 with pinned inputs and an explicit Buildx
version, embeds version, commit and source commit time, and pushes only a
`candidate-<run-id>-<attempt>` tag with BuildKit SBOM/provenance. A GitHub OIDC
provenance attestation is bound to that candidate's multi-platform digest.
`tools/release-image.py` then checks the raw index digest and both required Linux
platforms, generates platform-specific CycloneDX SBOMs and full vulnerability
reports from **that exact registry digest**, and blocks fixable HIGH/CRITICAL
findings on either platform. It verifies the provenance before assigning the
version tag by a manifest carbon copy, without rebuilding. The promoted manifest
must still match the checked digest. Reports identify their immutable subject
and are retained for 14 days.

The native PR builds remain useful preflight checks; they are not a substitute
for the exact candidate gate. Scanner, registry or attestation errors prevent
version promotion. A failed attempt can leave an unpromoted candidate and origin
attestation in GHCR; neither means the vulnerability gate passed. No `latest` tag
or automatic deployment is produced. Only a completed successful release summary
is a deployment reference. The environment-policy job has only Actions read
permission for the environment API; publishing write/OIDC grants remain isolated.

`python3 -m unittest discover -s tests/release -v` checks the actual promotion
helper's failure paths with mocked external commands: either platform failing,
scanner errors, missing platforms, wrong digest and provenance rejection must
not assign a version tag. Check mode cannot publish. These tests run in PR CI;
real package writes and OIDC issuance are reserved for a protected tag release.

## Verify before deployment

Use the immutable digest from the successful release summary:

```sh
gh attestation verify oci://ghcr.io/soulteary/porter@sha256:<digest> \
  --repo soulteary/porter \
  --signer-workflow soulteary/porter/.github/workflows/release.yml

docker buildx imagetools inspect ghcr.io/soulteary/porter@sha256:<digest>
```

Check the attested repository/workflow and source revision against the reviewed
tag, the expected platform manifests, and the associated SBOM and vulnerability
reports. Deploy by digest and run `version --json`, `check-config` and `doctor`
using the service identity and private mounts. A signed provenance statement
describes origin; it does not replace authentication/security regression tests,
vulnerability review or deployment isolation. Keep rollback and session handling
as in `deployment.md`.

Local validation: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`,
`go test -race ./...`, and `python3 tests/production.py`. Native architecture,
scanner/database access and package attestation are tested by their workflow
stages. This change does not publish a version or claim those release-only stages
have already been exercised with production publishing permissions.

The first scan identified two upstream go-jose advisories in v4.1.3:
[GHSA-mgcc-cww5-fp2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q)
(JWK parsing denial of service) and
[GHSA-78h2-9frx-2jm8](https://github.com/go-jose/go-jose/security/advisories/GHSA-78h2-9frx-2jm8)
(JWE decryption panic). The dependency is patched to v4.1.6. Porter uses JWK/JWS
verification for Google OIDC and does not add a JWE login flow. The upstream
4096-bit RSA JWK parsing limit is retained; larger keys are rejected, not granted
a custom exception. Existing signed-token issuer/audience/nonce/signature tests
and all four single-attempt exchange tests remain required.
