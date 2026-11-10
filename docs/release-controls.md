# Release protection and first candidate acceptance

`examples/release/controls.json` pins this repository and its reviewer user ID.
The current repository has one administrator, so `prevent_self_review` is false:
this is an explicit human single-maintainer approval, not an independent two-person
review. Add another eligible reviewer and review that policy before requiring
independent approval. No script approves a pending deployment.

The additive operator tool defaults to a read-only plan:

```sh
python3 tools/release-controls.py
python3 tools/release-controls.py --apply
python3 tools/release-controls.py --check --expected-repository soulteary/porter
```

The apply command needs GitHub administration write access through the existing
`gh` login. It creates a `release` environment with required reviewers and only
`v*` tag deployments, plus an active `porter-release-tags` ruleset restricting
version-tag creation, updates and deletion. Repository administrators retain an
explicit bypass for controlled creation/recovery; record any bypass. This does
not restrict main or merge requests. Never use a ruleset bypass to move an
already released version tag to unrelated content.

All conflict/identity checks precede writes. Existing settings with different
reviewers or rules are refused rather than overwritten. Rules outside the named
managed set are untouched. Operations are not transactional: an API failure can
leave partial controls, and the operator must inspect and rerun check. Serialize
administrative changes; concurrent environment/ruleset writers are unsupported.
Inventories over one 100-item page are refused instead of silently ignoring rules.

The release policy job checks these controls read-only and verifies that the
policy belongs to the workflow repository. Publishing still requires the protected
environment, main ancestry, all acceptance workflows and exact-digest image
scanning/provenance verification. Neither this operator tool nor PR CI creates
Git tags, approves deployments, publishes packages or changes runtime credentials.

## First protected candidate

Before selecting a version, review the exact main commit and its terminal CI.
Record the tag/version and previous compatible image, and use a new candidate
version rather than moving an existing tag. A real candidate release is a separate
operator action after reviewing those concrete inputs:

1. Create the selected signed tag at the reviewed main commit and push that tag.
2. Wait for the read-only release gates. Inspect their source commit, both native
   platforms, compatibility and no-retry authentication results.
3. Manually review the pending `release` environment deployment in GitHub.
4. Record the GHCR digest, workflow/run identity, platform-specific reports and
   verified provenance from the successful summary. Candidate-tag existence
   alone is not release success; late registry failures may leave partial artifacts.
5. Run an isolated deployment/rollback/recovery drill using the digest. Keep
   configuration and provider secrets outside the evidence report, and preserve
   the current database for compatible rollback. Disaster recovery invalidates
   every old session and pending callback.

This change prepares and checks controls. It does not claim that GHCR publishing,
OIDC issuance, manual approval or real provider application login has already
passed merely because offline tests or a dry-run policy passed.
