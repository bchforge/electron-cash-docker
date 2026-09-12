# CI And Security Baseline

The repository uses `./scripts/ci.sh` as its validation entry point:

```bash
./scripts/ci.sh fast
./scripts/ci.sh acceptance
```

`fast` performs source, pin, static regression, and Compose-resolution checks.
It does not build or start containers and is partial feedback, not full
acceptance. `acceptance` refuses a non-default or remote Docker context, builds
both runtime images from the checkout with uncached builders, resolves and
checks a task-owned Compose model, scans the candidate image references, and
runs the existing disposable runtime suites. Acceptance is not permitted to
fall back to a familiar image tag.

## Dependency Policy

Dependabot manages only GitHub Actions and the root `requirements.txt` manifest.
The Electron Cash, noVNC, Tor, and plugin identity/integrity tuples remain
manual units. A version, commit, archive hash, signature expectation, or
packaged-artifact hash must not be updated independently.

Dependency Review blocks newly introduced high or critical vulnerable
dependencies when GitHub can identify a fix. CodeQL analyzes first-party Python
and its results are reviewed as code-scanning findings, not treated as proof of
an audit.

## Image Scanning

Trivy scans both freshly built candidate images at HIGH and CRITICAL severity.
The scan fails for a finding with an available fixed version. Findings without
an available fix are retained in the JSON report and printed with an explicit
no-fix disposition; they are not treated as safe or hidden by a blanket ignore.
Scanner failure, invalid output, missing output, or database setup failure is a
validation failure. Reports are short-lived CI artifacts and do not contain
complete images.

Trivy package results do not fully audit source-built Tor, downloaded noVNC,
external plugin source, plugin behavior, or the Docker host. The repository's
source/archive/signature and deterministic-plugin checks cover the integrity
boundaries that image package scanning cannot.

## Scope

The baseline is maintenance hardening for v0.2.1. It does not add a deployment
workflow, registry publishing, production credentials, or production Docker
endpoint. It does not claim bit-for-bit whole-image reproducibility, independent
security certification, or removal of the funded v0.3, v0.4, or v1.0 scope.
