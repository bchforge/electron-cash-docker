# Local Validation And Security Baseline

The repository uses `./scripts/ci.sh` as its validation entry point:

```bash
./scripts/ci.sh fast
./scripts/ci.sh sast
./scripts/dependency-review.sh v0.2
./scripts/ci.sh acceptance
./scripts/ci.sh gate
./scripts/dependencies.sh check
```

`fast` performs source, pin, static regression, and Compose-resolution checks.
It does not build or start containers and is partial feedback, not full
acceptance. `acceptance` refuses a non-default or remote Docker context, builds
both runtime images from the checkout with uncached builders, resolves and
checks a task-owned Compose model, scans the candidate image references, and
runs the existing disposable runtime suites. Acceptance is not permitted to
fall back to a familiar image tag. `sast` runs pinned local Bandit analysis and
`dependency-review.sh` compares the candidate with `v0.2`. The
`./scripts/dependencies.sh check` command is read-only update discovery and is
advisory, not release authority.
`gate` composes `fast`, local SAST, source vulnerability and secret scans,
dependency review, and `acceptance` into the provider-independent release
authority. A forge adapter may publish the result for an immutable commit but
is not required for release correctness.

Each gate run writes durable evidence outside the repository by default under
`${XDG_STATE_HOME:-$HOME/.local/state}/electron-cash-docker/ci/<run-id>`. The
manifest records the effective source fingerprint, dirty candidate identity,
working-tree diff hash, tool versions, scan reports, candidate image IDs,
acceptance results, cleanup status, resource postconditions, and final
PASS/FAIL. `CI_REPORT_DIR` may override the location for a wrapper.

## Accepted Candidate Results

The result badges at the top of the README represent the accepted uncommitted
v0.2.1 candidate gate run on 2026-09-15. The complete gate passed, including
fast validation, feature and runtime acceptance, regression tests, dependency
review, vulnerability policy, and cleanup/resource postconditions. Bandit
`1.9.4` completed successfully with zero findings. Trivy `0.74.0` completed
source and freshly built wallet/Tor image vulnerability scans with zero
fixable HIGH or CRITICAL findings. Its source secret scan also reported zero
findings, but secret scanning is kept as a documented secondary control rather
than a primary badge.

These are point-in-time results for the accepted candidate and are not a claim
of absolute security, complete vulnerability discovery, or independent audit.
Local gate runs write evidence but do not rewrite the tracked badges. Before
publication, the complete gate must be rerun against the clean release commit;
the badges must be refreshed if that evidence differs.

## Dependency Policy

The direct runtime Python pins are reviewed against `v0.2` by the local
dependency-review command. The Electron Cash, noVNC, Tor, and plugin
identity/integrity tuples remain manual units. A version, commit, archive hash,
signature expectation, or packaged-artifact hash must not be updated
independently.

The direct `ecdsa==0.19.1` pin
remains visible in scans because the upstream advisory lists no patched version
and the package's own security policy says it does not protect against
side-channel attacks. Electron Cash Docker applies a versioned, fail-closed
integration patch: the application requires the verified BCH-specific
`libsecp256k1` backend instead of initializing the pure-Python private-operation
fallback, and Schnorr signing rejects its pure-Python fallback as well. The
supported image therefore has the application disposition `MITIGATED_IN_ECD`,
while the package-level advisory remains open and must not be called fixed.
Reassess by 2026-12-31 or sooner if upstream ships a fix, Electron Cash changes
its ECC boundary, or a supported deployment can run without the required native
backend. Local Bandit analysis examines first-party Python with a narrow
high-severity/high-confidence blocking policy. It is static analysis, not proof
of an audit.

The initial candidate scan found fixable protobuf vulnerabilities
`CVE-2025-4565` and `CVE-2026-0994` in the preserved `5.28.2` pin. The smallest
security-driven remediation is the direct `protobuf==5.29.6` pin; the Docker
build's `pip check`, installed-environment checks, and full acceptance rerun
are required evidence for that change. Other direct pins are not upgraded by
this release.

## Local SAST

The local SAST implementation uses Bandit `1.9.4` and its explicitly pinned
Python tool dependencies from `requirements-sast.txt`. Bandit is a stable,
Apache-2.0-licensed Python analyzer and supports the repository's current
Python 3.14 execution environment. The former hosted CodeQL workflow is not
used: this project does not claim CodeQL equivalence, and the local gate does
not depend on a hosted security service or upload permission.

The scanner examines first-party Python in `docker/`, `scripts/`, and `tests/`.
High-severity, high-confidence Bandit findings fail; lower-severity findings
are not silently treated as release failures. Tool bootstrap failure, malformed
output, scanner errors, or missing output fail. JSON, SARIF, command, and tool
reports are stored in the gate evidence directory.

## Dependency Review And Updates

`./scripts/dependency-review.sh v0.2` is a local base-vs-candidate review. It
compares exact Python pins, Dockerfile frontends and base-image digests,
Electron Cash/noVNC/Tor pins, plugin source/version/hash tuples, and local tool
pins. It fails malformed metadata, loss of an immutable reference, removed
integrity metadata, or a failing vulnerability disposition. An available newer
version alone does not fail the review.

`./scripts/dependencies.sh check` queries the public PyPI JSON index for the
direct Python packages and reports current/latest versions without modifying
source. Electron Cash, noVNC, Tor, plugins, and Docker base images remain
manual integrity authorities because their upstream release systems are not
queried by this read-only command. Lookup errors fail the command rather than
producing a false current result.

## Optional GitLab Status Adapter

`./scripts/forge/gitlab-gate.sh` is a thin optional adapter. It refuses a dirty
working tree, binds the status to the exact `HEAD` SHA and symbolic ref, posts
`ecd-local-gate` as pending, runs `./scripts/ci.sh gate`, and posts success or
failure for that same SHA. It uses the existing authenticated `glab` state,
does not print or persist tokens, retries only bounded transient API failures,
and fails closed on a mismatched response. It is not called by `gate`, and no
hosted CI configuration is required.

The GitLab project is configured to require a successful pipeline/status and to
reject skipped pipelines. A live Merge Request end-to-end test is deferred
until the first real committed candidate; the current candidate remains
uncommitted and therefore cannot receive a success status.

## Image Scanning

The local gate uses pinned Trivy `0.74.0` for both source and freshly built
candidate image scans at HIGH and CRITICAL severity. It also runs a source
secret scan; any confirmed secret finding fails the gate. Vulnerability results
are evaluated from JSON, not terminal text. A fixable HIGH/CRITICAL finding
fails, and a no-fix HIGH/CRITICAL finding fails unless it exactly matches an
active entry in `security/vulnerability-exceptions.json`. The reviewed
`CVE-2024-23342` / `ecdsa==0.19.1` finding is retained in the reports and is
allowed only for the declared source and Electron Cash image scopes. Scanner
failure, invalid output, missing output, malformed or expired exception data,
or database setup failure is a validation failure.

The gate attempts all owned cleanup, records cleanup failures without hiding a
primary test failure, and verifies that its containers, Compose projects,
networks, and temporary volumes are gone. Unrelated pre-existing Docker
resources are preserved. Reports do not contain complete images or raw secret
matches.

Trivy package results do not fully audit source-built Tor, downloaded noVNC,
external plugin source, plugin behavior, or the Docker host. The repository's
source/archive/signature and deterministic-plugin checks cover the integrity
boundaries that image package scanning cannot. The source scan still depends
on the current Trivy vulnerability database; the gate records scanner and
database metadata with each run.

## Scope

The baseline is maintenance hardening for v0.2.1. It does not add a deployment
workflow, registry publishing, production credentials, or production Docker
endpoint. It does not claim bit-for-bit whole-image reproducibility, independent
security certification, or removal of the funded v0.3, v0.4, or v1.0 scope.
