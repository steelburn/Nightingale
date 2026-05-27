# Nightingale Auto-Remediate

End-to-end pipeline that closes the loop on Trivy findings: it consumes
the `vulns-*.json` artifacts produced by `.github/workflows/trivy.yml`,
generates targeted patches against the mitigation scripts under
[`configuration/cve-mitigation/`](../../configuration/cve-mitigation), and
opens a pull request for review.

## How the loop runs end-to-end

```text
Monthly cron / workflow_dispatch
        │
        ▼
.github/workflows/trivy.yml
        │   (scans 6 GHCR images)
        ├─► artifacts/                          → upload-artifact
        │     ├─ trivy-results-<image>.sarif     → GitHub Security tab
        │     ├─ sbom-<image>.cyclonedx.json     → sbom-parser → sbom.rajanagori.in
        │     └─ vulns-<image>.json              → Auto-Remediate consumes
        │
        ▼
.github/workflows/auto-remediate.yml
        │
        ├─ gh run download trivy-artifacts
        ├─ python -m scripts.auto-remediate.remediate
        │    • parse_trivy.py   → Finding records
        │    • osv_lookup.py    → backfills empty FixedVersion via OSV.dev
        │    • update_mitigations.py → patches files in place
        │
        ├─ remediation-plan.json + pr-body.md + summary.md (uploaded)
        │
        └─ peter-evans/create-pull-request → branch
           auto-remediate/trivy-<run-id>     →    PR (label: security, auto-remediate)
```

## What it patches

| Trivy `Class`/`Type`         | Action                                                                                                                                                                                       |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `python-pkg`, `poetry`       | Bump `'pkg>=N'` pins in [`pip-security-upgrade.sh`](../../configuration/cve-mitigation/pip-security-upgrade.sh); add new pins if missing                                                      |
| `node-pkg`, `npm`            | Bump `'pkg@^N'` pins in [`npm-global-hardening.sh`](../../configuration/cve-mitigation/npm-global-hardening.sh); add new pins if missing                                                      |
| `debian`, `ubuntu`, `alpine` | If Trivy has `FixedVersion`, normal `apt-get upgrade` (already runs in [`debian-apt-security.sh`](../../configuration/cve-mitigation/debian-apt-security.sh)) handles it. If no fix is available and the package is on [`safe_purge_allowlist.txt`](safe_purge_allowlist.txt), it is appended to [`vuln-library-purge`](../../configuration/cve-mitigation/vuln-library-purge). Otherwise it is flagged for manual review. |
| `gobinary` (stdlib)          | Bump [`go-min-version.txt`](../../configuration/cve-mitigation/go-min-version.txt) and the `ARG GO_VERSION=` lines in the two `programming_langauge.Dockerfile` files. `audit-go-binaries.sh --strict` then enforces it during build.                                                                                                                       |
| `gomod`                      | Advisory only — let Dependabot update `nightingale-go/go.mod`.                                                                                                                                |
| `jar` (maven)                | Advisory only — Java jars come from the programming base image; flag for manual review.                                                                                                       |

## Files in this directory

| File                          | Purpose                                                                                  |
| ----------------------------- | ---------------------------------------------------------------------------------------- |
| `__init__.py`                 | Package marker.                                                                          |
| `remediate.py`                | CLI orchestrator: parse → plan → patch → render PR body.                                 |
| `parse_trivy.py`              | Parses Trivy native JSON reports into `Finding` dataclasses.                             |
| `osv_lookup.py`               | Optional OSV.dev backfill for findings with empty `FixedVersion`.                        |
| `update_mitigations.py`       | The only module that mutates source files. Patches `configuration/cve-mitigation/`.      |
| `safe_purge_allowlist.txt`    | Exact apt package names the bot may add to `vuln-library-purge`.                         |
| `requirements.txt`            | Pinned floor of Python deps (`requests`, `packaging`).                                   |

## Running locally

```bash
cd /path/to/Nightingale

# 1. Grab artifacts from a Trivy run (needs a PAT with actions:read)
gh run download <trivy-run-id> --dir trivy-artifacts

# 2. Dry-run (no file changes, no PR)
python -m pip install -r scripts/auto-remediate/requirements.txt
PYTHONPATH=. python -m scripts.auto-remediate.remediate \
    --artifacts trivy-artifacts \
    --repo . \
    --output remediation-plan.json \
    --pr-body pr-body.md \
    --summary summary.md \
    --trivy-run-id <trivy-run-id> \
    --dry-run

# 3. Inspect remediation-plan.json + pr-body.md
jq '.summary' remediation-plan.json
cat pr-body.md

# 4. Apply for real (drops --dry-run)
PYTHONPATH=. python -m scripts.auto-remediate.remediate \
    --artifacts trivy-artifacts \
    --trivy-run-id <trivy-run-id>
git status   # → diff in configuration/cve-mitigation/, Dockerfiles/, etc.
```

## Safety rails

- **No auto-merge.** PRs always require a reviewer.
- **Conservative apt purges.** Only packages explicitly listed in
  `safe_purge_allowlist.txt` are added to `vuln-library-purge`. Anything
  else is surfaced under "Needs human review" in the PR body.
- **PEP 440 version comparison.** Pins are only bumped when the new
  fix version is strictly greater than the current pin.
- **Idempotent.** Running the bot twice on the same Trivy artifacts is a
  no-op; existing pins are not re-listed and `vuln-library-purge`
  additions are deduped.
- **Scoped commits.** The PR only ever changes
  `configuration/cve-mitigation/**`, `Dockerfile`, `Dockerfiles/**`, and
  `architecture/**`.

## Failure modes & recovery

| Symptom                                      | Likely cause                                                            | Fix                                                                                                |
| -------------------------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Workflow exits with "No successful Trivy run"| Branch had no recent green Trivy run                                     | Re-run `trivy.yml` from the Actions tab, then re-run `auto-remediate.yml`.                          |
| PR body has empty tables                     | Trivy reported zero HIGH/CRITICAL CVEs                                   | Expected — no PR will be opened (detect-changes step short-circuits).                              |
| "could not locate pip-install block"         | The pin block in `pip-security-upgrade.sh` was edited in an unexpected shape | Re-align to the canonical `python3 -m pip install "${PIP_ARGS[@]}"` heredoc and rerun.              |
| OSV backfill hangs                           | OSV.dev throttling                                                       | Re-run with `--no-osv`; Trivy's `FixedVersion` covers most cases on its own.                       |

## Operator playbook (monthly)

1. Wait for the cron-driven `Trivy Scan` run (1st of every month, 10:00 UTC).
2. The Auto-Remediate cron fires 30 min later (10:30 UTC), or it can be
   triggered earlier via the `trigger_auto_remediate` job appended to
   `trivy.yml`.
3. Review the PR (label `auto-remediate`):
   - check the *Patches applied* table against upstream advisories
   - resolve anything in *Needs human review* (usually means adding a
     non-trivial package to `safe_purge_allowlist.txt` after verifying it
     isn't depended on, or hand-editing the mitigation script for a new
     ecosystem)
   - approve & merge once Docker Image CI passes
4. After merge, optionally re-run `trivy.yml` to confirm the count dropped;
   `sbom-parser` republishes `sbom.rajanagori.in` automatically.
