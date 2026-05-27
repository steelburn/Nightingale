"""Auto-remediation orchestrator.

Pipeline:

    1. Parse every Trivy JSON report under --artifacts/.
    2. Optionally backfill empty `FixedVersion` fields via OSV.dev.
    3. Aggregate findings per ecosystem and decide what to patch.
    4. Apply patches to configuration/cve-mitigation/*.
    5. Emit:
         - remediation-plan.json  (machine-readable)
         - pr-body.md             (GitHub PR description)
         - summary.md             (job summary for $GITHUB_STEP_SUMMARY)

Run:
    python -m scripts.auto-remediate.remediate \
        --artifacts ./trivy-artifacts \
        --repo . \
        --output ./remediation-plan.json \
        --pr-body ./pr-body.md \
        --summary ./summary.md \
        [--no-osv]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

from . import parse_trivy, update_mitigations

try:
    from packaging.version import InvalidVersion, Version
except ImportError:
    Version = None  # type: ignore[assignment]
    InvalidVersion = ValueError  # type: ignore[assignment]

log = logging.getLogger("auto-remediate")


def _max_version(values: list[str]) -> str:
    """Pick the highest PEP-440-parseable version from a list of candidates.

    Trivy sometimes reports multiple FixedVersion entries for a single CVE
    (e.g. backport chains like minimatch "10.2.3, 9.0.7, 8.0.6, ..."), packed
    into one comma-separated string. We split those into individual semvers
    before ranking so we never emit a multi-value pin into a shell script.
    """
    if not values:
        return ""
    flat: list[str] = []
    for raw in values:
        for part in str(raw).split(","):
            part = part.strip()
            if part:
                flat.append(part)
    if not flat:
        return ""
    if Version is None:
        return max(flat)
    parsed: list[tuple[Version, str]] = []
    for v in flat:
        try:
            parsed.append((Version(v), v))
        except InvalidVersion:
            pass
    if parsed:
        parsed.sort(key=lambda p: p[0])
        return parsed[-1][1]
    return max(flat)


def build_plan(
    findings: list[parse_trivy.Finding],
    *,
    use_osv: bool,
) -> dict:
    """Aggregate findings into per-ecosystem decisions."""
    if use_osv:
        try:
            from . import osv_lookup
        except ImportError as exc:
            log.warning("OSV lookup disabled: %s", exc)
            backfill = {}
        else:
            backfill = osv_lookup.backfill(findings)
    else:
        backfill = {}

    enriched: list[parse_trivy.Finding] = []
    for f in findings:
        if f.fixed_version:
            enriched.append(f)
            continue
        fix = backfill.get(f.key())
        if fix:
            enriched.append(
                parse_trivy.Finding(
                    image=f.image,
                    target=f.target,
                    ecosystem=f.ecosystem,
                    pkg_name=f.pkg_name,
                    installed_version=f.installed_version,
                    fixed_version=fix.fixed_version,
                    cve_id=f.cve_id,
                    severity=f.severity,
                    primary_url=f.primary_url,
                    title=f.title,
                )
            )
        else:
            enriched.append(f)

    by_eco: dict[str, list[parse_trivy.Finding]] = defaultdict(list)
    for f in enriched:
        by_eco[f.ecosystem].append(f)

    pip_items: dict[str, list[str]] = defaultdict(list)
    pip_cves: dict[str, list[str]] = defaultdict(list)
    npm_items: dict[str, list[str]] = defaultdict(list)
    npm_cves: dict[str, list[str]] = defaultdict(list)
    apt_unfixed: dict[str, list[str]] = defaultdict(list)
    apt_fixed: dict[str, dict[str, str]] = {}
    go_versions: list[str] = []
    go_cves: list[str] = []
    advisory_jar: dict[str, dict] = {}
    advisory_gomod: dict[str, dict] = {}

    for f in enriched:
        if f.ecosystem == "pip":
            if f.fixed_version:
                pip_items[f.pkg_name.lower()].append(f.fixed_version)
                pip_cves[f.pkg_name.lower()].append(f.cve_id)
        elif f.ecosystem == "npm":
            if f.fixed_version:
                npm_items[f.pkg_name.lower()].append(f.fixed_version)
                npm_cves[f.pkg_name.lower()].append(f.cve_id)
        elif f.ecosystem == "apt":
            if not f.fixed_version:
                apt_unfixed[f.pkg_name].append(f.cve_id)
            else:
                apt_fixed[f.pkg_name] = {
                    "installed": f.installed_version,
                    "fixed": f.fixed_version,
                    "cves": apt_fixed.get(f.pkg_name, {}).get("cves", []) + [f.cve_id],
                }
        elif f.ecosystem == "gobinary":
            if f.pkg_name.lower() == "stdlib" and f.fixed_version:
                go_versions.append(f.fixed_version.lstrip("v").lstrip("go"))
                go_cves.append(f.cve_id)
        elif f.ecosystem == "gomod":
            advisory_gomod[f.pkg_name] = {
                "installed": f.installed_version,
                "fixed": f.fixed_version,
                "cves": advisory_gomod.get(f.pkg_name, {}).get("cves", []) + [f.cve_id],
            }
        elif f.ecosystem == "jar":
            advisory_jar[f.pkg_name] = {
                "installed": f.installed_version,
                "fixed": f.fixed_version,
                "cves": advisory_jar.get(f.pkg_name, {}).get("cves", []) + [f.cve_id],
            }

    pip_targets = {pkg: _max_version(vs) for pkg, vs in pip_items.items() if vs}
    npm_targets = {pkg: _max_version(vs) for pkg, vs in npm_items.items() if vs}
    go_min = _max_version(go_versions) if go_versions else ""

    summary = parse_trivy.Summary.from_findings(enriched)

    return {
        "summary": {
            "total": summary.total,
            "by_severity": summary.by_severity,
            "by_ecosystem": summary.by_ecosystem,
            "by_image": summary.by_image,
            "images": summary.images,
        },
        "pip": {"pins": pip_targets, "cves": dict(pip_cves)},
        "npm": {"pins": npm_targets, "cves": dict(npm_cves)},
        "apt": {
            "unfixed": dict(apt_unfixed),
            "fixed_via_upgrade": apt_fixed,
        },
        "go": {"recommended_min": go_min, "cves": go_cves},
        "advisory": {
            "jar": advisory_jar,
            "gomod": advisory_gomod,
        },
        "findings": parse_trivy.to_jsonable(enriched),
    }


def apply_plan(plan: dict, repo: Path) -> update_mitigations.PatchResult:
    result = update_mitigations.PatchResult()

    update_mitigations.patch_pip(
        repo,
        items=plan["pip"]["pins"],
        plan_cves=plan["pip"]["cves"],
        result=result,
    )
    update_mitigations.patch_npm(
        repo,
        items=plan["npm"]["pins"],
        plan_cves=plan["npm"]["cves"],
        result=result,
    )
    update_mitigations.patch_purge_list(
        repo,
        candidates=plan["apt"]["unfixed"],
        allowlist=update_mitigations.load_purge_allowlist(repo),
        result=result,
    )
    update_mitigations.patch_go_min_version(repo, plan["go"]["recommended_min"], result)
    update_mitigations.advisory_only("jar", plan["advisory"]["jar"], result)
    update_mitigations.advisory_only("gomod", plan["advisory"]["gomod"], result)

    return result


# ---------------------------------------------------------------------------
# Rendering: PR body + step summary
# ---------------------------------------------------------------------------

def render_pr_body(
    plan: dict,
    result: update_mitigations.PatchResult,
    trivy_run_id: str,
    trivy_repo: str = "RAJANAGORI/Nightingale",
) -> str:
    s = plan["summary"]
    lines: list[str] = []
    lines.append("# Automated OSS CVE Remediation")
    lines.append("")
    lines.append(
        f"Generated from Trivy Scan run "
        f"[`{trivy_run_id}`](https://github.com/{trivy_repo}/actions/runs/{trivy_run_id})."
    )
    lines.append("")
    lines.append("## Scan summary")
    lines.append("")
    lines.append(f"- Total HIGH/CRITICAL findings: **{s['total']}**")
    if s.get("by_severity"):
        sev = ", ".join(f"{k}: {v}" for k, v in sorted(s["by_severity"].items()))
        lines.append(f"- By severity: {sev}")
    if s.get("by_ecosystem"):
        eco = ", ".join(f"{k}: {v}" for k, v in sorted(s["by_ecosystem"].items()))
        lines.append(f"- By ecosystem: {eco}")
    if s.get("images"):
        lines.append("- Images scanned:")
        for img in s["images"]:
            lines.append(f"  - `{img}` ({s['by_image'].get(img, 0)} findings)")
    lines.append("")

    if result.applied:
        lines.append("## Patches applied automatically")
        lines.append("")
        lines.append("| File | Change | CVEs |")
        lines.append("|---|---|---|")
        for a in result.applied:
            cves = ", ".join(a.cve_ids[:6])
            if len(a.cve_ids) > 6:
                cves += f", +{len(a.cve_ids) - 6} more"
            lines.append(f"| `{a.file}` | {a.description} | {cves or '-'} |")
        lines.append("")

    if result.needs_manual:
        lines.append("## Needs human review")
        lines.append("")
        lines.append("| Item | Detail | CVEs |")
        lines.append("|---|---|---|")
        for a in result.needs_manual:
            cves = ", ".join(a.cve_ids[:6])
            if len(a.cve_ids) > 6:
                cves += f", +{len(a.cve_ids) - 6} more"
            lines.append(f"| `{a.file}` | {a.description} | {cves or '-'} |")
        lines.append("")

    lines.append("## How this PR was generated")
    lines.append("")
    lines.append(
        "- `.github/workflows/auto-remediate.yml` downloaded the Trivy "
        "`vulns-*.json` artifacts from the scan run above."
    )
    lines.append(
        "- `scripts/auto-remediate/remediate.py` parsed them, optionally "
        "queried OSV.dev for missing fix versions, and produced this plan."
    )
    lines.append(
        "- `scripts/auto-remediate/update_mitigations.py` applied the plan "
        "to files under `configuration/cve-mitigation/`."
    )
    lines.append("")
    lines.append("## Reviewer checklist")
    lines.append("")
    lines.append("- [ ] All applied pins look correct against upstream advisories")
    lines.append("- [ ] Items in *Needs human review* either resolved here or tracked elsewhere")
    lines.append("- [ ] Docker Image CI is green for both `amd64` and `arm64`")
    lines.append("- [ ] A follow-up Trivy Scan after merge shows a reduced count")
    return "\n".join(lines) + "\n"


def render_summary(plan: dict, result: update_mitigations.PatchResult) -> str:
    s = plan["summary"]
    lines = [
        "## Auto-remediate run",
        "",
        f"- Findings considered: **{s['total']}**",
        f"- Patches applied: **{len(result.applied)}**",
        f"- Needs human review: **{len(result.needs_manual)}**",
        "",
    ]
    if result.applied:
        lines.append("### Applied")
        for a in result.applied[:25]:
            lines.append(f"- `{a.file}` — {a.description}")
        if len(result.applied) > 25:
            lines.append(f"- … and {len(result.applied) - 25} more")
        lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="auto-remediate",
        description="Apply Trivy-driven remediations to Nightingale's mitigation scripts.",
    )
    p.add_argument(
        "--artifacts",
        type=Path,
        required=True,
        help="Directory containing Trivy artifact downloads (vulns-*.json under subdirs).",
    )
    p.add_argument(
        "--repo",
        type=Path,
        default=Path("."),
        help="Repository root to patch (default: cwd).",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("remediation-plan.json"),
        help="Where to write the machine-readable plan.",
    )
    p.add_argument(
        "--pr-body",
        type=Path,
        default=Path("pr-body.md"),
        help="Where to write the PR description markdown.",
    )
    p.add_argument(
        "--summary",
        type=Path,
        default=Path("summary.md"),
        help="Where to write the job-summary markdown.",
    )
    p.add_argument(
        "--no-osv",
        action="store_true",
        help="Skip OSV.dev backfill (faster, but may miss fix versions).",
    )
    p.add_argument(
        "--trivy-run-id",
        default="",
        help="GitHub Actions run id of the Trivy scan that produced these artifacts.",
    )
    p.add_argument(
        "--trivy-repo",
        default="RAJANAGORI/Nightingale",
        help="owner/name of the repo that hosts the Trivy run (used for the PR body link).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Build the plan and write outputs but do NOT modify the repo.",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.artifacts.exists():
        log.error("artifacts directory does not exist: %s", args.artifacts)
        return 2

    findings = parse_trivy.parse_directory(args.artifacts)
    log.info("Parsed %d HIGH/CRITICAL findings from %s", len(findings), args.artifacts)

    plan = build_plan(findings, use_osv=not args.no_osv)

    if args.dry_run:
        log.info("Dry run: skipping file mutations")
        result = update_mitigations.PatchResult()
    else:
        result = apply_plan(plan, args.repo)

    args.output.write_text(json.dumps(plan, indent=2, default=str), encoding="utf-8")
    args.pr_body.write_text(
        render_pr_body(plan, result, args.trivy_run_id, args.trivy_repo),
        encoding="utf-8",
    )
    args.summary.write_text(render_summary(plan, result), encoding="utf-8")

    log.info(
        "Done. applied=%d needs_review=%d (plan=%s)",
        len(result.applied),
        len(result.needs_manual),
        args.output,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
