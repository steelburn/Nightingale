#!/usr/bin/env python3
"""Render a GitHub Security Advisory draft from a Trivy remediation plan.

Usage:
  python scripts/generate-security-advisory.py \\
      --plan remediation-plan.json \\
      --month June --year 2026 \\
      --fix-version 1.1.31 \\
      --output Advisories/2026-06-Security-Updates.md
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def _unique(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _load_purge_packages(repo: Path | None) -> list[str]:
    if repo is None:
        return []
    purge_file = repo / "configuration" / "cve-mitigation" / "vuln-library-purge"
    if not purge_file.exists():
        return []
    return [
        line.strip()
        for line in purge_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def render_advisory(
    plan: dict,
    *,
    month: str,
    year: int,
    fix_version: str,
    affected_from: str = "1.1.30",
    repo: Path | None = None,
) -> str:
    apt_purge = sorted(set(plan.get("apt", {}).get("purge", [])) | set(_load_purge_packages(repo)))
    apt_unfixed = plan.get("apt", {}).get("unfixed", {})
    go_min = plan.get("go", {}).get("recommended_min") or "see go-min-version.txt"
    npm_pins = plan.get("npm", {}).get("pins", {})
    jar_items = plan.get("advisory", {}).get("jar", {})

    rows: list[tuple[str, str, str, str]] = []

    if go_min:
        go_cves = _unique(plan.get("go", {}).get("cves", []))
        rows.append(
            (
                "Go stdlib (embedded binaries)",
                f"Rebuild with Go {go_min}+",
                "Multiple",
                "High",
            )
        )

    for pkg in apt_purge:
        cves = _unique(apt_unfixed.get(pkg, []))
        rows.append((pkg, "Removed", "Multiple" if len(cves) > 1 else (cves[0] if cves else "Multiple"), "High"))

    for pkg, ver in sorted(npm_pins.items()):
        cves = _unique(plan.get("npm", {}).get("cves", {}).get(pkg, []))
        rows.append((pkg, f"Patched (>={ver})", "Multiple" if len(cves) > 1 else (cves[0] if cves else "Multiple"), "High"))

    for pkg, info in sorted(jar_items.items()):
        fixed = info.get("fixed", "?")
        rows.append((pkg, f"Upgrade to {fixed}", "Multiple", "High"))

    # Collect all CVE IDs for the footnote block
    all_cves: list[str] = []
    for finding in plan.get("findings", []):
        cve = finding.get("cve_id")
        if cve:
            all_cves.append(cve)
    all_cves = sorted(set(all_cves))

    table_lines = [
        "| Package | Remediation | CVE | Severity |",
        "| :------ | :---------: | :-: | :------: |",
    ]
    for pkg, remediation, cve, severity in rows:
        table_lines.append(f"| {pkg} | {remediation} | {cve} | {severity} |")

    cve_block = "\n".join(f"> - {cve}" for cve in all_cves[:80])
    if len(all_cves) > 80:
        cve_block += f"\n> - … and {len(all_cves) - 80} more (see Trivy remediation plan)"

    unfixed_pkgs = sorted(apt_unfixed.keys())
    unfixed_note = ""
    if unfixed_pkgs:
        unfixed_note = (
            "\n\n### Awaiting upstream Debian fixes\n\n"
            "The following runtime packages still report HIGH/CRITICAL CVEs with no "
            "fixed version in Debian stable at scan time. `debian-apt-security.sh` "
            "applies fixes automatically on each image rebuild once published:\n\n"
            + ", ".join(f"`{p}`" for p in unfixed_pkgs[:20])
        )
        if len(unfixed_pkgs) > 20:
            unfixed_note += f", … ({len(unfixed_pkgs) - 20} more)"

    return f"""### Summary
We have addressed multiple CVEs originating from third-party dependencies in Nightingale versions **{fix_version}** and above, across **arm64** and **amd64** architectures. Images: [`ghcr.io/rajanagori/nightingale:stable`](https://ghcr.io/rajanagori/nightingale), [`ghcr.io/rajanagori/nightingale:arm64`](https://ghcr.io/rajanagori/nightingale).

{chr(10).join(table_lines)}

> Remediations applied during the Docker build via `configuration/cve-mitigation/`:
{cve_block}

### Fixed Releases
| Name | Affected Versions | Fix Version |
| ---- | :---------------: | :---------: |
| nightingale (Docker) | Below {fix_version} | {fix_version} |
| nightingale-go | {affected_from} to prior fix | {fix_version} |
| nightingale-go | 1.0 | Not Supported |

### Suggestion
Pull the latest Nightingale image tags (`stable`, `arm64`) or upgrade `nightingale-go` to **{fix_version}** from [Releases](https://github.com/RAJANAGORI/Nightingale/releases).

After upgrading, re-run the [Trivy Scan](https://github.com/RAJANAGORI/Nightingale/actions/workflows/trivy.yml) workflow so resolved findings are closed on the [Code scanning](https://github.com/RAJANAGORI/Nightingale/security/code-scanning) tab.{unfixed_note}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--month", default="June")
    parser.add_argument("--year", type=int, default=2026)
    parser.add_argument("--fix-version", default="1.1.31")
    parser.add_argument("--affected-from", default="1.1.30")
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    body = render_advisory(
        plan,
        month=args.month,
        year=args.year,
        fix_version=args.fix_version,
        affected_from=args.affected_from,
        repo=args.repo,
    )

    header = (
        f"# Security Updates - Nightingale ({args.month} {args.year})\n\n"
        f"**Title:** Security Updates - Nightingale ({args.month} {args.year})\n\n"
        f"Use this body when publishing at "
        f"https://github.com/RAJANAGORI/Nightingale/security/advisories/new\n\n"
    )
    text = header + body

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
