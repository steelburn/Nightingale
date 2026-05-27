"""Parse Trivy native JSON reports into normalised Finding records."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

SEVERITIES = {"CRITICAL", "HIGH"}


@dataclass(frozen=True)
class Finding:
    """One package/CVE pair surfaced by Trivy."""

    image: str
    target: str
    ecosystem: str  # apt | pip | npm | gobinary | gomod | jar | gem | other
    pkg_name: str
    installed_version: str
    fixed_version: str  # empty string when no fix is published
    cve_id: str
    severity: str
    primary_url: str
    title: str

    def key(self) -> tuple[str, str, str]:
        """Deduplication key across images."""
        return (self.ecosystem, self.pkg_name, self.cve_id)


_TRIVY_TYPE_TO_ECOSYSTEM = {
    "debian": "apt",
    "ubuntu": "apt",
    "alpine": "apk",
    "redhat": "rpm",
    "amazon": "rpm",
    "rocky": "rpm",
    "fedora": "rpm",
    "oracle": "rpm",
    "python-pkg": "pip",
    "pip": "pip",
    "poetry": "pip",
    "node-pkg": "npm",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "gobinary": "gobinary",
    "gomod": "gomod",
    "go-module": "gomod",
    "jar": "jar",
    "pom": "jar",
    "gradle": "jar",
    "gem": "gem",
    "bundler": "gem",
}


def _map_ecosystem(trivy_type: str | None) -> str:
    if not trivy_type:
        return "other"
    return _TRIVY_TYPE_TO_ECOSYSTEM.get(trivy_type.lower(), "other")


def _iter_results(report: dict) -> Iterator[dict]:
    for result in report.get("Results") or []:
        yield result


def parse_report_file(path: Path) -> list[Finding]:
    """Parse one Trivy JSON file. Returns findings filtered to HIGH/CRITICAL."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"Cannot parse Trivy report {path}: {exc}") from exc

    image = payload.get("ArtifactName") or path.stem
    findings: list[Finding] = []

    for result in _iter_results(payload):
        target = result.get("Target") or ""
        ecosystem = _map_ecosystem(result.get("Type"))

        for vuln in result.get("Vulnerabilities") or []:
            severity = (vuln.get("Severity") or "").upper()
            if severity not in SEVERITIES:
                continue

            pkg_name = (vuln.get("PkgName") or "").strip()
            installed = (vuln.get("InstalledVersion") or "").strip()
            cve = (vuln.get("VulnerabilityID") or "").strip()
            if not pkg_name or not cve:
                continue

            fixed = (vuln.get("FixedVersion") or "").strip()

            findings.append(
                Finding(
                    image=image,
                    target=target,
                    ecosystem=ecosystem,
                    pkg_name=pkg_name,
                    installed_version=installed,
                    fixed_version=fixed,
                    cve_id=cve,
                    severity=severity,
                    primary_url=(vuln.get("PrimaryURL") or "").strip(),
                    title=(vuln.get("Title") or "").strip(),
                )
            )

    return findings


def parse_directory(root: Path) -> list[Finding]:
    """Walk a directory and parse every Trivy JSON report (`vulns-*.json`)."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("vulns-*.json")):
        findings.extend(parse_report_file(path))
    return findings


@dataclass
class Summary:
    total: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_ecosystem: dict[str, int] = field(default_factory=dict)
    by_image: dict[str, int] = field(default_factory=dict)
    images: list[str] = field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: Iterable[Finding]) -> "Summary":
        s = cls()
        images_seen: set[str] = set()
        for f in findings:
            s.total += 1
            s.by_severity[f.severity] = s.by_severity.get(f.severity, 0) + 1
            s.by_ecosystem[f.ecosystem] = s.by_ecosystem.get(f.ecosystem, 0) + 1
            s.by_image[f.image] = s.by_image.get(f.image, 0) + 1
            images_seen.add(f.image)
        s.images = sorted(images_seen)
        return s


def to_jsonable(findings: Iterable[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]
