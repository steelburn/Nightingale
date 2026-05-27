"""OSV.dev client used to backfill missing fix versions from Trivy reports.

Trivy's `FixedVersion` is sometimes blank (CVE not yet mapped to the distro
package). OSV.dev maintains cross-source advisories from npm, PyPI, Go,
Debian, Ubuntu, Alpine, etc., so we use it as a fallback.

Public endpoint: https://osv.dev/docs/  -- no auth required.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Iterable

import requests

from .parse_trivy import Finding

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 20
RETRY_DELAY_S = 2.0
MAX_RETRIES = 3

_ECOSYSTEM_TO_OSV = {
    "apt": "Debian",
    "rpm": "Red Hat",
    "apk": "Alpine",
    "pip": "PyPI",
    "npm": "npm",
    "gobinary": "Go",
    "gomod": "Go",
    "jar": "Maven",
    "gem": "RubyGems",
}

log = logging.getLogger(__name__)


@dataclass
class OsvFix:
    fixed_version: str
    source: str


def _post_with_retry(session: requests.Session, payload: dict) -> dict:
    last_err: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = session.post(OSV_QUERY_URL, json=payload, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            last_err = exc
        else:
            if resp.status_code == 200:
                try:
                    return resp.json()
                except json.JSONDecodeError as exc:
                    last_err = exc
            elif resp.status_code in (429, 500, 502, 503, 504):
                last_err = RuntimeError(f"OSV {resp.status_code}: {resp.text[:200]}")
            else:
                log.debug("OSV non-retryable %s: %s", resp.status_code, resp.text[:200])
                return {}
        time.sleep(RETRY_DELAY_S * attempt)
    log.warning("OSV query failed after %s retries: %s", MAX_RETRIES, last_err)
    return {}


def query_one(session: requests.Session, finding: Finding) -> OsvFix | None:
    """Return the lowest known fixed version for `finding`, or None."""
    osv_ecosystem = _ECOSYSTEM_TO_OSV.get(finding.ecosystem)
    if not osv_ecosystem or not finding.pkg_name:
        return None

    payload = {
        "package": {"name": finding.pkg_name, "ecosystem": osv_ecosystem},
        "version": finding.installed_version or "0",
    }
    data = _post_with_retry(session, payload)
    if not data:
        return None

    cve_match = finding.cve_id.upper()
    candidates: list[str] = []

    for vuln in data.get("vulns") or []:
        aliases = {a.upper() for a in vuln.get("aliases") or []}
        aliases.add((vuln.get("id") or "").upper())
        if cve_match not in aliases:
            continue
        for affected in vuln.get("affected") or []:
            for r in affected.get("ranges") or []:
                for event in r.get("events") or []:
                    fixed = event.get("fixed")
                    if fixed:
                        candidates.append(str(fixed))

    if not candidates:
        return None

    try:
        from packaging.version import InvalidVersion, Version
        parsed = []
        for c in candidates:
            try:
                parsed.append((Version(c), c))
            except InvalidVersion:
                parsed.append((None, c))
        with_versions = [p for p in parsed if p[0] is not None]
        if with_versions:
            with_versions.sort(key=lambda p: p[0])  # type: ignore[arg-type]
            return OsvFix(fixed_version=with_versions[0][1], source="osv")
    except ImportError:
        pass

    return OsvFix(fixed_version=sorted(candidates)[0], source="osv")


def backfill(findings: Iterable[Finding]) -> dict[tuple[str, str, str], OsvFix]:
    """Look up OSV fix versions for any finding with empty Trivy fixed_version.

    Returns a dict keyed by Finding.key() with discovered fixes.
    """
    session = requests.Session()
    out: dict[tuple[str, str, str], OsvFix] = {}
    pending = [f for f in findings if not f.fixed_version]
    log.info("OSV backfill: %d findings need fix-version lookup", len(pending))
    seen: set[tuple[str, str, str]] = set()
    for f in pending:
        if f.key() in seen:
            continue
        seen.add(f.key())
        fix = query_one(session, f)
        if fix:
            out[f.key()] = fix
    return out
