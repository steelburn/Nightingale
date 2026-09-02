"""Apply a remediation plan to the configuration/cve-mitigation/ scripts.

The plan is built by remediate.py from Trivy findings. This module is the
only place that mutates source files, so all "what changes" decisions
live here.

Patches produced:

    pip   -> bump pins in `pip-security-upgrade.sh` ('pkg>=X')
    npm   -> bump pins in `npm-global-hardening.sh` ('pkg@^X')
    apt   -> append to `vuln-library-purge` when:
             (a) package is in safe_purge_allowlist.txt,
             (b) no fix version available, and
             (c) package isn't already listed
    go    -> bump `configuration/cve-mitigation/go-min-version.txt`
             and the `ARG GO_VERSION=` lines in the two
             `programming_langauge.Dockerfile` files
    jar   -> emit a "manual review" item in the plan; no patch yet
    gomod -> let Dependabot handle nightingale-go/go.mod; emit advisory
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    from packaging.version import InvalidVersion, Version
except ImportError:  # tests may run without dep installed
    Version = None  # type: ignore[assignment]
    InvalidVersion = ValueError  # type: ignore[assignment]

log = logging.getLogger(__name__)

_DRY_RUN = False


def set_dry_run(enabled: bool) -> None:
    global _DRY_RUN
    _DRY_RUN = enabled


@dataclass
class PatchAction:
    file: str
    description: str
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class PatchResult:
    applied: list[PatchAction] = field(default_factory=list)
    skipped: list[PatchAction] = field(default_factory=list)
    needs_manual: list[PatchAction] = field(default_factory=list)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_if_changed(path: Path, new_content: str, *, original: str) -> bool:
    if new_content == original:
        return False
    if _DRY_RUN:
        return True
    path.write_text(new_content, encoding="utf-8")
    return True


def _version_gt(a: str, b: str) -> bool:
    """`a > b` using PEP 440 when possible, fall back to lexical."""
    if Version is None:
        return a > b
    try:
        return Version(a) > Version(b)
    except (InvalidVersion, TypeError):
        return a > b


_INVALID_PIN_CHARS = set(" ,\t\n\r'\"")


def _is_pin_safe(version: str) -> bool:
    """Reject pin values that would corrupt the target shell script.

    Trivy occasionally emits multi-value `FixedVersion` strings (split upstream
    by the parser, but defence-in-depth here) or stray whitespace. Anything
    that contains a comma, whitespace, or quote characters is unsafe to drop
    into a single-quoted pin like `'pkg>=X'`.
    """
    if not version:
        return False
    return not any(ch in _INVALID_PIN_CHARS for ch in version)


def _filter_safe(
    items: dict[str, str],
    plan_cves: dict[str, list[str]],
    result: PatchResult,
    file_path: Path,
    repo: Path,
    *,
    label: str,
) -> dict[str, str]:
    """Return only items with sane version strings; flag the rest for review."""
    safe: dict[str, str] = {}
    for pkg, ver in items.items():
        if _is_pin_safe(ver):
            safe[pkg] = ver
            continue
        log.warning("%s skipped: unsafe version %r for %s", label, ver, pkg)
        result.needs_manual.append(
            PatchAction(
                file=str(file_path.relative_to(repo)),
                description=(
                    f"could not pin {pkg} -- Trivy reported a non-canonical "
                    f"version string ({ver!r}); pin manually"
                ),
                cve_ids=plan_cves.get(pkg, []),
            )
        )
    return safe


# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------

_PIP_LINE_RE = re.compile(
    r"""^(?P<indent>\s*)'(?P<pkg>[A-Za-z0-9_.\-]+)>=(?P<ver>[^']+)'(?P<trail>.*)$""",
    re.MULTILINE,
)


def patch_pip(
    repo: Path,
    items: dict[str, str],  # pkg -> recommended_min_version
    plan_cves: dict[str, list[str]],
    result: PatchResult,
) -> None:
    file_path = repo / "configuration" / "cve-mitigation" / "pip-security-upgrade.sh"
    if not file_path.exists():
        log.warning("pip mitigation script not found: %s", file_path)
        return

    # Drop any pin whose computed target version is malformed; surface as
    # needs-manual so the reviewer knows the bot saw the CVE but couldn't pin.
    items = _filter_safe(items, plan_cves, result, file_path, repo, label="pip pin")

    original = _read(file_path)
    text = original
    seen_pkgs: set[str] = set()

    def replace_existing(match: re.Match[str]) -> str:
        pkg = match.group("pkg").lower()
        seen_pkgs.add(pkg)
        recommended = items.get(pkg)
        if recommended and _version_gt(recommended, match.group("ver")):
            cves = plan_cves.get(pkg, [])
            result.applied.append(
                PatchAction(
                    file=str(file_path.relative_to(repo)),
                    description=f"bump {pkg} {match.group('ver')} -> {recommended}",
                    cve_ids=cves,
                )
            )
            return f"{match.group('indent')}'{pkg}>={recommended}'{match.group('trail')}"
        return match.group(0)

    text = _PIP_LINE_RE.sub(replace_existing, text)

    new_pins = []
    for pkg, ver in sorted(items.items()):
        if pkg in seen_pkgs:
            continue
        new_pins.append((pkg, ver))

    if new_pins:
        text = _insert_pip_pins(text, new_pins, result, file_path, plan_cves, repo)

    _write_if_changed(file_path, text, original=original)


def _insert_pip_pins(
    text: str,
    pins: list[tuple[str, str]],
    result: PatchResult,
    file_path: Path,
    plan_cves: dict[str, list[str]],
    repo: Path,
) -> str:
    """Splice new pins into the existing `pip install ... 2>/dev/null || true` block."""
    block_re = re.compile(
        r"(python3 -m pip install \"\$\{PIP_ARGS\[@\]\}\"[^\n]*\n)(?P<body>(?:\s+'[^']+'[^\n]*\n)+)",
        re.MULTILINE,
    )
    match = block_re.search(text)
    if not match:
        result.needs_manual.append(
            PatchAction(
                file=str(file_path.relative_to(repo)),
                description=f"could not locate pip-install block to add {len(pins)} new pin(s)",
                cve_ids=[c for p, _ in pins for c in plan_cves.get(p, [])],
            )
        )
        return text

    body_lines = match.group("body").splitlines(keepends=True)
    # Detect indent from existing pins
    indent_match = re.match(r"(\s+)", body_lines[0])
    indent = indent_match.group(1) if indent_match else "    "
    additions = []
    for pkg, ver in pins:
        additions.append(f"{indent}'{pkg}>={ver}' \\\n")
        result.applied.append(
            PatchAction(
                file=str(file_path.relative_to(repo)),
                description=f"add new pin {pkg}>={ver}",
                cve_ids=plan_cves.get(pkg, []),
            )
        )

    new_body = "".join(additions) + "".join(body_lines)
    start, end = match.span("body")
    return text[:start] + new_body + text[end:]


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

_NPM_LINE_RE = re.compile(
    r"""^(?P<indent>\s*)'(?P<pkg>@?[A-Za-z0-9_.\-/]+)@\^(?P<ver>[^']+)'(?P<trail>.*)$""",
    re.MULTILINE,
)


def patch_npm(
    repo: Path,
    items: dict[str, str],
    plan_cves: dict[str, list[str]],
    result: PatchResult,
) -> None:
    file_path = repo / "configuration" / "cve-mitigation" / "npm-global-hardening.sh"
    if not file_path.exists():
        log.warning("npm mitigation script not found: %s", file_path)
        return

    items = _filter_safe(items, plan_cves, result, file_path, repo, label="npm pin")

    original = _read(file_path)
    text = original
    seen_pkgs: set[str] = set()

    def replace_existing(match: re.Match[str]) -> str:
        pkg = match.group("pkg").lower()
        seen_pkgs.add(pkg)
        recommended = items.get(pkg)
        if recommended and _version_gt(recommended, match.group("ver")):
            cves = plan_cves.get(pkg, [])
            result.applied.append(
                PatchAction(
                    file=str(file_path.relative_to(repo)),
                    description=f"bump {pkg} ^{match.group('ver')} -> ^{recommended}",
                    cve_ids=cves,
                )
            )
            return f"{match.group('indent')}'{pkg}@^{recommended}'{match.group('trail')}"
        return match.group(0)

    text = _NPM_LINE_RE.sub(replace_existing, text)

    new_pins = []
    for pkg, ver in sorted(items.items()):
        if pkg in seen_pkgs:
            continue
        new_pins.append((pkg, ver))

    if new_pins:
        text = _insert_npm_pins(text, new_pins, result, file_path, plan_cves, repo)

    _write_if_changed(file_path, text, original=original)


def _insert_npm_pins(
    text: str,
    pins: list[tuple[str, str]],
    result: PatchResult,
    file_path: Path,
    plan_cves: dict[str, list[str]],
    repo: Path,
) -> str:
    block_re = re.compile(
        r"(npm install -g\s*\\\n)(?P<body>(?:\s+'[^']+'[^\n]*\n)+)",
        re.MULTILINE,
    )
    match = block_re.search(text)
    if not match:
        result.needs_manual.append(
            PatchAction(
                file=str(file_path.relative_to(repo)),
                description=f"could not locate `npm install -g` block to add {len(pins)} pin(s)",
                cve_ids=[c for p, _ in pins for c in plan_cves.get(p, [])],
            )
        )
        return text

    body_lines = match.group("body").splitlines(keepends=True)
    indent_match = re.match(r"(\s+)", body_lines[0])
    indent = indent_match.group(1) if indent_match else "    "
    additions = []
    for pkg, ver in pins:
        additions.append(f"{indent}'{pkg}@^{ver}' \\\n")
        result.applied.append(
            PatchAction(
                file=str(file_path.relative_to(repo)),
                description=f"add new pin {pkg}@^{ver}",
                cve_ids=plan_cves.get(pkg, []),
            )
        )

    new_body = "".join(additions) + "".join(body_lines)
    start, end = match.span("body")
    return text[:start] + new_body + text[end:]


# ---------------------------------------------------------------------------
# apt (vuln-library-purge)
# ---------------------------------------------------------------------------

def load_purge_allowlist(repo: Path) -> set[str]:
    path = repo / "scripts" / "auto-remediate" / "safe_purge_allowlist.txt"
    if not path.exists():
        return set()
    out: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.add(line)
    return out


def patch_purge_list(
    repo: Path,
    candidates: dict[str, list[str]],  # pkg -> cve_ids
    allowlist: set[str],
    result: PatchResult,
) -> None:
    file_path = repo / "configuration" / "cve-mitigation" / "vuln-library-purge"
    if not file_path.exists():
        log.warning("vuln-library-purge not found: %s", file_path)
        return

    original = _read(file_path)
    existing = {
        ln.strip()
        for ln in original.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    }

    additions: list[str] = []
    for pkg, cves in sorted(candidates.items()):
        if pkg in existing:
            continue
        if pkg in allowlist:
            additions.append(pkg)
            result.applied.append(
                PatchAction(
                    file=str(file_path.relative_to(repo)),
                    description=f"add {pkg} (unfixed CVE)",
                    cve_ids=cves,
                )
            )
        else:
            result.needs_manual.append(
                PatchAction(
                    file=str(file_path.relative_to(repo)),
                    description=(
                        f"{pkg} has unfixed HIGH/CRITICAL CVE(s) "
                        f"but is NOT in safe_purge_allowlist.txt -- review manually"
                    ),
                    cve_ids=cves,
                )
            )

    if not additions:
        return

    new_content = original
    if not new_content.endswith("\n"):
        new_content += "\n"
    new_content += "# Added by auto-remediate bot (unfixed apt CVEs)\n"
    new_content += "\n".join(additions) + "\n"
    _write_if_changed(file_path, new_content, original=original)


# ---------------------------------------------------------------------------
# Go stdlib version bump
# ---------------------------------------------------------------------------

_GO_VERSION_LINE_RE = re.compile(
    r"^(?P<key>ARG GO_VERSION=)(?P<ver>\S+)[ \t]*$",
    re.MULTILINE,
)

# `FROM golang:1.26.2-alpine3.22 AS builder` style stages in the GUI repo's
# Go backend Dockerfiles. Capture the version separately from the tag suffix
# so we keep the alpine/distroless variant intact.
_FROM_GOLANG_RE = re.compile(
    r"""^(?P<prefix>FROM\s+golang:)(?P<ver>\d+\.\d+(?:\.\d+)?)(?P<suffix>[\-A-Za-z0-9.]*)""",
    re.MULTILINE,
)

# `local go_version="${GO_VERSION:-1.26.2}"` inside go-install-modules.sh
_GO_INSTALL_MODULES_RE = re.compile(
    r"""(?P<prefix>GO_VERSION:-)(?P<ver>\d+\.\d+\.\d+)""",
)


# Dockerfile patch targets used by patch_go_min_version. Mapping each repo to
# a list of (path, regex, label) tuples lets us share one function across both
# the core Nightingale repo and the Nightingale-GUI repo.
GO_VERSION_TARGETS: dict[str, list[tuple[str, "re.Pattern[str]", str]]] = {
    # Programming-language images (`ARG GO_VERSION=`)
    "arg_go_version": [
        ("Dockerfiles/programming_langauge.Dockerfile", _GO_VERSION_LINE_RE, "ARG GO_VERSION"),
        (
            "architecture/arm64/v8/Dockerfiles/programming_langauge.Dockerfile",
            _GO_VERSION_LINE_RE,
            "ARG GO_VERSION",
        ),
    ],
    # `FROM golang:X.Y.Z-alpine...` builder stages used in the GUI repo
    "from_golang": [
        ("Dockerfile", _FROM_GOLANG_RE, "FROM golang"),
        ("gui/go_backend/Dockerfile", _FROM_GOLANG_RE, "FROM golang"),
        ("gui/go_backend/vscode_proxy/Dockerfile", _FROM_GOLANG_RE, "FROM golang"),
    ],
    # `local go_version="${GO_VERSION:-X.Y.Z}"` inside go-install-modules.sh
    "go_install_modules": [
        (
            "configuration/modules-installation/go-install-modules.sh",
            _GO_INSTALL_MODULES_RE,
            "GO_VERSION default",
        ),
    ],
}


def patch_go_min_version(repo: Path, recommended: str | None, result: PatchResult) -> None:
    if not recommended:
        return
    version_file = repo / "configuration" / "cve-mitigation" / "go-min-version.txt"
    current = version_file.read_text(encoding="utf-8").strip() if version_file.exists() else ""

    # 1) Bump the single source of truth if it lags behind.
    if version_file.exists() and (not current or _version_gt(recommended, current)):
        if not _DRY_RUN:
            version_file.write_text(f"{recommended}\n", encoding="utf-8")
        result.applied.append(
            PatchAction(
                file=str(version_file.relative_to(repo)),
                description=f"bump Go stdlib minimum {current or '(unset)'} -> {recommended}",
            )
        )

    # 2) Independently keep every Go-version-bearing file at >= recommended.
    #    This is its own pass so that a manual go-min-version.txt edit still
    #    gets the Dockerfiles realigned on the next run (idempotent).
    for category, targets in GO_VERSION_TARGETS.items():
        for path_rel, pattern, label in targets:
            target = repo / path_rel
            if not target.exists():
                continue
            original = _read(target)

            def sub(m: re.Match[str], _category: str = category) -> str:
                if not _version_gt(recommended, m.group("ver")):
                    return m.group(0)
                if _category == "arg_go_version":
                    return f"{m.group('key')}{recommended}"
                if _category == "from_golang":
                    return f"{m.group('prefix')}{recommended}{m.group('suffix')}"
                if _category == "go_install_modules":
                    return f"{m.group('prefix')}{recommended}"
                return m.group(0)

            text = pattern.sub(sub, original)
            if _write_if_changed(target, text, original=original):
                result.applied.append(
                    PatchAction(
                        file=path_rel,
                        description=f"bump {label} -> {recommended}",
                    )
                )


# ---------------------------------------------------------------------------
# Advisory-only ecosystems (jar/maven, gomod)
# ---------------------------------------------------------------------------

def advisory_only(
    label: str,
    items: dict[str, dict[str, str]],
    result: PatchResult,
) -> None:
    for pkg, info in sorted(items.items()):
        result.needs_manual.append(
            PatchAction(
                file=f"<advisory:{label}>",
                description=(
                    f"{pkg} {info.get('installed', '?')} -> "
                    f"{info.get('fixed', '?')} (handled outside Nightingale build)"
                ),
                cve_ids=info.get("cves", []),  # type: ignore[arg-type]
            )
        )
