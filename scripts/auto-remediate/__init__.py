"""Nightingale auto-remediation toolkit.

Reads Trivy JSON scan output, classifies HIGH/CRITICAL OSS findings per
ecosystem (apt, pip, npm, gobinary, gomod, jar), maps each to the matching
mitigation file under configuration/cve-mitigation/, and produces a
remediation plan that update_mitigations.py applies as in-place patches.

Designed to be invoked from .github/workflows/auto-remediate.yml after
Trivy Scan completes. Never auto-merges -- always opens a PR.
"""

__version__ = "0.1.0"
