"""
CyberLens AI assessment engine.

Runs the passive (and optionally safe active) assessment pipeline
for an authorized target.
"""

from scanner.http import inspect_target
from scanner.findings import build_findings
from scanner.active import run_active_checks


def run_assessment(target_url: str, profile: str = "passive") -> dict:
    """
    Run the security assessment pipeline.

    Args:
        target_url: The authorized target to assess.
        profile: "passive" for header/TLS/cookie/CORS/exposed-file
            checks only, or "safe_active" to additionally run
            lightweight, non-destructive active probes.

    Returns:
        A structured assessment result containing HTTP evidence
        and normalized security findings.
    """

    evidence = inspect_target(target_url)

    findings = build_findings(evidence)

    if profile == "safe_active":
        findings = findings + run_active_checks(evidence.get("final_url", target_url))

    return {
        "target_url": target_url,
        "profile": profile,
        "evidence": evidence,
        "findings": findings,
        "findings_count": len(findings),
    }
