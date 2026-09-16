"""
CyberLens AI assessment engine.

Runs the passive assessment pipeline for an authorized target.
"""

from scanner.http import inspect_target
from scanner.findings import build_findings


def run_assessment(target_url: str) -> dict:
    """
    Run the passive security assessment pipeline.

    Returns:
        A structured assessment result containing HTTP evidence
        and normalized security findings.
    """

    evidence = inspect_target(target_url)

    findings = build_findings(evidence)

    return {
        "target_url": target_url,
        "evidence": evidence,
        "findings": findings,
        "findings_count": len(findings),
    }
