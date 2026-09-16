"""
CyberLens AI passive findings engine.

Converts HTTP assessment evidence into actionable security findings.
"""

from typing import Any


def build_findings(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Build security findings from passive HTTP evidence."""

    findings = []
    headers = evidence.get("security_headers", {})

    def add_finding(
        title: str,
        severity: str,
        category: str,
        description: str,
        impact: str,
        remediation: str,
        cwe: str,
        confidence: str = "high",
    ) -> None:
        findings.append({
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "cwe": cwe,
            "confidence": confidence,
        })

    if not evidence.get("https"):
        add_finding(
            title="HTTPS is not enforced",
            severity="high",
            category="Transport Security",
            description="The assessment target resolved to a non-HTTPS URL.",
            impact="Traffic may be exposed to interception or modification.",
            remediation="Serve the application exclusively over HTTPS and redirect HTTP to HTTPS.",
            cwe="CWE-319",
        )

    if not headers.get("Content-Security-Policy"):
        add_finding(
            title="Content Security Policy header missing",
            severity="medium",
            category="Security Headers",
            description="No Content-Security-Policy response header was observed.",
            impact="The browser has fewer restrictions against certain client-side injection scenarios.",
            remediation="Define and deploy a restrictive Content-Security-Policy appropriate to the application.",
            cwe="CWE-693",
            confidence="medium",
        )

    if not headers.get("Strict-Transport-Security"):
        add_finding(
            title="HTTP Strict Transport Security header missing",
            severity="medium",
            category="Security Headers",
            description="No Strict-Transport-Security response header was observed.",
            impact="Browsers may continue allowing HTTP connections where HTTPS should be preferred.",
            remediation="Enable HSTS after confirming HTTPS is correctly configured across the application.",
            cwe="CWE-319",
            confidence="high",
        )

    if not headers.get("X-Content-Type-Options"):
        add_finding(
            title="X-Content-Type-Options header missing",
            severity="low",
            category="Security Headers",
            description="No X-Content-Type-Options response header was observed.",
            impact="Browsers may perform MIME type sniffing in situations where explicit content types should be respected.",
            remediation="Set X-Content-Type-Options to nosniff.",
            cwe="CWE-16",
            confidence="high",
        )

    if not headers.get("X-Frame-Options"):
        add_finding(
            title="Clickjacking protection header missing",
            severity="low",
            category="Security Headers",
            description="No X-Frame-Options header was observed.",
            impact="The application may be more exposed to UI redress or clickjacking scenarios.",
            remediation="Use X-Frame-Options or an appropriate frame-ancestors directive in Content-Security-Policy.",
            cwe="CWE-1021",
            confidence="medium",
        )

    if not headers.get("Referrer-Policy"):
        add_finding(
            title="Referrer-Policy header missing",
            severity="low",
            category="Security Headers",
            description="No Referrer-Policy response header was observed.",
            impact="URLs or path information may be disclosed to other origins through the Referer header.",
            remediation="Set an explicit Referrer-Policy such as strict-origin-when-cross-origin.",
            cwe="CWE-200",
            confidence="medium",
        )

    if not headers.get("Permissions-Policy"):
        add_finding(
            title="Permissions-Policy header missing",
            severity="info",
            category="Security Headers",
            description="No Permissions-Policy response header was observed.",
            impact="Browser feature access is not explicitly restricted by this response header.",
            remediation="Define a Permissions-Policy appropriate to the browser features used by the application.",
            cwe="CWE-16",
            confidence="medium",
        )

    if evidence.get("server"):
        add_finding(
            title="Server technology information disclosed",
            severity="info",
            category="Information Disclosure",
            description="The HTTP response exposes a Server header.",
            impact="Technology information can assist reconnaissance and fingerprinting.",
            remediation="Remove or minimize unnecessary server identification headers.",
            cwe="CWE-200",
            confidence="high",
        )

    if evidence.get("powered_by"):
        add_finding(
            title="Framework technology information disclosed",
            severity="low",
            category="Information Disclosure",
            description="The HTTP response exposes an X-Powered-By header.",
            impact="Framework information can assist technology fingerprinting.",
            remediation="Disable or remove the X-Powered-By header where possible.",
            cwe="CWE-200",
            confidence="high",
        )

    return findings
