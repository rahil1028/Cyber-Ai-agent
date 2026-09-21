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

    # ------------------------------------------------------------
    # TLS / certificate checks
    # ------------------------------------------------------------

    tls = evidence.get("tls")

    if evidence.get("https") and tls:

        protocol = tls.get("protocol")

        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            add_finding(
                title="Outdated TLS protocol version in use",
                severity="high",
                category="Transport Security",
                description=f"The server negotiated {protocol}, which is a deprecated protocol version.",
                impact="Deprecated TLS versions are vulnerable to known cryptographic weaknesses and are being phased out by browsers.",
                remediation="Disable TLS 1.0/1.1 and SSLv3/v2 on the server; require TLS 1.2 or higher.",
                cwe="CWE-326",
            )

        expires_in_days = tls.get("expires_in_days")

        if expires_in_days is not None:
            if expires_in_days < 0:
                add_finding(
                    title="TLS certificate has expired",
                    severity="high",
                    category="Transport Security",
                    description="The server's TLS certificate is past its expiration date.",
                    impact="Browsers will show security warnings and users may lose trust in the site; encrypted connections may be rejected.",
                    remediation="Renew the TLS certificate immediately and enable auto-renewal.",
                    cwe="CWE-298",
                )
            elif expires_in_days < 15:
                add_finding(
                    title="TLS certificate expiring soon",
                    severity="medium",
                    category="Transport Security",
                    description=f"The server's TLS certificate expires in {expires_in_days} day(s).",
                    impact="An expired certificate will break secure connections and trigger browser warnings.",
                    remediation="Renew the TLS certificate before expiry and enable auto-renewal where possible.",
                    cwe="CWE-298",
                    confidence="medium",
                )

    elif evidence.get("https") and tls is None:
        add_finding(
            title="TLS certificate could not be verified",
            severity="medium",
            category="Transport Security",
            description="A direct TLS connection to the host could not be established or inspected during the assessment.",
            impact="This may indicate an untrusted certificate, connection restrictions, or misconfiguration; manual verification is recommended.",
            remediation="Manually verify the certificate chain, expiry, and negotiated TLS version for this host.",
            cwe="CWE-295",
            confidence="low",
        )

    # ------------------------------------------------------------
    # Cookie security
    # ------------------------------------------------------------

    cookies = evidence.get("cookies") or []

    if cookies:
        missing_secure = [c["name"] for c in cookies if evidence.get("https") and not c["secure"]]
        missing_httponly = [c["name"] for c in cookies if not c["httponly"]]
        missing_samesite = [c["name"] for c in cookies if not c["samesite"]]

        if missing_secure:
            add_finding(
                title="Cookies set without the Secure attribute",
                severity="high",
                category="Session Management",
                description=f"{len(missing_secure)} cookie(s) were set without the Secure attribute over HTTPS: {', '.join(missing_secure)}.",
                impact="These cookies could be transmitted over an unencrypted connection if the user is ever downgraded to HTTP, exposing session data.",
                remediation="Set the Secure attribute on all cookies, especially session and authentication cookies.",
                cwe="CWE-614",
            )

        if missing_httponly:
            add_finding(
                title="Cookies set without the HttpOnly attribute",
                severity="medium",
                category="Session Management",
                description=f"{len(missing_httponly)} cookie(s) were set without the HttpOnly attribute: {', '.join(missing_httponly)}.",
                impact="Cookies without HttpOnly can be read by client-side JavaScript, increasing impact if an XSS vulnerability exists.",
                remediation="Set the HttpOnly attribute on session and authentication cookies.",
                cwe="CWE-1004",
            )

        if missing_samesite:
            add_finding(
                title="Cookies set without a SameSite attribute",
                severity="low",
                category="Session Management",
                description=f"{len(missing_samesite)} cookie(s) were set without a SameSite attribute: {', '.join(missing_samesite)}.",
                impact="Missing SameSite protection can increase exposure to cross-site request forgery in some scenarios.",
                remediation="Set SameSite=Lax or SameSite=Strict on cookies where appropriate.",
                cwe="CWE-352",
                confidence="medium",
            )

    # ------------------------------------------------------------
    # CORS misconfiguration
    # ------------------------------------------------------------

    cors = evidence.get("cors") or {}
    allow_origin = cors.get("allow_origin")
    allow_credentials = cors.get("allow_credentials")

    if allow_origin == "*" and str(allow_credentials).lower() == "true":
        add_finding(
            title="Permissive CORS policy with credentials allowed",
            severity="high",
            category="Access Control",
            description="The response allows any origin (Access-Control-Allow-Origin: *) while also allowing credentials.",
            impact="This combination can allow malicious sites to make authenticated cross-origin requests on behalf of a user.",
            remediation="Restrict Access-Control-Allow-Origin to a specific trusted origin when Access-Control-Allow-Credentials is true.",
            cwe="CWE-942",
        )
    elif allow_origin == "*":
        add_finding(
            title="Wildcard CORS policy in use",
            severity="low",
            category="Access Control",
            description="The response allows cross-origin requests from any origin (Access-Control-Allow-Origin: *).",
            impact="Any website can read this response client-side; this may be intentional for public APIs but should be reviewed.",
            remediation="Confirm that this endpoint is intended to be publicly accessible from any origin.",
            cwe="CWE-942",
            confidence="medium",
        )

    # ------------------------------------------------------------
    # Exposed sensitive files
    # ------------------------------------------------------------

    exposed_paths = evidence.get("exposed_paths") or []

    for path in exposed_paths:
        add_finding(
            title=f"Potentially sensitive file exposed: {path}",
            severity="high",
            category="Information Disclosure",
            description=f"A request to {path} returned an HTTP 200 response, suggesting the file may be publicly accessible.",
            impact="Exposed configuration or version-control files can leak credentials, secrets, or source code.",
            remediation=f"Restrict public access to {path} at the web server or application routing level, and rotate any credentials it may contain.",
            cwe="CWE-538",
            confidence="medium",
        )

    # ------------------------------------------------------------
    # Existing header checks
    # ------------------------------------------------------------

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
