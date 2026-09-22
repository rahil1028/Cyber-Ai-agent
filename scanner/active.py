"""
CyberLens AI safe active assessment module.

Performs lightweight, non-destructive active probes against an
authorized target to surface higher-confidence, higher-severity
findings than passive header inspection alone.

All probes are read-only, single-request checks: no data is modified,
no authentication is bypassed, and no exploitation is attempted.
"""

from urllib.parse import urlsplit, urlunsplit, quote

import requests


PROBE_TIMEOUT = 8

REFLECTED_XSS_MARKER = "cl_probe_7f3a<'\">"

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query()",
    "ora-01756",
    "sqlite3::",
    "sqlite error",
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
]


def _probe_reflected_input(base_url: str) -> dict | None:
    """
    Append a benign, non-executing marker as a query parameter and
    check whether it is reflected back unescaped in the response body.
    Unescaped reflection is a strong indicator of a reflected XSS
    surface, without ever attempting actual script execution.
    """

    parts = urlsplit(base_url)
    separator = "&" if parts.query else "?"
    probe_url = base_url + separator + "cl_probe=" + quote(REFLECTED_XSS_MARKER)

    try:
        response = requests.get(
            probe_url,
            timeout=PROBE_TIMEOUT,
            headers={"User-Agent": "CyberLens-AI-Security-Assessment/1.0"},
        )
    except Exception:
        return None

    if REFLECTED_XSS_MARKER in response.text:
        return {
            "title": "Unsanitized input reflected in page response",
            "severity": "high",
            "category": "Input Validation",
            "description": (
                "A test value passed via a query parameter was reflected "
                "back in the page response without apparent encoding."
            ),
            "impact": (
                "If user-controlled input is rendered without proper output "
                "encoding, this can enable reflected Cross-Site Scripting (XSS) "
                "and similar client-side injection attacks."
            ),
            "remediation": (
                "Apply context-aware output encoding to all reflected user "
                "input, and validate/sanitize input on the server side. "
                "Consider a strict Content-Security-Policy as defense in depth."
            ),
            "cwe": "CWE-79",
            "confidence": "medium",
        }

    return None


def _probe_sql_error_disclosure(base_url: str) -> dict | None:
    """
    Append a single SQL metacharacter to a query parameter and check
    the response for common database error signatures. This does not
    attempt to extract data or bypass authentication — it only checks
    whether the application leaks raw database errors.
    """

    parts = urlsplit(base_url)
    separator = "&" if parts.query else "?"
    probe_url = base_url + separator + "cl_probe=" + quote("cyberlens'\"")

    try:
        response = requests.get(
            probe_url,
            timeout=PROBE_TIMEOUT,
            headers={"User-Agent": "CyberLens-AI-Security-Assessment/1.0"},
        )
    except Exception:
        return None

    body_lower = response.text.lower()

    for signature in SQL_ERROR_SIGNATURES:
        if signature in body_lower:
            return {
                "title": "Database error message disclosed",
                "severity": "high",
                "category": "Input Validation",
                "description": (
                    "A raw database error message was observed in the response "
                    "after submitting a single quotation character in a query parameter."
                ),
                "impact": (
                    "Disclosed database errors can indicate a SQL Injection surface "
                    "and may leak information about the underlying database structure."
                ),
                "remediation": (
                    "Use parameterized queries / prepared statements for all database "
                    "access, and disable verbose error output in production, "
                    "replacing it with generic error pages."
                ),
                "cwe": "CWE-89",
                "confidence": "medium",
            }

    return None


def _probe_directory_listing(base_url: str) -> dict | None:
    """Check whether common asset directories expose directory listings."""

    parts = urlsplit(base_url)
    origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    for path in ["/uploads/", "/assets/", "/files/", "/backup/", "/static/"]:
        try:
            response = requests.get(
                origin + path,
                timeout=PROBE_TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": "CyberLens-AI-Security-Assessment/1.0"},
            )
        except Exception:
            continue

        body_lower = response.text.lower()

        if response.status_code == 200 and (
            "index of /" in body_lower or "<title>directory listing" in body_lower
        ):
            return {
                "title": f"Directory listing enabled at {path}",
                "severity": "medium",
                "category": "Configuration",
                "description": f"The path {path} returned a browsable directory listing.",
                "impact": "Directory listings can expose files that were not meant to be publicly discoverable.",
                "remediation": "Disable directory listing/autoindex on the web server for this and similar paths.",
                "cwe": "CWE-548",
                "confidence": "medium",
            }

    return None


def run_active_checks(base_url: str) -> list[dict]:
    """
    Run the safe active assessment probes against an authorized target.

    Returns a list of additional findings (may be empty).
    """

    findings = []

    for probe in (
        _probe_reflected_input,
        _probe_sql_error_disclosure,
        _probe_directory_listing,
    ):
        try:
            result = probe(base_url)
            if result:
                findings.append(result)
        except Exception:
            continue

    return findings
