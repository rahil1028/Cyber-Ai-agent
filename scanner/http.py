"""
CyberLens AI HTTP assessment module.

Collects passive HTTP/HTTPS evidence from an authorized target.
"""

from time import perf_counter

import requests


DEFAULT_TIMEOUT = 10

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def inspect_target(url: str) -> dict:
    """
    Fetch an authorized target and collect passive HTTP evidence.
    """

    started = perf_counter()

    response = requests.get(
        url,
        timeout=DEFAULT_TIMEOUT,
        allow_redirects=True,
        headers={
            "User-Agent": "CyberLens-AI-Security-Assessment/1.0"
        },
    )

    elapsed_ms = round(
        (perf_counter() - started) * 1000,
        2,
    )

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    security_headers = {
        name: headers.get(header_key)
        for header_key, name in SECURITY_HEADERS.items()
    }

    return {
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "response_time_ms": elapsed_ms,
        "redirect_count": len(response.history),
        "content_type": headers.get("content-type"),
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "security_headers": security_headers,
        "https": response.url.lower().startswith("https://"),
    }
