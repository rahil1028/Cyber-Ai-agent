"""
CyberLens AI HTTP assessment module.

Collects passive HTTP/HTTPS evidence from an authorized target.
"""

import socket
import ssl
from datetime import datetime, timezone
from time import perf_counter
from urllib.parse import urlsplit, urlunsplit

import requests


DEFAULT_TIMEOUT = 10
PROBE_TIMEOUT = 6

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
]


def _inspect_cookies(response: requests.Response) -> list[dict]:
    """Inspect Set-Cookie headers for missing security attributes."""

    try:
        raw_cookies = response.raw.headers.getlist("Set-Cookie")
    except Exception:
        single = response.headers.get("set-cookie")
        raw_cookies = [single] if single else []

    cookies_info = []

    for raw in raw_cookies:
        if not raw:
            continue

        lowered = raw.lower()
        name = raw.split("=", 1)[0].strip()

        cookies_info.append({
            "name": name,
            "secure": "secure" in lowered,
            "httponly": "httponly" in lowered,
            "samesite": "samesite" in lowered,
        })

    return cookies_info


def _inspect_cors(headers: dict) -> dict:
    """Inspect CORS-related response headers."""

    return {
        "allow_origin": headers.get("access-control-allow-origin"),
        "allow_credentials": headers.get("access-control-allow-credentials"),
    }


def _inspect_tls(hostname: str) -> dict | None:
    """Open a TLS connection to collect certificate and protocol info."""

    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=PROBE_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:

                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()

        not_after_raw = cert.get("notAfter")
        expires_in_days = None

        if not_after_raw:
            expires_at = datetime.strptime(
                not_after_raw, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            expires_in_days = (expires_at - datetime.now(timezone.utc)).days

        return {
            "protocol": protocol,
            "expires_in_days": expires_in_days,
        }

    except Exception:
        return None


def _probe_sensitive_paths(base_url: str) -> list[str]:
    """Check whether common sensitive files are publicly exposed."""

    parts = urlsplit(base_url)
    origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    exposed = []

    for path in SENSITIVE_PATHS:
        try:
            probe = requests.get(
                origin + path,
                timeout=PROBE_TIMEOUT,
                allow_redirects=False,
                headers={
                    "User-Agent": "CyberLens-AI-Security-Assessment/1.0"
                },
            )

            if probe.status_code == 200 and len(probe.content) > 0:
                exposed.append(path)

        except Exception:
            continue

    return exposed


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

    is_https = response.url.lower().startswith("https://")
    hostname = urlsplit(response.url).hostname

    tls_info = _inspect_tls(hostname) if (is_https and hostname) else None

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
        "https": is_https,
        "cookies": _inspect_cookies(response),
        "cors": _inspect_cors(headers),
        "tls": tls_info,
        "exposed_paths": _probe_sensitive_paths(response.url),
    }
