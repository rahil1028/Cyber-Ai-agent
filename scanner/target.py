"""
CyberLens AI target validation.

Validates scan targets before a security assessment is created.
"""

from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_SCHEMES = {"http", "https"}


def validate_target_url(url: str) -> tuple[bool, str]:
    """
    Validate that the supplied target is a well-formed HTTP/HTTPS URL.

    Returns:
        (True, normalized_url) when valid.
        (False, error_message) when invalid.
    """

    if not isinstance(url, str):
        return False, "Target URL must be a string."

    url = url.strip()

    if not url:
        return False, "Target URL is required."

    if len(url) > 2048:
        return False, "Target URL is too long."

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, "Only HTTP and HTTPS targets are supported."

    if not parsed.netloc:
        return False, "Enter a valid website URL."

    if parsed.username or parsed.password:
        return False, "URLs containing embedded credentials are not allowed."

    hostname = parsed.hostname
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        return False, "Localhost targets are not allowed."

    try:
        resolved_addresses = {
            info[4][0]
            for info in socket.getaddrinfo(hostname, None)
        }
    except socket.gaierror:
        return False, "Target hostname could not be resolved."

    for address in resolved_addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            return False, "Private or local network targets are not allowed."
    if not hostname:
        return False, "Target hostname is missing."

    return True, url
