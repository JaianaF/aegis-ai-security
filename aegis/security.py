from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from .config import ALLOW_PRIVATE_TARGETS


class UnsafeTargetError(ValueError):
    pass


def validate_target_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeTargetError("Only http/https targets are supported.")
    if not parsed.hostname:
        raise UnsafeTargetError("Target hostname is missing.")

    hostname = parsed.hostname.lower()
    if hostname in {"localhost", "localhost.localdomain"} and not ALLOW_PRIVATE_TARGETS:
        raise UnsafeTargetError("Local/private targets are blocked by default. Set ALLOW_PRIVATE_TARGETS=true for an authorized lab.")

    if ALLOW_PRIVATE_TARGETS:
        return

    try:
        infos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"Could not resolve target hostname: {exc}") from exc

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise UnsafeTargetError("Private, loopback, link-local and reserved targets are blocked by default.")
