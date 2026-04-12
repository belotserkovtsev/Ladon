"""Basic probe implementation for split-engine."""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any


def probe_domain(domain: str, timeout: float = 2.0) -> dict[str, Any]:
    """Run a staged probe for a domain.

    Stages:
    - DNS resolve
    - TCP 443 connect against resolved IPs
    - TLS handshake with SNI against the first reachable IP
    """
    started = time.monotonic()
    result: dict[str, Any] = {
        "domain": domain,
        "dns_ok": False,
        "tcp_ok": False,
        "tls_ok": False,
        "http_ok": None,
        "resolved_ips": [],
        "failure_reason": None,
        "latency_ms": None,
    }

    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        resolved_ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
        result["resolved_ips"] = resolved_ips
        result["dns_ok"] = bool(resolved_ips)
    except OSError as e:
        result["failure_reason"] = f"dns:{e}"
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        return result

    reachable_ip = None
    for ip in result["resolved_ips"][:3]:
        try:
            with socket.create_connection((ip, 443), timeout=timeout):
                reachable_ip = ip
                result["tcp_ok"] = True
                break
        except OSError:
            continue

    if not result["tcp_ok"]:
        result["failure_reason"] = "tcp_connect_failed"
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((reachable_ip, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                result["tls_ok"] = True
    except OSError as e:
        result["failure_reason"] = f"tls:{e}"

    result["latency_ms"] = int((time.monotonic() - started) * 1000)
    return result
