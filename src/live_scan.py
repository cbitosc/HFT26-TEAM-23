"""Read-only snapshot of processes connected to recognized AI endpoints."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any

import psutil

from ai_detector import HOST_PROVIDERS, OLLAMA_PORT

CLOUD_ENDPOINT_PORT = 443


@dataclass(frozen=True)
class LiveConnection:
    process_name: str
    pid: int
    remote_endpoint: str
    provider: str
    recognized_endpoint: str


@dataclass(frozen=True)
class LiveScanResult:
    connections: tuple[LiveConnection, ...]
    warnings: tuple[str, ...]


def _normalize_ip(value: str) -> str:
    address = ipaddress.ip_address(value.split("%", 1)[0])
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def _remote_address(address: Any) -> tuple[str, int] | None:
    if not address:
        return None
    try:
        return _normalize_ip(str(address[0])), int(address[1])
    except (IndexError, TypeError, ValueError):
        return None


def _resolve_provider_addresses() -> tuple[dict[str, set[tuple[str, str]]], list[str]]:
    addresses: dict[str, set[tuple[str, str]]] = {}
    warnings: list[str] = []
    for hostname, provider in HOST_PROVIDERS.items():
        try:
            results = socket.getaddrinfo(hostname, CLOUD_ENDPOINT_PORT, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            warnings.append(f"Could not resolve {hostname} for provider matching: {exc}")
            continue
        for result in results:
            try:
                address = _normalize_ip(str(result[4][0]))
            except (IndexError, TypeError, ValueError):
                continue
            addresses.setdefault(address, set()).add((provider, hostname))
    return addresses, warnings


def scan_live_connections() -> LiveScanResult:
    """Find established TCP sockets matching known provider endpoints.

    Only socket metadata and process names are read; connection contents are not
    inspected.
    """
    connections = psutil.net_connections(kind="tcp")
    active = [
        (connection, _remote_address(connection.raddr))
        for connection in connections
        if connection.status == psutil.CONN_ESTABLISHED and connection.raddr
    ]
    cloud_active = any(remote is not None and remote[1] == CLOUD_ENDPOINT_PORT for _, remote in active)
    provider_addresses, warnings = (
        _resolve_provider_addresses() if cloud_active else ({}, [])
    )
    results: list[LiveConnection] = []
    process_names: dict[int, str] = {}
    warning_set = set(warnings)

    for connection, remote in active:
        if remote is None:
            continue
        ip, port = remote
        if port == OLLAMA_PORT:
            provider = "ollama"
            recognized_endpoint = f"localhost:{OLLAMA_PORT}"
        elif port == CLOUD_ENDPOINT_PORT and ip in provider_addresses:
            matches = provider_addresses[ip]
            providers = sorted({item[0] for item in matches})
            hostnames = sorted({item[1] for item in matches})
            provider = providers[0] if len(providers) == 1 else f"Ambiguous: {', '.join(providers)}"
            recognized_endpoint = ", ".join(hostnames)
        else:
            continue

        pid = connection.pid
        if pid is None:
            warning_set.add(
                f"Could not attribute {provider} connection at {ip}:{port}: the operating system did not provide a PID."
            )
            continue
        if pid not in process_names:
            try:
                process_names[pid] = psutil.Process(pid).name()
            except psutil.AccessDenied:
                process_names[pid] = "Unavailable (permission denied)"
                warning_set.add(f"Permission denied while reading the process name for PID {pid}.")
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        results.append(
            LiveConnection(
                process_name=process_names[pid],
                pid=pid,
                remote_endpoint=f"{ip}:{port}",
                provider=provider,
                recognized_endpoint=recognized_endpoint,
            )
        )

    return LiveScanResult(
        connections=tuple(results),
        warnings=tuple(sorted(warning_set)),
    )
