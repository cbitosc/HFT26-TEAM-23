from __future__ import annotations

import socket
import sys
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from live_scan import scan_live_connections


HOST_ADDRESSES = {
    "api.openai.com": "203.0.113.10",
    "api.anthropic.com": "203.0.113.11",
    "huggingface.co": "203.0.113.12",
    "api.featherless.ai": "203.0.113.13",
    "generativelanguage.googleapis.com": "203.0.113.14",
}


def _connection(
    *,
    pid: int | None,
    ip: str,
    port: int,
    status: str = psutil.CONN_ESTABLISHED,
) -> SimpleNamespace:
    return SimpleNamespace(
        pid=pid,
        raddr=(ip, port),
        status=status,
    )


def _resolve(host: str, port: int, *, type: int) -> list[tuple]:
    assert port == 443
    assert type == socket.SOCK_STREAM
    return [
        (2, 1, 6, "", (HOST_ADDRESSES[host], port)),
    ]


def test_identifies_process_with_established_provider_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("live_scan.socket.getaddrinfo", _resolve)
    monkeypatch.setattr(
        "live_scan.psutil.net_connections",
        lambda kind: [
            _connection(pid=431, ip=HOST_ADDRESSES["api.openai.com"], port=443),
            _connection(pid=432, ip="203.0.113.99", port=443),
            _connection(
                pid=433,
                ip=HOST_ADDRESSES["api.openai.com"],
                port=443,
                status=psutil.CONN_LISTEN,
            ),
        ] if kind == "tcp" else pytest.fail("Only TCP connections should be queried"),
    )
    monkeypatch.setattr(
        "live_scan.psutil.Process",
        lambda pid: SimpleNamespace(name=lambda: "assistant-app")
        if pid == 431
        else pytest.fail("Unexpected process lookup"),
    )

    result = scan_live_connections()

    assert len(result.connections) == 1
    assert result.connections[0].process_name == "assistant-app"
    assert result.connections[0].pid == 431
    assert result.connections[0].remote_endpoint == "203.0.113.10:443"
    assert result.connections[0].provider == "openai"
    assert result.connections[0].recognized_endpoint == "api.openai.com"
    assert result.warnings == ()


def test_identifies_local_ollama_by_default_port_without_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "live_scan.psutil.net_connections",
        lambda kind: [_connection(pid=51, ip="127.0.0.1", port=11434)]
        if kind == "tcp"
        else pytest.fail("Only TCP connections should be queried"),
    )
    monkeypatch.setattr(
        "live_scan.psutil.Process",
        lambda pid: SimpleNamespace(name=lambda: "ollama")
        if pid == 51
        else pytest.fail("Unexpected process lookup"),
    )

    def unexpected_dns(host: str, port: int, *, type: int) -> list[tuple]:
        assert host in HOST_ADDRESSES
        assert port == 443
        assert type == socket.SOCK_STREAM
        pytest.fail("DNS should not be needed for local Ollama")

    monkeypatch.setattr(
        "live_scan.socket.getaddrinfo",
        unexpected_dns,
    )

    result = scan_live_connections()

    assert len(result.connections) == 1
    assert result.connections[0].process_name == "ollama"
    assert result.connections[0].provider == "ollama"
    assert result.connections[0].recognized_endpoint == "localhost:11434"


def test_reports_provider_dns_resolution_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def failed_resolution(*_args: object, **_kwargs: object) -> list[tuple]:
        assert _args
        assert _kwargs.get("type") == socket.SOCK_STREAM
        raise socket.gaierror("name resolution unavailable")

    monkeypatch.setattr("live_scan.socket.getaddrinfo", failed_resolution)
    monkeypatch.setattr(
        "live_scan.psutil.net_connections",
        lambda kind: [_connection(pid=71, ip="203.0.113.10", port=443)]
        if kind == "tcp"
        else pytest.fail("Only TCP connections should be queried"),
    )

    result = scan_live_connections()

    assert result.connections == ()
    assert any("Could not resolve api.openai.com" in warning for warning in result.warnings)


def test_reports_connections_without_process_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("live_scan.socket.getaddrinfo", _resolve)
    monkeypatch.setattr(
        "live_scan.psutil.net_connections",
        lambda kind: [_connection(pid=901, ip=HOST_ADDRESSES["api.openai.com"], port=443)]
        if kind == "tcp"
        else pytest.fail("Only TCP connections should be queried"),
    )

    def denied_process(pid: int) -> SimpleNamespace:
        assert pid == 901
        raise psutil.AccessDenied(pid=pid)

    monkeypatch.setattr("live_scan.psutil.Process", denied_process)

    result = scan_live_connections()

    assert len(result.connections) == 1
    assert result.connections[0].process_name == "Unavailable (permission denied)"
    assert any("PID 901" in warning for warning in result.warnings)


def test_propagates_system_denial_of_connection_table(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied_connections(kind: str) -> list:
        assert kind == "tcp"
        raise psutil.AccessDenied()

    monkeypatch.setattr("live_scan.psutil.net_connections", denied_connections)

    with pytest.raises(psutil.AccessDenied):
        scan_live_connections()
