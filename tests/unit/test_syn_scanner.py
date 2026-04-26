"""
tests/unit/test_syn_scanner.py

Unit tests for TCP SYN scanner.

NOTE: These tests use 127.0.0.1 (localhost) which is always available.
We start a simple TCP server in fixtures for testing.
"""

import pytest
import socket
import threading
from threatforge.core.recon.syn_scanner import (
    check_port_tcp_connect,
    scan_ports,
    PORT_GROUPS,
    COMMON_PORTS
)


@pytest.fixture(scope="module")
def tcp_test_server():
    """Start a simple TCP server on port 19876 for testing."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 19876))
    server.listen(5)
    server.settimeout(1)

    running = True

    def accept_connections():
        while running:
            try:
                conn, _ = server.accept()
                conn.close()
            except socket.timeout:
                pass
            except Exception:
                break

    thread = threading.Thread(target=accept_connections, daemon=True)
    thread.start()

    yield 19876

    running = False
    server.close()


class TestTCPConnectScan:

    def test_open_port_detected(self, tcp_test_server):
        """Port with server should be detected as open"""
        result = check_port_tcp_connect("127.0.0.1", tcp_test_server)
        assert result == "open"

    def test_closed_port_detected(self):
        """Port with nothing listening should be closed"""
        result = check_port_tcp_connect("127.0.0.1", 19999, timeout=0.5)
        assert result == "closed"

    def test_timeout_returns_filtered(self):
        """Unreachable host should return filtered"""
        result = check_port_tcp_connect("10.255.255.255", 80, timeout=0.3)
        assert result in ("filtered", "closed")


class TestPortGroupScan:

    def test_scan_returns_required_fields(self):
        """Scan result should have all required fields"""
        result = scan_ports("127.0.0.1", [19999, 19998], timing="fast")
        assert "open_ports" in result
        assert "port_details" in result
        assert "scan_duration_seconds" in result
        assert "target" in result

    def test_port_groups_exist(self):
        """All port groups should be defined"""
        for group in ["top_20", "top_100", "web", "database"]:
            assert group in PORT_GROUPS
            assert len(PORT_GROUPS[group]) > 0

    def test_scan_duration_measured(self):
        """Scan should measure duration"""
        result = scan_ports("127.0.0.1", [19999], timing="fast")
        assert result["scan_duration_seconds"] >= 0

    def test_details_include_service_names(self):
        """Port details should include service name lookup"""
        result = scan_ports("127.0.0.1", [80, 443, 22], timing="fast")
        for detail in result["port_details"]:
            assert "service" in detail
            assert "port" in detail
            assert "status" in detail
