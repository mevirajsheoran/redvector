"""
tests/unit/test_http_flood.py

Unit tests for HTTP flood module.
Uses local HTTP server to avoid external calls.
"""

import pytest
import asyncio
import threading
import http.server
from threatforge.core.dos_simulation.http_flood import HTTPFlood, http_get_flood


@pytest.fixture(scope="module")
def local_http_server():
    """Start local HTTP server for flood testing."""
    class QuietHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        def log_message(self, format, *args):
            pass  # Suppress output

    server = http.server.HTTPServer(("127.0.0.1", 18765), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:18765"
    server.shutdown()


class TestHTTPFloodInit:

    def test_rate_limit_capped(self):
        """Rate should be capped at MAX"""
        flood = HTTPFlood("http://localhost", rate_limit=99999)
        assert flood.rate_limit <= 500

    def test_default_initialization(self):
        """Default initialization should work"""
        flood = HTTPFlood("http://localhost", rate_limit=10)
        assert flood.target_url == "http://localhost"
        assert flood.rate_limit == 10


class TestHTTPFloodExecution:

    @pytest.mark.asyncio
    async def test_flood_returns_metrics(self, local_http_server):
        """Flood should return complete metrics"""
        flood = HTTPFlood(local_http_server, rate_limit=5)
        result = await flood.execute(duration_seconds=5)

        assert "total_requests_sent" in result
        assert "actual_rps" in result
        assert "success_rate_pct" in result
        assert "duration_seconds" in result

    @pytest.mark.asyncio
    async def test_flood_sends_requests(self, local_http_server):
        """Flood should actually send requests"""
        flood = HTTPFlood(local_http_server, rate_limit=10)
        result = await flood.execute(duration_seconds=3)
        assert result["total_requests_sent"] > 0

    @pytest.mark.asyncio
    async def test_flood_measures_duration(self, local_http_server):
        """Duration should be measured accurately"""
        flood = HTTPFlood(local_http_server, rate_limit=5)
        result = await flood.execute(duration_seconds=5)
        assert 4.0 <= result["duration_seconds"] <= 7.0

    @pytest.mark.asyncio
    async def test_high_success_rate_local(self, local_http_server):
        """Against local server, success rate should be high"""
        result = await http_get_flood(local_http_server, 10, 5)
        assert result["success_rate_pct"] > 50.0
