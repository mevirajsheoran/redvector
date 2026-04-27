"""
tests/integration/test_full_pipeline.py

Integration test for complete ThreatForge pipeline.
Tests that all modules can run end-to-end.
"""

import pytest
import asyncio
from threatforge.core.crypto_attacks.caesar import encrypt_caesar, run_full_caesar_analysis
from threatforge.core.dos_simulation.http_flood import http_get_flood
from threatforge.validation.sentinel_client import SentinelClient


class TestCryptoPipeline:

    def test_caesar_encrypt_and_attack(self):
        ciphertext = encrypt_caesar("Hello World Security Test", 7)
        result = run_full_caesar_analysis(ciphertext)
        assert result["final_answer"]["key"] == 7
        assert result["methods_agree"]


class TestDoSPipeline:

    @pytest.mark.asyncio
    async def test_http_flood_metrics(self):
        """HTTP flood should return complete metrics"""
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 18888), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        result = await http_get_flood("http://127.0.0.1:18888", 5, 5)
        server.shutdown()

        assert "total_requests_sent" in result
        assert result["total_requests_sent"] > 0
        assert "actual_rps" in result


class TestSentinelClient:

    def test_sentinel_client_handles_offline(self):
        """Client should handle offline Sentinel gracefully"""
        client = SentinelClient("http://localhost:19999")  # Wrong port
        assert not client.test_connection()

    def test_snapshot_returns_default_when_offline(self):
        """Snapshot should return empty stats when Sentinel offline"""
        client = SentinelClient("http://localhost:19999")
        stats = client.snapshot_stats()
        assert stats.total_requests == 0
        assert stats.block_rate_pct == 0.0
