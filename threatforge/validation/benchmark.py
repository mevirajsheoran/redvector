"""
threatforge/validation/benchmark.py

Performance Benchmarking for Sentinel Detection

Measures:
- Detection latency (time from attack start to first block)
- Throughput impact (how many requests get through before blocking)
- False positive rate (legitimate traffic incorrectly blocked)
- Recovery time (how long until system returns to normal)

ACADEMIC VALUE:
These metrics are what security researchers use to evaluate IDS:
- High detection rate = good sensitivity
- Low latency = fast response
- Low false positive rate = accurate detection
- Fast recovery = resilient system
"""

import time
import asyncio
from typing import Dict, Any, List
from .sentinel_client import SentinelClient


class SentinelBenchmark:
    """Benchmarks Sentinel's detection performance."""

    def __init__(self, sentinel: SentinelClient):
        self.sentinel = sentinel

    async def measure_detection_latency(
        self,
        attack_type: str = "http_flood",
        rate: int = 100
    ) -> Dict[str, Any]:
        """
        Measure how quickly Sentinel detects an attack.

        ALGORITHM:
        1. Start sending attack requests
        2. Record timestamp of FIRST blocked response
        3. Latency = time from first request to first block

        Args:
            attack_type: Type of attack to measure
            rate: Requests per second

        Returns:
            Latency measurements
        """
        if not self.sentinel.is_connected():
            return {"error": "Sentinel offline"}

        start_time = time.perf_counter()
        first_block_time = None
        request_count = 0
        blocked_count = 0
        responses = []

        # Send requests until we see a block or 60 seconds pass
        paths = {
            "http_flood": ["/api/data", "/api/products", "/search"],
            "credential_stuffing": ["/login", "/auth", "/signin"],
            "enumeration": [f"/api/users/{i}" for i in range(1, 200)]
        }

        target_paths = paths.get(attack_type, ["/api/test"])
        path_idx = 0
        end_time = start_time + 60.0  # Max 60 seconds

        while time.perf_counter() < end_time:
            path = target_paths[path_idx % len(target_paths)]
            path_idx += 1

            result = self.sentinel.analyze_request(
                method="POST" if attack_type == "credential_stuffing" else "GET",
                path=path,
                status_code=401 if attack_type == "credential_stuffing" else 200
            )

            request_count += 1
            action = result.get("action", "allow")
            responses.append({
                "request_num": request_count,
                "action": action,
                "threat_score": result.get("threat_score", 0),
                "timestamp": time.perf_counter() - start_time
            })

            if action in ["block", "challenge"] and first_block_time is None:
                first_block_time = time.perf_counter() - start_time
                blocked_count += 1
            elif action in ["block", "challenge"]:
                blocked_count += 1

            # Stop after detecting
            if first_block_time and request_count >= rate * 5:
                break

            # Rate control
            await asyncio.sleep(1.0 / rate)

        total_time = time.perf_counter() - start_time

        return {
            "benchmark_type": "detection_latency",
            "attack_type": attack_type,
            "total_requests_sent": request_count,
            "first_block_at_request": next(
                (i+1 for i, r in enumerate(responses) if r["action"] in ["block", "challenge"]),
                None
            ),
            "detection_latency_seconds": round(first_block_time, 3) if first_block_time else None,
            "total_blocked": blocked_count,
            "block_rate_pct": round((blocked_count / max(request_count, 1)) * 100, 2),
            "total_benchmark_time": round(total_time, 2),
            "threat_score_progression": [
                r["threat_score"] for r in responses[::5]
            ][:20]
        }

    async def measure_false_positive_rate(
        self,
        duration_seconds: int = 60
    ) -> Dict[str, Any]:
        """
        Measure false positive rate with legitimate traffic.

        Sends NORMAL browsing traffic and counts incorrectly blocked requests.

        NORMAL traffic characteristics:
        - Varied paths (not repetitive)
        - Reasonable rate (10 RPM)
        - Normal HTTP methods
        - Realistic user-agent

        Args:
            duration_seconds: How long to send legitimate traffic

        Returns:
            False positive metrics
        """
        if not self.sentinel.is_connected():
            return {"error": "Sentinel offline"}

        import random
        normal_paths = [
            "/", "/about", "/products", "/contact",
            "/api/products", "/api/categories",
            "/search?q=test", "/profile", "/settings"
        ]

        start_time = time.perf_counter()
        end_time = start_time + duration_seconds

        total_legitimate = 0
        incorrectly_blocked = 0
        responses = []

        while time.perf_counter() < end_time:
            path = random.choice(normal_paths)
            result = self.sentinel.analyze_request(
                method="GET",
                path=path,
                status_code=200
            )

            total_legitimate += 1
            action = result.get("action", "allow")

            if action in ["block", "challenge", "shadowban"]:
                incorrectly_blocked += 1

            responses.append(action)

            # Realistic delay (human browsing pace)
            await asyncio.sleep(random.uniform(3, 8))

        false_positive_rate = (incorrectly_blocked / max(total_legitimate, 1)) * 100

        return {
            "benchmark_type": "false_positive_rate",
            "total_legitimate_requests": total_legitimate,
            "incorrectly_blocked": incorrectly_blocked,
            "false_positive_rate_pct": round(false_positive_rate, 2),
            "duration_seconds": round(time.perf_counter() - start_time, 2),
            "action_distribution": {
                action: responses.count(action)
                for action in set(responses)
            },
            "assessment": (
                "EXCELLENT" if false_positive_rate < 1.0
                else "GOOD" if false_positive_rate < 5.0
                else "NEEDS_TUNING"
            )
        }
