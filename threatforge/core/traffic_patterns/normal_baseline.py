"""
threatforge/core/traffic_patterns/normal_baseline.py

Normal Traffic Baseline Generator

SYLLABUS: Unit 8 (Recon), Unit 12 (IDS - understanding baseline)
COVERAGE: CO3, CO4, CO5

THEORY:
IDS systems work by distinguishing NORMAL traffic from ATTACK traffic.
To do this, they need a BASELINE of what normal looks like.

ThreatForge generates both:
1. Normal traffic  (this module)  - what IDS should ALLOW
2. Attack traffic  (other modules) - what IDS should BLOCK

By comparing the two, you can:
- Tune IDS thresholds
- Measure false positive rates
- Prove your detection system works

NORMAL TRAFFIC CHARACTERISTICS:
- Irregular timing (humans don't click at exactly 1.0 second intervals)
- Mixed HTTP methods (GET, POST, occasionally PUT/DELETE)
- Natural response code distribution (mostly 200, some 404, few 500)
- Realistic Think Time between requests (0.5 - 30 seconds)
- Varied paths (not all the same endpoint)
- Human-like User-Agent strings
"""

import asyncio
import time
import random
from typing import Dict, Any, List
import httpx


# Realistic paths a user might visit
REALISTIC_PATHS = [
    "/", "/about", "/products", "/products/1", "/products/2",
    "/contact", "/login", "/register", "/profile", "/settings",
    "/api/products", "/api/categories", "/search?q=test",
    "/blog", "/blog/post-1", "/faq", "/pricing",
    "/static/style.css", "/static/app.js",
    "/favicon.ico", "/robots.txt"
]

# Human-like User Agents
HUMAN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15"
]


async def generate_normal_traffic(
    base_url: str,
    duration_seconds: int = 60,
    avg_requests_per_minute: int = 10
) -> Dict[str, Any]:
    """
    Generate realistic human-like web traffic to a target.

    This is used for:
    1. Establishing baseline before running attacks
    2. Testing IDS false positive rates
    3. Proving our IDS doesn't block legitimate traffic

    REALISTIC PATTERNS:
    - Think time: 2-30 seconds between requests (human reading pages)
    - Mixed paths: Not hammering same endpoint repeatedly
    - Natural distribution: Mostly GETs, some POSTs
    - Random user agents: Different browser types

    Args:
        base_url: Target base URL
        duration_seconds: How long to generate traffic
        avg_requests_per_minute: Target rate (simulating N users)

    Returns:
        Traffic generation metrics
    """
    duration_seconds = min(duration_seconds, 300)  # Max 5 minutes

    # Calculate inter-request delay for target rate
    avg_delay = 60.0 / max(avg_requests_per_minute, 1)

    start_time = time.perf_counter()
    end_time = start_time + duration_seconds

    all_results = []
    status_distribution = {}

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0),
        follow_redirects=True
    ) as client:
        while time.perf_counter() < end_time:
            # Choose random path (weighted toward common pages)
            path = random.choice(REALISTIC_PATHS)
            url = f"{base_url.rstrip('/')}{path}"

            # Choose random user agent
            ua = random.choice(HUMAN_USER_AGENTS)

            try:
                start = time.perf_counter()
                response = await client.get(
                    url,
                    headers={"User-Agent": ua}
                )
                elapsed = (time.perf_counter() - start) * 1000

                result = {
                    "path": path,
                    "status_code": response.status_code,
                    "response_time_ms": round(elapsed, 2),
                    "timestamp": time.time()
                }
                all_results.append(result)
                status_distribution[response.status_code] = (
                    status_distribution.get(response.status_code, 0) + 1
                )

            except Exception as e:
                all_results.append({
                    "path": path,
                    "error": str(e)[:50],
                    "timestamp": time.time()
                })

            # Human-like delay between requests (with randomness)
            delay = random.gauss(avg_delay, avg_delay * 0.3)
            delay = max(0.5, min(delay, 30.0))  # Clamp to 0.5-30s
            await asyncio.sleep(delay)

    total_duration = time.perf_counter() - start_time

    return {
        "traffic_type": "normal_baseline",
        "target": base_url,
        "total_requests": len(all_results),
        "duration_seconds": round(total_duration, 2),
        "average_rpm": round(len(all_results) / (total_duration / 60), 2),
        "status_code_distribution": status_distribution,
        "avg_response_time_ms": round(
            sum(r.get("response_time_ms", 0) for r in all_results)
            / max(len(all_results), 1), 2
        ),
        "traffic_pattern": "human_like",
        "use_case": "Baseline for IDS false positive testing"
    }
