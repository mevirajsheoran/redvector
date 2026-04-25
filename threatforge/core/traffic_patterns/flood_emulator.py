"""
threatforge/core/traffic_patterns/flood_emulator.py

Attack Traffic Pattern Generator

Generates attack-like traffic patterns for comparison with normal baseline.
Used to prove IDS correctly distinguishes attack from normal traffic.
"""

import asyncio
import time
from typing import Dict, Any
import httpx


async def generate_attack_pattern(
    base_url: str,
    attack_type: str = "http_flood",
    duration_seconds: int = 30
) -> Dict[str, Any]:
    """
    Generate recognizable attack traffic patterns.

    Generates traffic that should trigger IDS detection.
    Contrast with normal_baseline.py output.

    Args:
        base_url: Target URL
        attack_type: Pattern type (http_flood, enumeration, scan_pattern)
        duration_seconds: Duration

    Returns:
        Attack traffic metrics for comparison with baseline
    """
    start_time = time.perf_counter()
    end_time = start_time + min(duration_seconds, 60)
    results = []

    if attack_type == "enumeration":
        # Sequential ID enumeration - obvious pattern
        paths = [f"/api/users/{i}" for i in range(1, 500)]

        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
            for path in paths:
                if time.perf_counter() >= end_time:
                    break
                try:
                    response = await client.get(f"{base_url}{path}")
                    results.append({
                        "path": path,
                        "status": response.status_code,
                        "timestamp": time.time()
                    })
                except Exception:
                    results.append({"path": path, "error": True})
                await asyncio.sleep(0.05)

    elif attack_type == "http_flood":
        # Same endpoint, high rate
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
            while time.perf_counter() < end_time:
                tasks = [client.get(base_url) for _ in range(50)]
                batch = await asyncio.gather(*tasks, return_exceptions=True)
                results.extend([
                    {"status": r.status_code if not isinstance(r, Exception) else -1}
                    for r in batch
                ])
                await asyncio.sleep(1.0)

    total_duration = time.perf_counter() - start_time

    return {
        "traffic_type": "attack_pattern",
        "attack_type": attack_type,
        "target": base_url,
        "total_requests": len(results),
        "duration_seconds": round(total_duration, 2),
        "actual_rpm": round(len(results) / (total_duration / 60), 2),
        "contrast": "Compare with normal_baseline output to see IDS detection value"
    }
