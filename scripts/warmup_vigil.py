#!/usr/bin/env python3
"""
Warm up Vigil with normal traffic before running attack tests.
This gives Vigil history so its detection algorithms work properly.
"""
import asyncio
import httpx
import random
import time

VIGIL = "http://172.28.64.1:8000"

NORMAL_PATHS = ["/api/products", "/api/users/me", "/api/search",
                "/api/categories", "/api/orders", "/health"]

async def send_normal_traffic():
    """Send 50 normal requests to warm up Vigil"""
    print(f"[*] Warming up Vigil at {VIGIL}")
    print("[*] Sending 50 normal requests...")

    async with httpx.AsyncClient(timeout=5.0) as client:
        for i in range(50):
            path = random.choice(NORMAL_PATHS)
            try:
                await client.post(f"{VIGIL}/v1/analyze", json={
                    "method": "GET",
                    "path": path,
                    "status_code": 200
                }, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                })
                if i % 10 == 0:
                    print(f"    Sent {i+1}/50 requests...")
                await asyncio.sleep(random.uniform(0.5, 1.5))
            except Exception as e:
                print(f"    Error: {e}")

    print("[✓] Warmup complete. Vigil now has baseline history.")
    print("[*] Wait 5 seconds for background worker to process...")
    await asyncio.sleep(5)
    print("[✓] Ready for attack tests!")

asyncio.run(send_normal_traffic())
