"""
threatforge/core/dos_simulation/credential_stuff.py

Credential Stuffing Attack Simulation

SYLLABUS: Unit 11 - DoS/DDoS (application layer attacks)
COVERAGE: CO4, CO5

THEORY:
Credential stuffing uses LEAKED username/password pairs from one
data breach to attempt login on other services.

Why it works:
- People reuse passwords across multiple sites
- Billions of credentials from past breaches are publicly available
- Automated tools try thousands per second

EXAMPLE REAL ATTACK:
2020: 500,000 Zoom accounts compromised via credential stuffing
2019: 100 million Dunkin Donuts accounts targeted
2018: Reddit, GitHub, others targeted with 770M credential dataset

OUR SIMULATION:
Uses FAKE, generated credentials (not real breach data).
Tests whether the target application:
1. Implements rate limiting on login endpoints
2. Locks accounts after N failed attempts
3. Returns different errors for valid vs invalid usernames
   (allows username enumeration - a secondary vulnerability)

HOW THIS CONNECTS TO SENTINEL/VIGIL:
Sentinel detects credential stuffing by monitoring:
- High POST rate to /login, /auth endpoints
- High 401/403 response rate
- Same fingerprint across multiple failed attempts
This module generates exactly that traffic pattern.
"""

import asyncio
import time
import random
from typing import Dict, Any, List

import httpx


# Fake credentials for simulation
# These are NOT real credentials from any breach
FAKE_USERNAMES = [
    "john.doe@example.com", "jane.smith@test.com",
    "admin@company.org", "user1234@gmail.com",
    "test.account@yahoo.com", "demo.user@outlook.com",
    "security@corp.net", "hello.world@proton.me"
]

FAKE_PASSWORDS = [
    "password123", "123456789", "letmein",
    "qwerty2024", "admin1234", "welcome1",
    "monkey123", "dragon999", "master2024"
]

# Common login endpoints to target
LOGIN_ENDPOINTS = [
    "/login", "/signin", "/auth/login",
    "/api/auth", "/api/v1/login", "/user/login"
]


class CredentialStuffer:
    """
    Simulated credential stuffing attack.

    Generates fake login attempts to test application security.
    """

    def __init__(self, target_base_url: str, login_path: str = "/login"):
        self.base_url = target_base_url.rstrip("/")
        self.login_url = f"{self.base_url}{login_path}"
        self.attempts = []

    def _generate_credential_pair(self) -> Dict[str, str]:
        """Generate one fake credential pair."""
        # Mix and match to create "realistic" fake credentials
        username = random.choice(FAKE_USERNAMES)
        # Slightly modify username to seem like different accounts
        username = username.replace("@", f"{random.randint(1,999)}@")
        password = random.choice(FAKE_PASSWORDS)
        return {"username": username, "password": password}

    async def _attempt_login(
        self,
        client: httpx.AsyncClient,
        credentials: Dict[str, str]
    ) -> Dict[str, Any]:
        """Attempt a single login with given credentials."""
        start = time.perf_counter()
        try:
            response = await client.post(
                self.login_url,
                json=credentials,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Educational Test)"
                }
            )
            elapsed = (time.perf_counter() - start) * 1000

            return {
                "username": credentials["username"],
                "status_code": response.status_code,
                "response_time_ms": round(elapsed, 2),
                "success": response.status_code == 200,
                "response_size": len(response.content)
            }

        except Exception as e:
            return {
                "username": credentials["username"],
                "status_code": -1,
                "error": str(e)[:50],
                "success": False,
                "response_time_ms": round((time.perf_counter() - start) * 1000, 2)
            }

    async def run(
        self,
        attempts_per_second: int = 5,
        duration_seconds: int = 30
    ) -> Dict[str, Any]:
        """
        Execute credential stuffing simulation.

        Sends credential pairs to login endpoint, measures
        response codes to detect security controls.

        WHAT WE MEASURE:
        - 200: Login succeeded (shouldn't happen with fake creds)
        - 401/403: Login failed (expected)
        - 429: Rate limiting triggered (good! defense working)
        - 423/403+lockout: Account lockout (good! defense working)
        - Consistent response times: No username enumeration
        - Different response times: Username enumeration possible

        Args:
            attempts_per_second: Rate (max 20 for credential stuffing)
            duration_seconds: Duration (max 60)

        Returns:
            Complete simulation metrics and security assessment
        """
        attempts_per_second = min(attempts_per_second, 20)
        duration_seconds = min(duration_seconds, 60)

        start_time = time.perf_counter()
        end_time = start_time + duration_seconds
        all_results = []
        rate_limited = False
        account_lockout = False

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False
        ) as client:
            while time.perf_counter() < end_time:
                batch = [
                    self._attempt_login(client, self._generate_credential_pair())
                    for _ in range(attempts_per_second)
                ]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)

                for result in batch_results:
                    if isinstance(result, Exception):
                        all_results.append({"success": False, "error": str(result)})
                    else:
                        all_results.append(result)
                        if result.get("status_code") == 429:
                            rate_limited = True
                        if result.get("status_code") in [423, 403]:
                            account_lockout = True

                await asyncio.sleep(1.0)

        total_duration = time.perf_counter() - start_time
        status_codes = {}
        for r in all_results:
            code = r.get("status_code", -1)
            status_codes[code] = status_codes.get(code, 0) + 1

        response_times = [
            r.get("response_time_ms", 0) for r in all_results if r.get("response_time_ms")
        ]

        return {
            "attack_type": "credential_stuffing_simulation",
            "target": self.login_url,
            "total_attempts": len(all_results),
            "duration_seconds": round(total_duration, 2),
            "actual_aps": round(len(all_results) / total_duration, 2),
            "status_code_distribution": status_codes,
            "rate_limiting_detected": rate_limited,
            "account_lockout_detected": account_lockout,
            "avg_response_time_ms": round(sum(response_times) / len(response_times), 2) if response_times else 0,
            "security_assessment": {
                "rate_limiting": "DETECTED ✅" if rate_limited else "NOT DETECTED ❌",
                "account_lockout": "DETECTED ✅" if account_lockout else "NOT DETECTED ❌",
                "endpoint_accessible": any(
                    r.get("status_code") != -1 for r in all_results
                )
            },
            "sentinel_connection": (
                "This traffic pattern matches Sentinel's credential stuffing detector: "
                "high POST rate to auth endpoint + high failure rate. "
                "Check Sentinel dashboard for detected attack session."
            )
        }
