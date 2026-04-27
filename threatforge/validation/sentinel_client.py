"""
threatforge/validation/sentinel_client.py

Sentinel/Vigil API Client

This module communicates with the running Sentinel/Vigil instance
to validate its detection capabilities.

SENTINEL RUNS ON: http://localhost:8000
THREATFORGE RUNS ON: http://localhost:9000

IMPORTANT:
This is the ONLY file that knows about Sentinel.
All other ThreatForge modules are independent.
The validation layer is OPTIONAL - ThreatForge works without it.

SENTINEL API ENDPOINTS WE USE:
POST /v1/analyze            → Send request through Sentinel analysis
GET  /v1/attacks            → List detected attack sessions
GET  /v1/analytics/overview → Block rates, threat scores, totals
GET  /v1/fingerprints       → Fingerprint threat scores
GET  /v1/analytics/top-threats → Top threat fingerprints
"""

import time
import requests
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class SentinelStats:
    """Snapshot of Sentinel's statistics at a point in time."""
    total_requests: int = 0
    blocked: int = 0
    allowed: int = 0
    suspicious: int = 0
    unique_fingerprints: int = 0
    avg_threat_score: float = 0.0
    block_rate_pct: float = 0.0
    attack_sessions: List[Dict] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class SentinelClient:
    """
    HTTP client for Sentinel/Vigil API.

    Handles connection, retries, and response parsing.
    All methods return structured data regardless of connection state.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 5.0
    ):
        """
        Initialize Sentinel client.

        Args:
            base_url: Sentinel base URL (default: localhost:8000)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._connected = None  # None = not tested yet

    def test_connection(self) -> bool:
        """
        Test if Sentinel is reachable and responding.

        Returns:
            True if connected, False otherwise
        """
        try:
            response = requests.get(
                f"{self.base_url}/health",
                timeout=self.timeout
            )
            self._connected = response.status_code < 500
            return self._connected
        except Exception:
            self._connected = False
            return False

    def is_connected(self) -> bool:
        """Return connection status (uses cached result if available)."""
        if self._connected is None:
            return self.test_connection()
        return self._connected

    def analyze_request(
        self,
        method: str = "GET",
        path: str = "/",
        status_code: Optional[int] = None,
        body_hash: Optional[str] = None,
        headers: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Send a request through Sentinel's analysis endpoint.

        This is how we generate attack traffic that Sentinel processes.
        Each call to this endpoint is one "request" that Sentinel sees.

        Sentinel returns:
        - action: allow/block/challenge/shadowban
        - threat_score: 0.0 - 1.0
        - fingerprint: Device fingerprint hash
        - velocity_rpm: Current requests per minute
        - phase: Which detection phase triggered

        Args:
            method: HTTP method of simulated request
            path: URL path being accessed
            status_code: Response code (for post-hoc analysis)
            body_hash: Hash of request body
            headers: Additional headers to include

        Returns:
            Sentinel's analysis decision
        """
        if not self.is_connected():
            return {
                "action": "unknown",
                "reason": "sentinel_offline",
                "threat_score": 0.0,
                "fingerprint": "offline",
                "velocity_rpm": 0,
                "phase": "offline"
            }

        try:
            payload = {
                "method": method,
                "path": path,
            }
            if status_code is not None:
                payload["status_code"] = status_code
            if body_hash is not None:
                payload["body_hash"] = body_hash

            response = requests.post(
                f"{self.base_url}/v1/analyze",
                json=payload,
                headers=headers or {},
                timeout=self.timeout
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "action": "error",
                    "reason": f"sentinel_returned_{response.status_code}",
                    "threat_score": 0.0,
                    "fingerprint": "error",
                    "velocity_rpm": 0,
                    "phase": "error"
                }

        except Exception as e:
            return {
                "action": "error",
                "reason": str(e)[:100],
                "threat_score": 0.0,
                "fingerprint": "exception",
                "velocity_rpm": 0,
                "phase": "exception"
            }

    def get_analytics_overview(self, hours: int = 1) -> Dict[str, Any]:
        """
        Get Sentinel's analytics overview.

        Returns block rate, total requests, threat scores.
        Called before AND after attacks to measure delta.

        Args:
            hours: Time window in hours

        Returns:
            Analytics data or empty dict if offline
        """
        if not self.is_connected():
            return {}

        try:
            response = requests.get(
                f"{self.base_url}/v1/analytics/overview",
                params={"hours": hours},
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception:
            return {}

    def get_attack_sessions(
        self,
        limit: int = 20,
        status: Optional[str] = None
    ) -> List[Dict]:
        """
        Get list of attack sessions detected by Sentinel.

        Called after firing attacks to see if Sentinel caught them.

        Args:
            limit: Maximum sessions to return
            status: Filter by status (active, mitigated, etc.)

        Returns:
            List of attack session dicts
        """
        if not self.is_connected():
            return []

        try:
            params = {"limit": limit}
            if status:
                params["status"] = status

            response = requests.get(
                f"{self.base_url}/v1/attacks",
                params=params,
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception:
            return []

    def get_top_threats(self, hours: int = 1, limit: int = 10) -> List[Dict]:
        """
        Get top threat fingerprints from Sentinel.

        Args:
            hours: Time window
            limit: Maximum results

        Returns:
            List of top threat fingerprints with scores
        """
        if not self.is_connected():
            return []

        try:
            response = requests.get(
                f"{self.base_url}/v1/analytics/top-threats",
                params={"hours": hours, "limit": limit},
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception:
            return []

    def get_fingerprints(
        self,
        limit: int = 20,
        blocked_only: bool = False
    ) -> List[Dict]:
        """
        Get fingerprints tracked by Sentinel.

        Args:
            limit: Maximum fingerprints to return
            blocked_only: Only return blocked fingerprints

        Returns:
            List of fingerprint dicts with threat scores
        """
        if not self.is_connected():
            return []

        try:
            response = requests.get(
                f"{self.base_url}/v1/fingerprints",
                params={"limit": limit, "blocked_only": blocked_only},
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception:
            return []

    def snapshot_stats(self) -> SentinelStats:
        """
        Take a complete snapshot of Sentinel's current state.

        Called before and after attacks to compute deltas.

        Returns:
            SentinelStats dataclass with all current metrics
        """
        overview = self.get_analytics_overview(hours=1)
        attacks = self.get_attack_sessions(limit=50)

        return SentinelStats(
            total_requests=overview.get("total_requests", 0),
            blocked=overview.get("blocked", 0),
            allowed=overview.get("allowed", 0),
            suspicious=overview.get("suspicious", 0),
            unique_fingerprints=overview.get("unique_fingerprints", 0),
            avg_threat_score=overview.get("avg_threat_score", 0.0),
            block_rate_pct=overview.get("block_rate_pct", 0.0),
            attack_sessions=attacks,
            timestamp=time.time()
        )

    def compute_delta(
        self,
        before: SentinelStats,
        after: SentinelStats
    ) -> Dict[str, Any]:
        """
        Compute the change in Sentinel's stats between two snapshots.

        This is how we measure what Sentinel detected during our attack.

        Args:
            before: Stats snapshot before attack
            after: Stats snapshot after attack

        Returns:
            Delta metrics showing Sentinel's response to the attack
        """
        new_sessions = [
            s for s in after.attack_sessions
            if s not in before.attack_sessions
        ]

        return {
            "new_requests_processed": after.total_requests - before.total_requests,
            "new_blocked": after.blocked - before.blocked,
            "new_suspicious": after.suspicious - before.suspicious,
            "block_rate_change": round(after.block_rate_pct - before.block_rate_pct, 2),
            "new_attack_sessions": new_sessions,
            "attack_sessions_detected": len(new_sessions),
            "avg_threat_score_change": round(
                after.avg_threat_score - before.avg_threat_score, 4
            ),
            "time_elapsed_seconds": round(after.timestamp - before.timestamp, 2)
        }
