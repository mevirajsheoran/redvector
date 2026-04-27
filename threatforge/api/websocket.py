"""
threatforge/api/websocket.py

WebSocket Live Feed for React Dashboard

Pushes real-time updates to the dashboard without polling.

HOW IT WORKS:
1. React dashboard connects to ws://localhost:9000/ws/live-feed
2. FastAPI accepts connection, adds to connected_clients list
3. When any attack runs, it calls broadcast_event()
4. broadcast_event() sends JSON to ALL connected dashboards
5. React receives JSON, updates live terminal display

MESSAGE FORMAT:
{
    "type": "attack_event",
    "data": {
        "timestamp": 1234567890.123,
        "module": "dos_simulation",
        "attack_type": "http_flood",
        "target": "http://172.25.0.12",
        "metric": "requests_sent",
        "value": 1500,
        "status": "running"
    }
}

EVENT TYPES:
- attack_started     → Attack beginning
- attack_progress    → Per-second metric update
- attack_complete    → Attack finished with summary
- sentinel_detected  → Sentinel blocked something
- validation_result  → Validation test result
- system_status      → General status update
"""

import json
import asyncio
import time
from typing import List, Dict, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["WebSocket"])

# Global list of connected dashboard clients
# All connected browsers receive every event
connected_clients: List[WebSocket] = []


async def broadcast_event(event_type: str, data: Dict[str, Any]):
    """
    Send event to ALL connected dashboard clients.

    Called by attack modules to push real-time updates.

    Args:
        event_type: Type of event (attack_started, progress, etc.)
        data: Event payload dict
    """
    if not connected_clients:
        return  # No dashboards connected, skip

    message = json.dumps({
        "type": event_type,
        "timestamp": time.time(),
        "data": data
    })

    # Send to all clients, remove disconnected ones
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)

    for client in disconnected:
        if client in connected_clients:
            connected_clients.remove(client)


async def send_attack_started(
    module: str,
    attack_type: str,
    target: str,
    parameters: Dict
):
    """Notify dashboard that an attack has started."""
    await broadcast_event("attack_started", {
        "module": module,
        "attack_type": attack_type,
        "target": target,
        "parameters": parameters,
        "status": "running"
    })


async def send_attack_progress(
    attack_type: str,
    metrics: Dict
):
    """Send per-second progress update to dashboard."""
    await broadcast_event("attack_progress", {
        "attack_type": attack_type,
        "metrics": metrics,
        "status": "running"
    })


async def send_attack_complete(
    attack_type: str,
    final_metrics: Dict
):
    """Notify dashboard that attack is complete."""
    await broadcast_event("attack_complete", {
        "attack_type": attack_type,
        "final_metrics": final_metrics,
        "status": "complete"
    })


async def send_sentinel_event(
    event_type: str,
    detection_data: Dict
):
    """Send Sentinel detection event to dashboard."""
    await broadcast_event("sentinel_detected", {
        "sentinel_event": event_type,
        "detection": detection_data,
        "status": "detected"
    })


@router.websocket("/ws/live-feed")
async def live_feed_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for React dashboard.

    Connection lifecycle:
    1. Dashboard connects
    2. Send welcome message with current status
    3. Keep alive with heartbeat every 30 seconds
    4. Push events as attacks run
    5. Clean up on disconnect
    """
    await websocket.accept()
    connected_clients.append(websocket)

    # Send welcome message
    await websocket.send_text(json.dumps({
        "type": "connected",
        "timestamp": time.time(),
        "data": {
            "message": "ThreatForge Live Feed Connected",
            "connected_dashboards": len(connected_clients),
            "version": "0.1.0"
        }
    }))

    try:
        # Keep connection alive with periodic heartbeat
        while True:
            # Check for any incoming messages from dashboard
            try:
                message = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                # Echo back (ping-pong keepalive)
                if message == "ping":
                    await websocket.send_text(json.dumps({
                        "type": "pong",
                        "timestamp": time.time()
                    }))

            except asyncio.TimeoutError:
                # Send heartbeat every 30 seconds
                await websocket.send_text(json.dumps({
                    "type": "heartbeat",
                    "timestamp": time.time(),
                    "data": {
                        "connected_dashboards": len(connected_clients)
                    }
                }))

    except WebSocketDisconnect:
        pass
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


@router.get("/ws/status")
async def websocket_status():
    """Get WebSocket connection status."""
    return {
        "connected_dashboards": len(connected_clients),
        "ws_endpoint": "ws://localhost:9000/ws/live-feed"
    }
