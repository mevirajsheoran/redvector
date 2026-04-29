#!/bin/bash
# Stop all ThreatForge services
echo "Stopping all ThreatForge services..."
pkill -f "uvicorn threatforge" || true
pkill -f "npm run dev" || true
docker compose down || true
echo "✅ All stopped"
