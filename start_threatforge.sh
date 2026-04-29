#!/bin/bash
# ThreatForge startup script
# Auto-detects Windows host IP for WSL2 networking

WINDOWS_IP=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
echo "Windows host IP: $WINDOWS_IP"
echo "Vigil URL will be: http://$WINDOWS_IP:8000"

# Test if Vigil is reachable
if curl -s --max-time 2 http://$WINDOWS_IP:8000/health > /dev/null 2>&1; then
    echo "✅ Vigil is reachable at http://$WINDOWS_IP:8000"
else
    echo "⚠️  Warning: Cannot reach Vigil at http://$WINDOWS_IP:8000"
    echo "   Make sure Vigil is running on Windows with --host 0.0.0.0"
fi

# Start ThreatForge with correct Sentinel URL
export SENTINEL_URL="http://$WINDOWS_IP:8000"
source venv/bin/activate
uvicorn threatforge.main:app --reload --port 9000 --host 0.0.0.0
