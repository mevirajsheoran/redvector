#!/bin/bash
echo "═══════════════════════════════════════"
echo "  THREATFORGE NETWORK DIAGNOSTICS"
echo "═══════════════════════════════════════"

WINDOWS_IP=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
echo ""
echo "WSL2 IP:      $(hostname -I | awk '{print $1}')"
echo "Windows IP:   $WINDOWS_IP"
echo ""

echo "─── Service Status ───"

# Vigil
if curl -s --max-time 2 http://$WINDOWS_IP:8000/health > /dev/null 2>&1; then
    echo "✅ Vigil        http://$WINDOWS_IP:8000 - ONLINE"
else
    echo "❌ Vigil        http://$WINDOWS_IP:8000 - OFFLINE"
    echo "   Fix: uvicorn Vigil.main:app --host 0.0.0.0 --port 8000"
fi

# ThreatForge
if curl -s --max-time 2 http://localhost:9000/health > /dev/null 2>&1; then
    echo "✅ ThreatForge  http://localhost:9000 - ONLINE"
else
    echo "❌ ThreatForge  http://localhost:9000 - OFFLINE"
    echo "   Fix: uvicorn threatforge.main:app --port 9000"
fi

# Docker Lab
if curl -s --max-time 2 http://172.25.0.12 > /dev/null 2>&1; then
    echo "✅ Docker Lab   http://172.25.0.12 - ONLINE"
else
    echo "❌ Docker Lab   http://172.25.0.12 - OFFLINE"
    echo "   Fix: docker compose up -d"
fi

echo ""
echo "─── Validation Check ───"
RESULT=$(curl -s --max-time 5 http://localhost:9000/api/validate/status 2>/dev/null)
if echo $RESULT | grep -q "true"; then
    echo "✅ Sentinel connection verified via ThreatForge API"
else
    echo "❌ ThreatForge cannot reach Sentinel"
    echo "   Raw response: $RESULT"
fi

echo ""
echo "═══════════════════════════════════════"
