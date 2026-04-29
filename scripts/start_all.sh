#!/bin/bash
# scripts/start_all.sh
# Start everything for ThreatForge demo

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ⚔ THREATFORGE - STARTING ALL SERVICES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check we are in project root
if [ ! -f "requirements.txt" ]; then
    echo "❌ Run this from threatforge project root"
    exit 1
fi

# Step 1: Start Docker lab
echo ""
echo "Step 1: Starting Docker test lab..."
docker compose up -d
sleep 5
echo "✅ Docker lab started"

# Step 2: Activate venv
echo ""
echo "Step 2: Activating Python environment..."
source venv/bin/activate
echo "✅ Virtual environment active"

# Step 3: Start ThreatForge backend
echo ""
echo "Step 3: Starting ThreatForge backend (port 9000)..."
uvicorn threatforge.main:app --reload --port 9000 &
THREATFORGE_PID=$!
sleep 3

# Verify
if curl -s http://localhost:9000/health > /dev/null 2>&1; then
    echo "✅ ThreatForge API running at http://localhost:9000"
else
    echo "❌ ThreatForge failed to start"
fi

# Step 4: Start React dashboard
echo ""
echo "Step 4: Starting React dashboard (port 5173)..."
cd dashboard && npm run dev &
DASHBOARD_PID=$!
cd ..
sleep 3
echo "✅ Dashboard starting at http://localhost:5173"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  THREATFORGE READY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  API:         http://localhost:9000"
echo "  API Docs:    http://localhost:9000/docs"
echo "  Dashboard:   http://localhost:5173"
echo ""
echo "  ALSO START SENTINEL (separate terminal):"
echo "  cd ~/your-sentinel-folder"
echo "  uvicorn Vigil.main:app --reload --port 8000"
echo ""
echo "  THEN RUN DEMO:"
echo "  python scripts/demo_full.py"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for Ctrl+C
trap "kill $THREATFORGE_PID $DASHBOARD_PID 2>/dev/null; docker compose down; echo 'All stopped'; exit" INT
wait
