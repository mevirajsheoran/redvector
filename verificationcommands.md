# ══════════════════════════════════════════════
# FINAL VERIFICATION SEQUENCE
# Run each command. All must succeed before demo.
# ══════════════════════════════════════════════

# 1. Activate environment
cd ~/projects/threatforge
source venv/bin/activate

# 2. Install all dependencies
pip install -r requirements.txt

# 3. Run unit tests
pytest tests/unit/ -v --tb=short
# Expect: 20+ tests PASSED, 0 failed

# 4. Start Docker lab
docker compose up -d
sleep 10
docker compose ps
# Expect: 4 containers Up

# 5. Start ThreatForge backend
uvicorn threatforge.main:app --reload --port 9000 &
sleep 3
curl http://localhost:9000/
# Expect: JSON with module list

# 6. Test all API endpoints
curl http://localhost:9000/api/crypto/ciphers
curl http://localhost:9000/api/recon/targets
curl http://localhost:9000/api/dos/status
curl http://localhost:9000/api/validate/status

# 7. Run crypto demo
python scripts/demo_crypto.py
# Expect: Colorful output with successful cipher attacks

# 8. Run recon demo
python scripts/demo_recon.py
# Expect: Port scan results, banner grabs

# 9. Run DoS demo
python scripts/demo_dos.py
# Expect: Flood metrics, baseline comparison

# 10. Build React dashboard
cd dashboard
npm install
npm run build
npm run dev &
cd ..
sleep 3
# Expect: http://localhost:5173 shows dashboard

# 11. Final git commit
git add .
git commit -m "Complete ThreatForge - All 5 parts done - Ready for submission"
git push origin main

# 12. Print final status
echo "════════════════════════════════════════"
echo "  THREATFORGE READY FOR SUBMISSION"
echo "════════════════════════════════════════"
echo "  API:         http://localhost:9000"
echo "  Dashboard:   http://localhost:5173"
echo "  API Docs:    http://localhost:9000/docs"
echo "  Test suite:  pytest tests/unit/"
echo "  Demo:        python scripts/demo_full.py"
echo "════════════════════════════════════════"