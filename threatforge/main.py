"""
threatforge/main.py

ThreatForge - Main FastAPI Application Entry Point

ETHICAL USE: Authorized testing in isolated environments only.
See ETHICS.md for full statement.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from threatforge.api.crypto import router as crypto_router

# Create FastAPI app
app = FastAPI(
    title="ThreatForge",
    description=(
        "Offensive Security Testing Framework - Educational Use Only. "
        "See /ethics for full statement."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS - Allow React dashboard to call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(crypto_router)
# More routers will be added in Part 3 (recon, dos, patterns)
# app.include_router(recon_router)      <- Week 2
# app.include_router(dos_router)        <- Week 3
# app.include_router(patterns_router)   <- Week 3
# app.include_router(validation_router) <- Week 4

@app.get("/")
async def root():
    return {
        "name": "ThreatForge",
        "version": "0.1.0",
        "status": "operational",
        "modules": {
            "cryptanalysis": "operational",
            "reconnaissance": "coming_week2",
            "dos_simulation": "coming_week3",
            "validation": "coming_week4"
        },
        "docs": "/docs",
        "ethics": "/ethics"
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "0.1.0"}

@app.get("/ethics")
async def ethics():
    return {
        "statement": "ThreatForge is for authorized testing in isolated environments only",
        "allowed_targets": [
            "Systems you own",
            "Docker lab environments",
            "Systems with written authorization",
            "DVWA, WebGoat, and similar training apps"
        ],
        "prohibited": [
            "Production systems without authorization",
            "Third-party websites or services",
            "Public infrastructure"
        ],
        "full_statement": "See ETHICS.md in project root"
    }
