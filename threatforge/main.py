"""ThreatForge - Main FastAPI Application

This module provides the main FastAPI application instance for ThreatForge,
an offensive security testing framework for educational use.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="ThreatForge",
    description="Offensive Security Testing Framework for Educational Use",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Root endpoint returning application metadata."""
    return {
        "name": "ThreatForge",
        "version": "0.1.0",
        "status": "operational",
        "ethics": "See ETHICS.md - Educational use only",
        "documentation": "/docs",
        "endpoints": {
            "health": "/health",
            "docs": "/docs"
        }
    }


@app.get("/health")
async def health():
    """Health check endpoint for monitoring and container orchestration."""
    return {
        "status": "healthy",
        "service": "threatforge-backend",
        "version": "0.1.0"
    }
