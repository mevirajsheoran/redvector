"""
threatforge/api/validation.py

FastAPI endpoints for Sentinel/Vigil Validation Layer.

ENDPOINTS:
GET  /api/validate/status           - Check Sentinel connection
POST /api/validate/http-flood       - Validate HTTP flood detection
POST /api/validate/credential-stuff - Validate credential stuffing detection
POST /api/validate/enumeration      - Validate enumeration detection
POST /api/validate/full-suite       - Run complete test suite
GET  /api/validate/matrix           - Get current validation matrix
POST /api/validate/benchmark/latency   - Measure detection latency
POST /api/validate/benchmark/fp-rate   - Measure false positive rate
GET  /api/validate/summary          - Get test summary
"""

import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from threatforge.validation.sentinel_client import SentinelClient
from threatforge.validation.correlator import AttackCorrelator
from threatforge.validation.matrix_builder import ValidationMatrixBuilder
from threatforge.validation.benchmark import SentinelBenchmark

router = APIRouter(prefix="/api/validate", tags=["Validation"])

# Module-level instances
# These persist across requests (in-memory)
_sentinel_client = SentinelClient("http://localhost:8000")
_correlator = AttackCorrelator(_sentinel_client)
_matrix_builder = ValidationMatrixBuilder()
_benchmark = SentinelBenchmark(_sentinel_client)


class ValidationConfig(BaseModel):
    sentinel_url: str = Field("http://localhost:8000", description="Sentinel base URL")
    duration_seconds: int = Field(30, ge=10, le=120)
    rate: int = Field(50, ge=1, le=200)


class BenchmarkConfig(BaseModel):
    attack_type: str = Field("http_flood", description="Attack type: http_flood, credential_stuffing, enumeration")
    rate: int = Field(50, ge=1, le=200)


@router.get("/status")
async def validation_status():
    """
    Check if Sentinel is running and reachable.

    This is the FIRST thing to run before validation tests.
    If this fails, Sentinel is not running.
    """
    connected = _sentinel_client.test_connection()

    if connected:
        stats = _sentinel_client.snapshot_stats()
        return {
            "sentinel_connected": True,
            "sentinel_url": _sentinel_client.base_url,
            "current_stats": {
                "total_requests": stats.total_requests,
                "block_rate_pct": stats.block_rate_pct,
                "unique_fingerprints": stats.unique_fingerprints,
                "avg_threat_score": stats.avg_threat_score
            },
            "validation_ready": True,
            "message": "Sentinel is running. Ready for validation tests."
        }
    else:
        return {
            "sentinel_connected": False,
            "sentinel_url": _sentinel_client.base_url,
            "validation_ready": False,
            "message": (
                "Sentinel not reachable. "
                "Start Sentinel with: uvicorn Vigil.main:app --port 8000"
            )
        }


@router.post("/http-flood")
async def validate_http_flood_detection(config: ValidationConfig):
    """
    Validate Sentinel's HTTP flood detection capability.

    Runs controlled HTTP flood through Sentinel's analyze endpoint,
    then checks if Sentinel detected and blocked the attack.
    """
    global _sentinel_client
    _sentinel_client = SentinelClient(config.sentinel_url)

    if not _sentinel_client.is_connected():
        raise HTTPException(
            status_code=503,
            detail="Sentinel not reachable. Start Sentinel first."
        )

    result = await _correlator.run_http_flood_validation(
        target_url=config.sentinel_url,
        requests_per_second=config.rate,
        duration_seconds=config.duration_seconds
    )

    _matrix_builder.add_result(result)

    return {
        "test_id": result.test_id,
        "attack_type": result.attack_type,
        "payloads_sent": result.payloads_sent,
        "sentinel_detected": result.sentinel_detected,
        "detection_latency_s": result.detection_latency_seconds,
        "blocks_triggered": result.blocks_triggered,
        "block_rate_pct": result.block_rate_pct,
        "confidence": result.detection_confidence,
        "sentinel_delta": result.sentinel_delta
    }


@router.post("/credential-stuff")
async def validate_credential_stuffing_detection(config: ValidationConfig):
    """
    Validate Sentinel's credential stuffing detection.

    Sends POST requests to auth paths with 401 responses,
    mimicking real credential stuffing pattern.
    """
    if not _sentinel_client.is_connected():
        raise HTTPException(status_code=503, detail="Sentinel not reachable")

    result = await _correlator.run_credential_stuffing_validation(
        target_url=config.sentinel_url,
        attempts_per_second=min(config.rate, 20),
        duration_seconds=config.duration_seconds
    )

    _matrix_builder.add_result(result)
    return result.to_csv_row()


@router.post("/enumeration")
async def validate_enumeration_detection(config: ValidationConfig):
    """
    Validate Sentinel's enumeration attack detection.

    Sends sequential ID requests (/api/users/1, /2, /3...)
    and verifies Sentinel detects the pattern.
    """
    if not _sentinel_client.is_connected():
        raise HTTPException(status_code=503, detail="Sentinel not reachable")

    result = await _correlator.run_enumeration_validation(
        target_url=config.sentinel_url,
        items_per_second=config.rate,
        duration_seconds=config.duration_seconds
    )

    _matrix_builder.add_result(result)
    return result.to_csv_row()


@router.post("/full-suite")
async def run_full_validation_suite(
    sentinel_url: str = "http://localhost:8000",
    duration_each: int = 20
):
    """
    Run complete validation suite:
    1. HTTP flood detection
    2. Credential stuffing detection
    3. Enumeration detection

    Generates complete validation_matrix.csv.

    This is the SHOWSTOPPER for your demo.
    Run this and show your professor all 3 attacks being detected.
    """
    client = SentinelClient(sentinel_url)
    if not client.is_connected():
        raise HTTPException(
            status_code=503,
            detail="Sentinel not reachable. Run: uvicorn Vigil.main:app --port 8000"
        )

    correlator = AttackCorrelator(client)
    builder = ValidationMatrixBuilder()
    suite_results = []

    # Test 1: HTTP Flood
    r1 = await correlator.run_http_flood_validation(
        sentinel_url, 50, duration_each
    )
    suite_results.append(r1)
    builder.add_result(r1)

    await asyncio.sleep(3)

    # Test 2: Credential Stuffing
    r2 = await correlator.run_credential_stuffing_validation(
        sentinel_url, 5, duration_each
    )
    suite_results.append(r2)
    builder.add_result(r2)

    await asyncio.sleep(3)

    # Test 3: Enumeration
    r3 = await correlator.run_enumeration_validation(
        sentinel_url, 10, duration_each
    )
    suite_results.append(r3)
    builder.add_result(r3)

    # Save matrix
    csv_path = builder.save_csv("validation_matrix.csv")
    json_path = builder.save_json("validation_full.json")
    final_metrics = builder.compute_final_metrics()
    summary_table = builder.generate_summary_table()

    return {
        "suite_complete": True,
        "tests_run": len(suite_results),
        "results": [r.to_csv_row() for r in suite_results],
        "final_metrics": final_metrics,
        "summary_table": summary_table,
        "files_saved": {
            "csv": csv_path,
            "json": json_path
        }
    }


@router.get("/matrix")
async def get_validation_matrix():
    """Get current validation matrix (all tests so far)."""
    return {
        "total_tests": len(_matrix_builder.results),
        "results": [r.to_csv_row() for r in _matrix_builder.results],
        "summary": _matrix_builder.compute_final_metrics() if _matrix_builder.results else {}
    }


@router.post("/benchmark/latency")
async def run_latency_benchmark(config: BenchmarkConfig):
    """
    Measure Sentinel's detection latency.

    How many requests get through before Sentinel blocks?
    """
    if not _sentinel_client.is_connected():
        raise HTTPException(status_code=503, detail="Sentinel not reachable")

    result = await _benchmark.measure_detection_latency(
        attack_type=config.attack_type,
        rate=config.rate
    )
    return result


@router.post("/benchmark/fp-rate")
async def run_false_positive_benchmark(duration: int = 60):
    """
    Measure Sentinel's false positive rate.

    Sends legitimate traffic and counts incorrect blocks.
    """
    if not _sentinel_client.is_connected():
        raise HTTPException(status_code=503, detail="Sentinel not reachable")

    result = await _benchmark.measure_false_positive_rate(duration)
    return result


@router.get("/summary")
async def get_validation_summary():
    """Get summary of all validation tests."""
    return {
        "correlator_summary": _correlator.get_summary(),
        "matrix_metrics": _matrix_builder.compute_final_metrics(),
        "matrix_table": _matrix_builder.generate_summary_table()
    }
