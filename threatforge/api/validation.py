import asyncio
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from threatforge.validation.sentinel_client import SentinelClient
from threatforge.validation.correlator import AttackCorrelator
from threatforge.validation.matrix_builder import ValidationMatrixBuilder
from threatforge.validation.benchmark import SentinelBenchmark

router = APIRouter(prefix="/api/validate", tags=["Validation"])

SENTINEL_URL = os.environ.get("SENTINEL_URL", "http://172.28.64.1:8000")

_sentinel_client = SentinelClient(SENTINEL_URL)
_correlator = AttackCorrelator(_sentinel_client)
_matrix_builder = ValidationMatrixBuilder()
_benchmark = SentinelBenchmark(_sentinel_client)


class ValidationConfig(BaseModel):
    sentinel_url: str = SENTINEL_URL
    duration_seconds: int = Field(30, ge=10, le=120)
    rate: int = Field(50, ge=1, le=200)


@router.get("/status")
async def validation_status():
    client = SentinelClient(SENTINEL_URL)
    connected = client.test_connection()
    if connected:
        stats = client.snapshot_stats()
        return {
            "sentinel_connected": True,
            "sentinel_url": SENTINEL_URL,
            "current_stats": {
                "total_requests": stats.total_requests,
                "block_rate_pct": stats.block_rate_pct,
                "unique_fingerprints": stats.unique_fingerprints,
                "avg_threat_score": stats.avg_threat_score
            },
            "validation_ready": True,
            "message": f"Sentinel online at {SENTINEL_URL}"
        }
    return {
        "sentinel_connected": False,
        "sentinel_url": SENTINEL_URL,
        "validation_ready": False,
        "message": f"Cannot reach Sentinel at {SENTINEL_URL}"
    }


@router.post("/http-flood")
async def validate_http_flood(config: ValidationConfig):
    url = config.sentinel_url or SENTINEL_URL
    client = SentinelClient(url)
    if not client.is_connected():
        raise HTTPException(status_code=503, detail=f"Sentinel not reachable at {url}")
    correlator = AttackCorrelator(client)
    result = await correlator.run_http_flood_validation(url, config.rate, config.duration_seconds)
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
async def validate_cred_stuff(config: ValidationConfig):
    url = config.sentinel_url or SENTINEL_URL
    client = SentinelClient(url)
    if not client.is_connected():
        raise HTTPException(status_code=503, detail="Sentinel not reachable")
    correlator = AttackCorrelator(client)
    result = await correlator.run_credential_stuffing_validation(url, min(config.rate, 20), config.duration_seconds)
    _matrix_builder.add_result(result)
    return result.to_csv_row()


@router.post("/enumeration")
async def validate_enumeration(config: ValidationConfig):
    url = config.sentinel_url or SENTINEL_URL
    client = SentinelClient(url)
    if not client.is_connected():
        raise HTTPException(status_code=503, detail="Sentinel not reachable")
    correlator = AttackCorrelator(client)
    result = await correlator.run_enumeration_validation(url, config.rate, config.duration_seconds)
    _matrix_builder.add_result(result)
    return result.to_csv_row()


@router.post("/full-suite")
async def full_suite(sentinel_url: Optional[str] = None, duration_each: int = 20):
    url = sentinel_url or SENTINEL_URL
    client = SentinelClient(url)
    if not client.is_connected():
        raise HTTPException(status_code=503, detail=f"Sentinel not reachable at {url}")
    correlator = AttackCorrelator(client)
    builder = ValidationMatrixBuilder()
    results = []

    r1 = await correlator.run_http_flood_validation(url, 50, duration_each)
    results.append(r1)
    builder.add_result(r1)
    await asyncio.sleep(3)

    r2 = await correlator.run_credential_stuffing_validation(url, 5, duration_each)
    results.append(r2)
    builder.add_result(r2)
    await asyncio.sleep(3)

    r3 = await correlator.run_enumeration_validation(url, 10, duration_each)
    results.append(r3)
    builder.add_result(r3)

    csv_path = builder.save_csv()
    json_path = builder.save_json()

    return {
        "suite_complete": True,
        "tests_run": len(results),
        "results": [r.to_csv_row() for r in results],
        "final_metrics": builder.compute_final_metrics(),
        "files_saved": {"csv": csv_path, "json": json_path}
    }


@router.get("/matrix")
async def get_matrix():
    return {
        "total_tests": len(_matrix_builder.results),
        "results": [r.to_csv_row() for r in _matrix_builder.results],
        "summary": _matrix_builder.compute_final_metrics() if _matrix_builder.results else {}
    }


@router.get("/summary")
async def get_summary():
    return {
        "correlator_summary": _correlator.get_summary(),
        "matrix_metrics": _matrix_builder.compute_final_metrics(),
    }
