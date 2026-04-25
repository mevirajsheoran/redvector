"""
threatforge/api/crypto.py

FastAPI endpoints for cryptanalysis module.

All endpoints follow RESTful conventions:
POST /api/crypto/{cipher}/attack  - Run attack on provided ciphertext
POST /api/crypto/{cipher}/demo    - Run demo with generated ciphertext
GET  /api/crypto/ciphers          - List available cipher attacks
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict

from threatforge.core.crypto_attacks.caesar import (
    run_full_caesar_analysis, encrypt_caesar
)
from threatforge.core.crypto_attacks.vigenere import (
    kasiski_attack, encrypt_vigenere
)
from threatforge.core.crypto_attacks.rail_fence import (
    brute_force_rails, encrypt_rail_fence
)
from threatforge.core.crypto_attacks.rsa_factor import (
    demo_full_rsa_attack, attack_small_rsa,
    generate_rsa_keypair, rsa_encrypt, generate_small_prime
)
from threatforge.core.crypto_attacks.hill import (
    known_plaintext_attack, encrypt_hill_2x2
)

router = APIRouter(prefix="/api/crypto", tags=["Cryptanalysis"])


# ─────────────────────────────────────────
# Request/Response Models
# ─────────────────────────────────────────

class CaesarAttackRequest(BaseModel):
    ciphertext: str = Field(
        ...,
        description="Ciphertext encrypted with Caesar cipher",
        example="KHOOR ZRUOG"
    )

class VigenereAttackRequest(BaseModel):
    ciphertext: str = Field(
        ...,
        description="Ciphertext encrypted with Vigenere cipher",
        min_length=20,
        example="LXFOPVEFRNHR"
    )

class RailFenceAttackRequest(BaseModel):
    ciphertext: str = Field(..., description="Rail fence encrypted text")
    max_rails: int = Field(20, ge=2, le=50, description="Maximum rails to try")

class RSAAttackRequest(BaseModel):
    n: int = Field(..., description="Public modulus n = p * q", example=3233)
    e: int = Field(..., description="Public exponent", example=17)
    ciphertext: int = Field(..., description="Encrypted message as integer", example=2790)

class HillAttackRequest(BaseModel):
    plaintext_sample: str = Field(
        ...,
        description="Known plaintext (minimum 4 letters)",
        example="HELP"
    )
    ciphertext_sample: str = Field(
        ...,
        description="Corresponding ciphertext",
        example="HPED"
    )


# ─────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────

@router.get("/ciphers")
async def list_available_ciphers():
    """
    List all available cipher attacks.
    Shows what ThreatForge can crack.
    """
    return {
        "available_attacks": [
            {
                "cipher": "caesar",
                "endpoint": "/api/crypto/caesar/attack",
                "methods": ["brute_force", "frequency_analysis"],
                "syllabus_unit": 1,
                "complexity": "O(26n) - trivially easy"
            },
            {
                "cipher": "vigenere",
                "endpoint": "/api/crypto/vigenere/attack",
                "methods": ["kasiski_examination", "index_of_coincidence"],
                "syllabus_unit": 3,
                "complexity": "O(n^2) - polynomial, practical"
            },
            {
                "cipher": "rail_fence",
                "endpoint": "/api/crypto/rail_fence/attack",
                "methods": ["brute_force_rails"],
                "syllabus_unit": 4,
                "complexity": "O(rails * n) - trivially easy"
            },
            {
                "cipher": "hill",
                "endpoint": "/api/crypto/hill/attack",
                "methods": ["known_plaintext"],
                "syllabus_unit": 5,
                "complexity": "O(n^3) - matrix inversion, fast"
            },
            {
                "cipher": "rsa_small",
                "endpoint": "/api/crypto/rsa/attack",
                "methods": ["trial_division_factorization"],
                "syllabus_unit": 6,
                "complexity": "O(sqrt(n)) - only feasible for small n"
            }
        ]
    }


@router.post("/caesar/attack")
async def attack_caesar(request: CaesarAttackRequest):
    """
    Break Caesar cipher using brute force + frequency analysis.
    Returns all 26 possible decryptions scored by English likelihood.
    """
    if not request.ciphertext.strip():
        raise HTTPException(status_code=400, detail="Ciphertext cannot be empty")

    result = run_full_caesar_analysis(request.ciphertext)
    return result


@router.post("/caesar/demo")
async def demo_caesar(key: int = 13, plaintext: str = "ThreatForge breaks Caesar cipher easily"):
    """
    Generate Caesar demo: encrypt then immediately attack.
    Used for live demos.
    """
    if key < 0 or key > 25:
        raise HTTPException(status_code=400, detail="Key must be between 0 and 25")

    encrypted = encrypt_caesar(plaintext, key)
    attack_result = run_full_caesar_analysis(encrypted)

    return {
        "demo": True,
        "original_plaintext": plaintext,
        "key_used": key,
        "key_character": chr(key + 65),
        "ciphertext": encrypted,
        "attack_result": attack_result,
        "attack_correct": attack_result["final_answer"]["key"] == key
    }


@router.post("/vigenere/attack")
async def attack_vigenere(request: VigenereAttackRequest):
    """
    Break Vigenere cipher using Kasiski examination.
    Requires at least 20 characters for reliable key length detection.
    """
    result = kasiski_attack(request.ciphertext)
    return result


@router.post("/vigenere/demo")
async def demo_vigenere(
    key: str = "CYBER",
    plaintext: str = "The security of a cryptographic system should not depend on the secrecy of the algorithm but only on the secrecy of the key which is Kerckhoffs principle"
):
    """Generate Vigenere demo: encrypt then attack."""
    encrypted = encrypt_vigenere(plaintext, key)
    attack_result = kasiski_attack(encrypted)

    return {
        "demo": True,
        "original_key": key,
        "original_plaintext": plaintext[:50] + "...",
        "ciphertext": encrypted[:50] + "...",
        "attack_result": attack_result,
        "key_recovered": attack_result["best_result"]["key_found"] if attack_result["best_result"] else None
    }


@router.post("/rail_fence/attack")
async def attack_rail_fence(request: RailFenceAttackRequest):
    """Break Rail Fence cipher by trying all rail counts."""
    result = brute_force_rails(request.ciphertext, request.max_rails)
    return result


@router.post("/rail_fence/demo")
async def demo_rail_fence(rails: int = 3, plaintext: str = "THREATFORGESECURITYTESTING"):
    """Generate Rail Fence demo."""
    if rails < 2 or rails > 10:
        raise HTTPException(status_code=400, detail="Rails must be between 2 and 10")

    encrypted = encrypt_rail_fence(plaintext, rails)
    attack_result = brute_force_rails(encrypted)

    return {
        "demo": True,
        "rails_used": rails,
        "original_plaintext": plaintext,
        "encrypted": encrypted,
        "attack_result": attack_result,
        "rails_found": attack_result["best_result"]["rails"] if attack_result["best_result"] else None,
        "correct": attack_result["best_result"]["rails"] == rails if attack_result["best_result"] else False
    }


@router.post("/hill/attack")
async def attack_hill(request: HillAttackRequest):
    """
    Break Hill cipher using known plaintext attack.
    Requires at least 4 characters of known plaintext-ciphertext pair.
    """
    result = known_plaintext_attack(
        request.plaintext_sample,
        request.ciphertext_sample
    )
    return result


@router.post("/rsa/attack")
async def attack_rsa(request: RSAAttackRequest):
    """
    Break small RSA by factoring the public modulus n.
    Only works for small primes (n < ~10^12 is practical).
    """
    if request.n > 10**12:
        raise HTTPException(
            status_code=400,
            detail="n too large for trial division. ThreatForge demos use small RSA only."
        )

    result = attack_small_rsa(request.n, request.e, request.ciphertext)
    return result


@router.post("/rsa/demo")
async def demo_rsa():
    """
    Generate complete RSA demo: generate small keys, encrypt, attack.
    Shows every step of the attack with all intermediate values.
    """
    result = demo_full_rsa_attack()
    return result


@router.get("/health")
async def crypto_health():
    """Verify crypto module is operational."""
    return {
        "module": "cryptanalysis",
        "status": "operational",
        "ciphers_available": 5
    }
