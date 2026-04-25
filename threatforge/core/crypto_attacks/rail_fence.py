"""
threatforge/core/crypto_attacks/rail_fence.py

Rail Fence Cipher Cryptanalysis

SYLLABUS: Unit 4 - Rail Fence Technique
COVERAGE: CO1, CO2

THEORY:
Rail Fence is a transposition cipher - it doesn't substitute letters,
it rearranges them in a specific pattern.

The plaintext is written diagonally across N 'rails', then
read off row by row.

With 3 rails and plaintext HELLOWORLD:
Rail 0: H . . . O . . . L .     → HOL
Rail 1: . E . L . W . R . D     → ELWRD
Rail 2: . . L . . . O . . .     → LO

Ciphertext (reading rails top to bottom): HOLELWRDLO

WEAKNESS:
The pattern is completely predictable. Given:
- Length of ciphertext
- Number of rails
We can reconstruct exactly which positions belong to which rail
and reverse the transposition.

ATTACK STRATEGY:
Try all possible number of rails (2 to max_rails).
For each, reconstruct and score the plaintext.
"""

import time
from typing import List, Dict, Any
from .frequency import combined_english_score


def encrypt_rail_fence(plaintext: str, rails: int) -> str:
    """
    Encrypt using Rail Fence cipher.

    Creates a 2D grid with 'rails' rows, writes text diagonally,
    then reads off row by row.

    Args:
        plaintext: Original message
        rails: Number of rails (2 or more)

    Returns:
        Encrypted ciphertext
    """
    if rails < 2:
        return plaintext
    if rails >= len(plaintext):
        return plaintext

    # Create rail structure
    fence = [[] for _ in range(rails)]

    # Determine which rail each character goes to
    # Pattern: 0,1,2,...,rails-1,rails-2,...,1,0,1,2,...
    current_rail = 0
    direction = 1  # 1 = going down, -1 = going up

    for char in plaintext:
        fence[current_rail].append(char)

        # Change direction at top and bottom rails
        if current_rail == 0:
            direction = 1
        elif current_rail == rails - 1:
            direction = -1

        current_rail += direction

    # Read off each rail top to bottom
    return ''.join(''.join(rail) for rail in fence)


def decrypt_rail_fence(ciphertext: str, rails: int) -> str:
    """
    Decrypt Rail Fence with known number of rails.

    ALGORITHM:
    1. Determine which positions belong to which rail
    2. Distribute ciphertext letters to rails in order
    3. Read off letters following the diagonal pattern

    Args:
        ciphertext: Encrypted text
        rails: Number of rails used

    Returns:
        Decrypted plaintext
    """
    n = len(ciphertext)

    if rails < 2 or rails >= n:
        return ciphertext

    # Step 1: Map each position to its rail
    # This mirrors the encryption pattern
    rail_pattern = []
    current_rail = 0
    direction = 1

    for i in range(n):
        rail_pattern.append(current_rail)

        if current_rail == 0:
            direction = 1
        elif current_rail == rails - 1:
            direction = -1

        current_rail += direction

    # Step 2: Determine how many characters go to each rail
    # Sort positions by rail, maintaining order within each rail
    rail_positions = [[] for _ in range(rails)]
    for pos, rail in enumerate(rail_pattern):
        rail_positions[rail].append(pos)

    # Step 3: Distribute ciphertext letters to rails
    result = [''] * n
    cipher_idx = 0
    for rail in range(rails):
        for pos in rail_positions[rail]:
            result[pos] = ciphertext[cipher_idx]
            cipher_idx += 1

    return ''.join(result)


def brute_force_rails(ciphertext: str, max_rails: int = 20) -> Dict[str, Any]:
    """
    Try all possible numbers of rails and find best decryption.

    ALGORITHM:
    For rails in 2..max_rails:
        decrypted = decrypt_rail_fence(ciphertext, rails)
        score = combined_english_score(decrypted)
    Return best scoring result

    The number of possible keys is very small (typically 2-20),
    making brute force trivially easy.

    ACADEMIC INSIGHT:
    Rail fence security depends entirely on key secrecy (number of rails).
    Unlike Caesar which has 26 keys, rail fence has even fewer practical
    keys (2-10 rails is typical). This makes it weaker than Caesar
    for short messages.

    Args:
        ciphertext: Encrypted text
        max_rails: Maximum rails to try

    Returns:
        Attack results with best decryption found
    """
    start_time = time.perf_counter()
    results = []

    # Limit max rails to ciphertext length
    actual_max = min(max_rails, len(ciphertext) - 1)

    for rails in range(2, actual_max + 1):
        decrypted = decrypt_rail_fence(ciphertext, rails)
        score = combined_english_score(decrypted)

        results.append({
            "rails": rails,
            "decrypted": decrypted,
            "score": score
        })

    # Sort by score
    results.sort(key=lambda x: x["score"], reverse=True)

    end_time = time.perf_counter()
    time_taken_ms = round((end_time - start_time) * 1000, 3)

    return {
        "attack_type": "rail_fence_brute_force",
        "ciphertext": ciphertext,
        "ciphertext_length": len(ciphertext),
        "rails_tried": actual_max - 1,
        "all_results": results,
        "best_result": results[0] if results else None,
        "time_taken_ms": time_taken_ms,
        "success": results[0]["score"] > 35 if results else False
    }
