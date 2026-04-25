"""
threatforge/core/crypto_attacks/hill.py

Hill Cipher Cryptanalysis - Known Plaintext Attack

SYLLABUS: Unit 5 - Hill Cipher
COVERAGE: CO1, CO2

THEORY:
Hill cipher encrypts blocks of text using matrix multiplication modulo 26.

For block size 2 (2x2 key matrix K):
  Plaintext pairs: [p1, p2]
  Ciphertext pairs: [c1, c2] = K × [p1, p2] mod 26

WEAKNESS - Known Plaintext Attack:
If we know several plaintext-ciphertext pairs:
  [c1, c3]   [k11 k12]   [p1 p3]
  [c2, c4] = [k21 k22] × [p2 p4] (mod 26)

  C = K × P (mod 26)
  K = C × P⁻¹ (mod 26)   <- Solve for key matrix!

This is powerful because in practice, attackers often know
some plaintext (message headers, common phrases).

ACADEMIC IMPORTANCE:
Hill cipher demonstrates why modern ciphers need non-linear operations.
AES uses non-linear S-boxes specifically to prevent linear algebraic attacks
like the Hill cipher known-plaintext attack.
"""

import time
from typing import List, Dict, Any, Optional, Tuple
from .frequency import combined_english_score


def mod_inverse(a: int, m: int) -> Optional[int]:
    """
    Compute modular multiplicative inverse of a (mod m).

    Extended Euclidean Algorithm.
    Needed for modular matrix inversion.

    Returns a^(-1) mod m, or None if not invertible.
    """
    # Extended Euclidean Algorithm
    if math.gcd(a, m) != 1:
        return None  # No inverse exists

    # Use extended GCD
    old_r, r = a, m
    old_s, s = 1, 0

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    return old_s % m


import math


def matrix_mod_inverse_2x2(matrix: List[List[int]], mod: int) -> Optional[List[List[int]]]:
    """
    Compute modular inverse of a 2x2 matrix.

    FORMULA for 2x2 matrix [[a,b],[c,d]]:
    1. Determinant: det = (a*d - b*c) mod 26
    2. Check: gcd(det, 26) must be 1 (otherwise non-invertible)
    3. Modular inverse of determinant: det_inv = det^(-1) mod 26
    4. Inverse matrix = det_inv * [[d,-b],[-c,a]] mod 26

    Args:
        matrix: 2x2 matrix as list of lists
        mod: Modulus (26 for cipher)

    Returns:
        Inverse matrix or None if not invertible
    """
    a, b = matrix[0][0], matrix[0][1]
    c, d = matrix[1][0], matrix[1][1]

    # Compute determinant mod 26
    det = (a * d - b * c) % mod

    # Check if determinant has modular inverse
    if math.gcd(det, mod) != 1:
        return None  # Matrix not invertible mod 26

    det_inv = mod_inverse(det, mod)
    if det_inv is None:
        return None

    # Compute inverse matrix
    inv = [
        [(det_inv * d) % mod,  (det_inv * (-b)) % mod],
        [(det_inv * (-c)) % mod, (det_inv * a) % mod]
    ]

    return inv


def text_to_numbers(text: str) -> List[int]:
    """Convert text to number list (A=0, B=1, ..., Z=25)"""
    return [ord(c.upper()) - 65 for c in text if c.isalpha()]


def numbers_to_text(numbers: List[int]) -> str:
    """Convert number list back to text"""
    return ''.join(chr(n % 26 + 65) for n in numbers)


def encrypt_hill_2x2(plaintext: str, key_matrix: List[List[int]]) -> str:
    """
    Encrypt using 2x2 Hill cipher.

    Args:
        plaintext: Text to encrypt (must have even length, will pad if needed)
        key_matrix: 2x2 encryption matrix

    Returns:
        Ciphertext
    """
    # Clean and prepare plaintext
    clean = ''.join(c.upper() for c in plaintext if c.isalpha())
    if len(clean) % 2 != 0:
        clean += 'X'  # Pad with X if odd length

    numbers = text_to_numbers(clean)
    result = []

    for i in range(0, len(numbers), 2):
        p1, p2 = numbers[i], numbers[i + 1]
        # Matrix multiplication mod 26
        c1 = (key_matrix[0][0] * p1 + key_matrix[0][1] * p2) % 26
        c2 = (key_matrix[1][0] * p1 + key_matrix[1][1] * p2) % 26
        result.extend([c1, c2])

    return numbers_to_text(result)


def decrypt_hill_2x2(ciphertext: str, key_matrix: List[List[int]]) -> Optional[str]:
    """
    Decrypt Hill cipher with known key.

    Args:
        ciphertext: Encrypted text
        key_matrix: 2x2 key matrix

    Returns:
        Decrypted text or None if key is not invertible
    """
    inv_matrix = matrix_mod_inverse_2x2(key_matrix, 26)
    if inv_matrix is None:
        return None

    clean = ''.join(c.upper() for c in ciphertext if c.isalpha())
    numbers = text_to_numbers(clean)
    result = []

    for i in range(0, len(numbers), 2):
        if i + 1 >= len(numbers):
            break
        c1, c2 = numbers[i], numbers[i + 1]
        p1 = (inv_matrix[0][0] * c1 + inv_matrix[0][1] * c2) % 26
        p2 = (inv_matrix[1][0] * c1 + inv_matrix[1][1] * c2) % 26
        result.extend([p1, p2])

    return numbers_to_text(result)


def known_plaintext_attack(
    plaintext_sample: str,
    ciphertext_sample: str
) -> Dict[str, Any]:
    """
    Recover Hill cipher 2x2 key using known plaintext-ciphertext pairs.

    ALGORITHM:
    Given plaintext P and ciphertext C (at least 4 letters each):
    C = K × P (mod 26)
    K = C × P⁻¹ (mod 26)

    We take the first 4 letters (2 pairs) to form:
    Plaintext matrix P:  [[p1, p3],    Ciphertext matrix C: [[c1, c3],
                          [p2, p4]]                          [c2, c4]]

    Then K = C × P⁻¹ mod 26

    Args:
        plaintext_sample: Known plaintext (minimum 4 letters)
        ciphertext_sample: Corresponding ciphertext

    Returns:
        Attack results including recovered key matrix
    """
    start_time = time.perf_counter()

    plain_nums = text_to_numbers(plaintext_sample)[:4]
    cipher_nums = text_to_numbers(ciphertext_sample)[:4]

    if len(plain_nums) < 4 or len(cipher_nums) < 4:
        return {
            "attack_type": "hill_known_plaintext",
            "success": False,
            "error": "Need at least 4 characters of known plaintext/ciphertext"
        }

    # Build plaintext matrix (columns are plaintext pairs)
    P = [[plain_nums[0], plain_nums[2]],
         [plain_nums[1], plain_nums[3]]]

    # Build ciphertext matrix
    C = [[cipher_nums[0], cipher_nums[2]],
         [cipher_nums[1], cipher_nums[3]]]

    # Compute P inverse
    P_inv = matrix_mod_inverse_2x2(P, 26)

    if P_inv is None:
        end_time = time.perf_counter()
        return {
            "attack_type": "hill_known_plaintext",
            "success": False,
            "error": "Plaintext matrix not invertible mod 26 - try different plaintext sample",
            "time_taken_ms": round((end_time - start_time) * 1000, 3)
        }

    # Compute K = C × P_inv mod 26
    K = [
        [
            (C[0][0] * P_inv[0][0] + C[0][1] * P_inv[1][0]) % 26,
            (C[0][0] * P_inv[0][1] + C[0][1] * P_inv[1][1]) % 26
        ],
        [
            (C[1][0] * P_inv[0][0] + C[1][1] * P_inv[1][0]) % 26,
            (C[1][0] * P_inv[0][1] + C[1][1] * P_inv[1][1]) % 26
        ]
    ]

    # Verify by decrypting full ciphertext
    decrypted = decrypt_hill_2x2(ciphertext_sample, K)
    score = combined_english_score(decrypted) if decrypted else 0

    end_time = time.perf_counter()

    return {
        "attack_type": "hill_known_plaintext",
        "success": decrypted is not None and score > 20,
        "recovered_key_matrix": K,
        "key_as_letters": [
            [chr(K[0][0] + 65), chr(K[0][1] + 65)],
            [chr(K[1][0] + 65), chr(K[1][1] + 65)]
        ],
        "decrypted": decrypted,
        "english_score": score,
        "time_taken_ms": round((end_time - start_time) * 1000, 3)
    }
