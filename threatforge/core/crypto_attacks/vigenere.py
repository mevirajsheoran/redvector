"""
threatforge/core/crypto_attacks/vigenere.py

Vigenere Cipher Cryptanalysis - Kasiski Examination + IC Analysis

SYLLABUS: Unit 3 - Polyalphabetic Cipher
COVERAGE: CO1, CO2

THEORY:
Vigenere cipher uses a repeating keyword. For each position i:
  C[i] = (P[i] + Key[i mod key_length]) mod 26

Blaise de Vigenere (1586) - considered unbreakable for 300 years.
Friedrich Kasiski (1863) - published the first known method to break it.

KASISKI EXAMINATION ALGORITHM:
1. Find all repeated sequences of length 3+ in ciphertext
2. Record distance between each repeated sequence
3. GCD of all distances = likely key length
4. Split ciphertext into key_length groups (each group is Caesar-encrypted)
5. Run frequency analysis on each group to find each key letter
6. Reconstruct full key and decrypt

INDEX OF COINCIDENCE:
Alternative to Kasiski for finding key length.
For key length guess k:
  - Split text into k groups
  - Compute IC for each group
  - If IC ≈ 0.065 (English IC), key length is correct
"""

import time
import math
from typing import List, Dict, Any, Tuple
from .frequency import (
    combined_english_score,
    compute_letter_frequency,
    index_of_coincidence,
    ENGLISH_FREQUENCIES,
    ENGLISH_LETTER_ORDER
)
from .caesar import decrypt_caesar, brute_force_attack


def encrypt_vigenere(plaintext: str, key: str) -> str:
    """
    Encrypt plaintext using Vigenere cipher.

    Used to generate test cases for our attack.

    Args:
        plaintext: Original message
        key: Keyword (letters only, will be uppercased)

    Returns:
        Encrypted ciphertext
    """
    key_upper = key.upper()
    key_length = len(key_upper)
    result = []
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            # Get shift from current key character
            shift = ord(key_upper[key_index % key_length]) - 65
            # Apply shift
            shifted = (ord(char.upper()) - 65 + shift) % 26
            result.append(chr(shifted + 65))
            key_index += 1
        else:
            result.append(char)

    return ''.join(result)


def decrypt_vigenere(ciphertext: str, key: str) -> str:
    """
    Decrypt Vigenere ciphertext with known key.

    Args:
        ciphertext: Encrypted message
        key: Known keyword

    Returns:
        Decrypted plaintext
    """
    key_upper = key.upper()
    key_length = len(key_upper)
    result = []
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            # Reverse shift using key
            shift = ord(key_upper[key_index % key_length]) - 65
            decrypted_idx = (ord(char.upper()) - 65 - shift) % 26
            result.append(chr(decrypted_idx + 65))
            key_index += 1
        else:
            result.append(char)

    return ''.join(result)


def find_repeated_sequences(ciphertext: str, min_length: int = 3) -> Dict[str, List[int]]:
    """
    Find all repeated sequences in ciphertext (Kasiski Step 1).

    ALGORITHM:
    For each starting position i:
        For each sequence length L (3 to max):
            Extract sequence = ciphertext[i:i+L]
            Search for same sequence elsewhere in text
            If found, record positions

    WHY MINIMUM LENGTH 3:
    Length 1-2 sequences repeat randomly even in random text.
    Length 3+ repetitions in Vigenere are almost always caused
    by the same plaintext being encrypted with the same key offset.

    Args:
        ciphertext: Vigenere encrypted text
        min_length: Minimum sequence length to look for (default 3)

    Returns:
        Dict mapping sequence → list of starting positions
    """
    # Clean ciphertext - only letters
    clean = ''.join(c.upper() for c in ciphertext if c.isalpha())
    sequences: Dict[str, List[int]] = {}

    # Scan all possible starting positions
    for start in range(len(clean) - min_length + 1):
        # Try sequence lengths from min_length up
        for length in range(min_length, min(min_length + 6, len(clean) - start + 1)):
            sequence = clean[start:start + length]

            if sequence not in sequences:
                sequences[sequence] = []

            # Check if this sequence appears elsewhere
            search_start = start + 1
            while True:
                pos = clean.find(sequence, search_start)
                if pos == -1:
                    break
                if pos not in sequences[sequence]:
                    sequences[sequence].append(pos)
                search_start = pos + 1

            # Only record if we haven't seen this sequence starting at `start`
            if start not in sequences[sequence]:
                if sequences[sequence]:  # Only if it appears elsewhere
                    sequences[sequence].insert(0, start)

    # Filter: only keep sequences that appear at least twice
    return {seq: positions for seq, positions in sequences.items()
            if len(positions) >= 2}


def compute_distances(repeated_sequences: Dict[str, List[int]]) -> List[int]:
    """
    Compute distances between repeated sequences (Kasiski Step 2).

    THEORY:
    If key length is K, and same plaintext occurs at positions
    i and j where j-i is a multiple of K, then the same ciphertext
    sequence appears at both positions.

    Therefore: distances between repeats are multiples of K.
    GCD of all distances = K (or a factor of K).

    Args:
        repeated_sequences: Output from find_repeated_sequences()

    Returns:
        List of all distances between repeated sequence positions
    """
    distances = []
    for sequence, positions in repeated_sequences.items():
        sorted_positions = sorted(positions)
        for i in range(len(sorted_positions) - 1):
            distance = sorted_positions[i + 1] - sorted_positions[i]
            if distance > 0:
                distances.append(distance)
    return distances


def find_likely_key_lengths(distances: List[int], max_key_length: int = 20) -> List[Tuple[int, int]]:
    """
    Find most likely key lengths using GCD analysis (Kasiski Step 3).

    ALGORITHM:
    For each possible key length k (2 to max_key_length):
        Count how many distances are divisible by k
        More divisible → more likely to be key length

    Also considers GCD of all distances for additional confirmation.

    Args:
        distances: List of distances from compute_distances()
        max_key_length: Maximum key length to consider

    Returns:
        List of (key_length, score) sorted by score descending
    """
    if not distances:
        return [(i, 0) for i in range(2, max_key_length + 1)]

    key_scores: Dict[int, int] = {}

    for k in range(2, max_key_length + 1):
        # Count how many distances are divisible by k
        divisible_count = sum(1 for d in distances if d % k == 0)
        key_scores[k] = divisible_count

    # Sort by score descending
    sorted_keys = sorted(key_scores.items(), key=lambda x: x[1], reverse=True)
    return sorted_keys


def split_into_groups(ciphertext: str, key_length: int) -> List[str]:
    """
    Split ciphertext into key_length groups for Caesar analysis (Kasiski Step 4).

    THEORY:
    If key length is K, then positions 0, K, 2K, ... are all encrypted
    with key[0]. Positions 1, K+1, 2K+1, ... with key[1]. Etc.

    By grouping letters this way, each group is a simple Caesar cipher
    encrypted with the corresponding key letter.

    Example with key_length=3:
    CIPHERTEXT: A B C D E F G H I
    Group 0:    A     D     G       (positions 0, 3, 6)
    Group 1:      B     E     H     (positions 1, 4, 7)
    Group 2:        C     F     I   (positions 2, 5, 8)

    Args:
        ciphertext: Vigenere encrypted text
        key_length: Guessed key length

    Returns:
        List of key_length strings, one per key position
    """
    clean = ''.join(c.upper() for c in ciphertext if c.isalpha())
    groups = ['' for _ in range(key_length)]

    for i, char in enumerate(clean):
        groups[i % key_length] += char

    return groups


def find_key_letter(group: str) -> Tuple[str, float]:
    """
    Find the Caesar shift (key letter) for a single group.

    ALGORITHM:
    Each group is encrypted with a single Caesar shift = key letter.
    Run Caesar frequency attack on the group.
    The most likely shift gives us the key letter.

    Args:
        group: String of letters all encrypted with same key letter

    Returns:
        Tuple of (key_letter, confidence_score)
    """
    frequencies = compute_letter_frequency(group)

    # Find most common letter in this group
    most_common = max(frequencies.items(), key=lambda x: x[1])
    most_common_letter = most_common[0]

    # Assume most common = E (shifted by key letter)
    # shift = (most_common - E) mod 26
    e_idx = 4
    most_common_idx = ord(most_common_letter) - 65
    shift = (most_common_idx - e_idx) % 26

    # The key letter IS the shift amount
    key_letter = chr(shift + 65)

    # Score confidence by decrypting group with this key and checking English
    decrypted_group = decrypt_caesar(group, shift)
    confidence = combined_english_score(decrypted_group)

    return key_letter, confidence


def kasiski_attack(ciphertext: str) -> Dict[str, Any]:
    """
    Full Kasiski Examination attack on Vigenere cipher.

    This is the main attack function that executes all steps:
    1. Find repeated sequences
    2. Compute distances
    3. Find likely key lengths
    4. For each candidate key length:
       a. Split into groups
       b. Find each key letter
       c. Reconstruct key
       d. Decrypt and score

    Args:
        ciphertext: Vigenere encrypted text to break

    Returns:
        Complete attack results with key discovery and decryption
    """
    start_time = time.perf_counter()

    clean_cipher = ''.join(c.upper() for c in ciphertext if c.isalpha())

    # Step 1: Find repeated sequences
    repeated = find_repeated_sequences(clean_cipher)

    # Step 2: Compute distances
    distances = compute_distances(repeated)

    # Step 3: Find likely key lengths
    likely_lengths = find_likely_key_lengths(distances)
    top_key_lengths = [k for k, score in likely_lengths[:5]]

    # Also use IC method as backup
    ic_scores = []
    for k in range(2, 16):
        groups = split_into_groups(clean_cipher, k)
        avg_ic = sum(index_of_coincidence(g) for g in groups) / k
        ic_scores.append((k, avg_ic))

    # English IC is ~0.065 - find key length where IC is closest to English
    ic_scores.sort(key=lambda x: abs(x[1] - 0.065))
    ic_best_length = ic_scores[0][0]

    # Combine Kasiski and IC suggestions
    candidate_lengths = list(set(top_key_lengths[:3] + [ic_best_length]))

    # Step 4: Try each candidate key length
    candidates = []
    for key_length in candidate_lengths:
        if key_length < 2 or key_length > 20:
            continue

        # Split and attack each group
        groups = split_into_groups(clean_cipher, key_length)
        key_letters = []
        group_confidences = []

        for group in groups:
            if len(group) < 3:
                key_letters.append('A')
                group_confidences.append(0.0)
                continue
            letter, confidence = find_key_letter(group)
            key_letters.append(letter)
            group_confidences.append(confidence)

        reconstructed_key = ''.join(key_letters)

        # Decrypt with reconstructed key
        decrypted = decrypt_vigenere(clean_cipher, reconstructed_key)
        overall_score = combined_english_score(decrypted)
        avg_confidence = sum(group_confidences) / len(group_confidences) if group_confidences else 0

        candidates.append({
            "key_length": key_length,
            "key_found": reconstructed_key,
            "decrypted": decrypted,
            "overall_score": overall_score,
            "avg_group_confidence": round(avg_confidence, 2),
            "group_confidences": group_confidences
        })

    # Sort by overall score
    candidates.sort(key=lambda x: x["overall_score"], reverse=True)

    end_time = time.perf_counter()
    time_taken_ms = round((end_time - start_time) * 1000, 3)

    best = candidates[0] if candidates else None

    return {
        "attack_type": "vigenere_kasiski",
        "ciphertext": ciphertext,
        "ciphertext_length": len(clean_cipher),
        "repeated_sequences_found": len(repeated),
        "distances_computed": len(distances),
        "kasiski_suggested_lengths": top_key_lengths[:5],
        "ic_suggested_length": ic_best_length,
        "all_candidates": candidates,
        "best_result": best,
        "time_taken_ms": time_taken_ms,
        "success": best["overall_score"] > 35 if best else False
    }
