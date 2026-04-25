"""
threatforge/core/crypto_attacks/caesar.py

Caesar Cipher Cryptanalysis Module

SYLLABUS: Unit 1 - Implement Caesar Cipher
COVERAGE: CO1, CO2

THEORY:
Caesar cipher is a substitution cipher where each letter is replaced
by a letter a fixed number of positions down the alphabet.

If key K=3:
  A→D, B→E, C→F, ..., Z→C

WEAKNESS: Only 26 possible keys. Any of the following attacks works:
1. Brute force: Try all 26 keys, score each for English
2. Frequency attack: Most common ciphertext letter is likely E (shifted by K)

REAL-WORLD CONNECTION:
ROT13 (K=13) is still used in forums to hide spoilers.
Many CTF challenges use Caesar variants.
Understanding this helps with Vigenere and other polyalphabetic ciphers.
"""

import time
from typing import List, Dict, Any
from .frequency import combined_english_score, compute_letter_frequency, find_most_likely_shift


def encrypt_caesar(plaintext: str, key: int) -> str:
    """
    Encrypt plaintext using Caesar cipher.

    We include encryption so we can:
    1. Generate test ciphertexts for demos
    2. Verify our decryption is correct

    Args:
        plaintext: Original message
        key: Shift amount (0-25)

    Returns:
        Encrypted ciphertext (preserves case and spaces)
    """
    result = []
    for char in plaintext:
        if char.isalpha():
            # Determine base (A=65 for uppercase, a=97 for lowercase)
            base = 65 if char.isupper() else 97
            # Shift the character
            shifted = (ord(char) - base + key) % 26
            result.append(chr(shifted + base))
        else:
            # Preserve non-alphabetic characters (spaces, punctuation)
            result.append(char)
    return ''.join(result)


def decrypt_caesar(ciphertext: str, key: int) -> str:
    """
    Decrypt Caesar ciphertext with known key.

    Decryption is just encryption with negative key.

    Args:
        ciphertext: Encrypted message
        key: Known shift amount

    Returns:
        Decrypted plaintext
    """
    # Decryption = encryption with key = (26 - original_key) % 26
    return encrypt_caesar(ciphertext, (26 - key) % 26)


def brute_force_attack(ciphertext: str) -> List[Dict[str, Any]]:
    """
    Break Caesar cipher by trying all 26 possible keys.

    ALGORITHM:
    For shift in 0..25:
        decrypted = decrypt(ciphertext, shift)
        score = combined_english_score(decrypted)
    Return all results sorted by score (best first)

    TIME COMPLEXITY: O(26 * n) where n = len(ciphertext)
    SPACE COMPLEXITY: O(26 * n)

    Args:
        ciphertext: The encrypted text to break

    Returns:
        List of dicts with keys: shift, decrypted, score, confidence
        Sorted by score descending (best guess first)
    """
    start_time = time.perf_counter()
    results = []

    for shift in range(26):
        # Attempt decryption with this shift
        decrypted = decrypt_caesar(ciphertext, shift)

        # Score how likely this is to be English
        score = combined_english_score(decrypted)

        results.append({
            "shift": shift,
            "decrypted": decrypted,
            "score": score,
            "key_char": chr(shift + 65)  # Convert to letter for readability
        })

    # Sort by score (highest = most likely English = correct key)
    results.sort(key=lambda x: x["score"], reverse=True)

    end_time = time.perf_counter()
    time_taken_ms = round((end_time - start_time) * 1000, 3)

    # Add confidence rating to top result
    # If top score is significantly higher than second, high confidence
    top_score = results[0]["score"]
    second_score = results[1]["score"] if len(results) > 1 else 0
    confidence_gap = top_score - second_score

    if confidence_gap > 20:
        confidence = "HIGH"
    elif confidence_gap > 10:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # Attach metadata to top result
    results[0]["confidence"] = confidence

    return {
        "attack_type": "caesar_brute_force",
        "ciphertext": ciphertext,
        "ciphertext_length": len([c for c in ciphertext if c.isalpha()]),
        "all_results": results,
        "best_guess": results[0],
        "time_taken_ms": time_taken_ms,
        "keys_tried": 26,
        "success": results[0]["score"] > 40  # Score threshold for success
    }


def frequency_attack(ciphertext: str) -> Dict[str, Any]:
    """
    Break Caesar cipher using frequency analysis.

    ALGORITHM:
    1. Compute letter frequencies in ciphertext
    2. Find most frequent letter in ciphertext
    3. Assume it corresponds to E (most common English letter)
    4. Derive key: K = (freq_letter - E) mod 26
    5. Verify by scoring decrypted text

    This is faster than brute force and demonstrates
    why letter frequency preservation is a critical weakness.

    ACADEMIC IMPORTANCE:
    This exact technique was used to break early cipher systems
    throughout history. Al-Kindi (9th century) documented this
    method - it's the oldest known cryptanalysis technique.

    Args:
        ciphertext: Encrypted text to analyze

    Returns:
        Dictionary with attack results and frequency analysis data
    """
    start_time = time.perf_counter()

    # Step 1: Compute frequencies
    frequencies = compute_letter_frequency(ciphertext)

    # Step 2: Find most frequent letter in ciphertext
    most_frequent = max(frequencies.items(), key=lambda x: x[1])
    most_frequent_letter = most_frequent[0]
    most_frequent_count = most_frequent[1]

    # Step 3: Compute likely keys
    # If most_frequent_letter is E shifted by K, then K = (freq_letter - E) mod 26
    e_position = 4  # E is 4th letter (A=0, B=1, ..., E=4)
    freq_position = ord(most_frequent_letter) - 65

    likely_key = (freq_position - e_position) % 26

    # Step 4: Decrypt with likely key
    decrypted = decrypt_caesar(ciphertext, likely_key)
    score = combined_english_score(decrypted)

    # Also get all ranked shifts from frequency analysis
    all_shifts = find_most_likely_shift(frequencies)

    # Try top 3 frequency-suggested shifts
    top_candidates = []
    for shift, freq_score in all_shifts[:3]:
        candidate = decrypt_caesar(ciphertext, shift)
        english_score = combined_english_score(candidate)
        top_candidates.append({
            "shift": shift,
            "frequency_score": freq_score,
            "english_score": english_score,
            "decrypted": candidate
        })

    top_candidates.sort(key=lambda x: x["english_score"], reverse=True)
    best = top_candidates[0]

    end_time = time.perf_counter()
    time_taken_ms = round((end_time - start_time) * 1000, 3)

    return {
        "attack_type": "caesar_frequency",
        "ciphertext": ciphertext,
        "most_frequent_cipher_letter": most_frequent_letter,
        "most_frequent_percentage": most_frequent_count,
        "frequencies": frequencies,
        "primary_key_guess": likely_key,
        "top_candidates": top_candidates,
        "best_result": best,
        "time_taken_ms": time_taken_ms,
        "success": best["english_score"] > 40
    }


def run_full_caesar_analysis(ciphertext: str) -> Dict[str, Any]:
    """
    Run both attacks and combine results.

    This is the main entry point for the Caesar module.
    Called by the FastAPI endpoint.

    Args:
        ciphertext: Text to analyze

    Returns:
        Combined results from both attack methods with comparison
    """
    brute_result = brute_force_attack(ciphertext)
    freq_result = frequency_attack(ciphertext)

    # Compare results from both methods
    brute_best_key = brute_result["best_guess"]["shift"]
    freq_best_key = freq_result["best_result"]["shift"]
    methods_agree = brute_best_key == freq_best_key

    return {
        "cipher": "caesar",
        "ciphertext": ciphertext,
        "brute_force": brute_result,
        "frequency_analysis": freq_result,
        "methods_agree": methods_agree,
        "final_answer": {
            "key": brute_result["best_guess"]["shift"],
            "decrypted": brute_result["best_guess"]["decrypted"],
            "confidence": brute_result["best_guess"].get("confidence", "UNKNOWN"),
            "score": brute_result["best_guess"]["score"]
        },
        "academic_insight": (
            "Both methods agree - high certainty" if methods_agree
            else "Methods disagree - low confidence, text may be too short"
        )
    }
