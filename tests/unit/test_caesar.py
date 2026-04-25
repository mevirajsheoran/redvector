"""
tests/unit/test_caesar.py

Unit tests for Caesar cipher cryptanalysis module.

RUN WITH: pytest tests/unit/test_caesar.py -v
"""

import pytest
from threatforge.core.crypto_attacks.caesar import (
    encrypt_caesar,
    decrypt_caesar,
    brute_force_attack,
    frequency_attack,
    run_full_caesar_analysis
)


class TestCaesarEncryption:
    """Test Caesar encryption correctness"""

    def test_encrypt_basic_shift(self):
        """A shifted by 1 should become B"""
        result = encrypt_caesar("A", 1)
        assert result == "B"

    def test_encrypt_shift_13_rot13(self):
        """ROT13 is Caesar with key=13"""
        result = encrypt_caesar("HELLO", 13)
        assert result == "URYYB"

    def test_encrypt_preserves_spaces(self):
        """Spaces should not be encrypted"""
        result = encrypt_caesar("HELLO WORLD", 3)
        assert " " in result

    def test_encrypt_wraps_around(self):
        """Z + 1 should become A"""
        result = encrypt_caesar("Z", 1)
        assert result == "A"

    def test_encrypt_decrypt_inverse(self):
        """Decrypting encrypted text should give original"""
        original = "The Quick Brown Fox"
        key = 7
        encrypted = encrypt_caesar(original, key)
        decrypted = decrypt_caesar(encrypted, key)
        assert decrypted.upper() == original.upper()


class TestCaesarBruteForce:
    """Test brute force attack"""

    def test_brute_force_finds_correct_key(self):
        """Brute force should find the correct key"""
        plaintext = "HELLO WORLD THIS IS A TEST MESSAGE FOR SECURITY"
        key = 13
        ciphertext = encrypt_caesar(plaintext, key)
        result = brute_force_attack(ciphertext)
        assert result["best_guess"]["shift"] == key

    def test_brute_force_tries_all_26(self):
        """Should try exactly 26 keys"""
        result = brute_force_attack("HELLO")
        assert result["keys_tried"] == 26

    def test_brute_force_returns_sorted_results(self):
        """Results should be sorted by score descending"""
        result = brute_force_attack("KHOOR ZRUOG")
        scores = [r["score"] for r in result["all_results"]]
        assert scores == sorted(scores, reverse=True)

    def test_brute_force_high_confidence_on_long_text(self):
        """Longer text should give higher confidence"""
        long_text = "SECURITY TESTING IS IMPORTANT FOR ENTERPRISE SYSTEMS " * 5
        key = 5
        ciphertext = encrypt_caesar(long_text, key)
        result = brute_force_attack(ciphertext)
        assert result["best_guess"].get("confidence") in ["HIGH", "MEDIUM"]


class TestCaesarFrequencyAttack:
    """Test frequency analysis attack"""

    def test_frequency_attack_finds_key(self):
        """Frequency attack should find correct key on long text"""
        long_plaintext = (
            "The quick brown fox jumps over the lazy dog "
            "and the security system detected an intrusion attempt "
            "in the network infrastructure today evening "
        )
        key = 7
        ciphertext = encrypt_caesar(long_plaintext, key)
        result = frequency_attack(ciphertext)
        # Check top candidates include correct key
        top_shifts = [c["shift"] for c in result["top_candidates"]]
        assert key in top_shifts

    def test_frequency_attack_computes_frequencies(self):
        """Frequency analysis should return letter frequencies"""
        result = frequency_attack("HELLO WORLD")
        assert "frequencies" in result
        assert "E" in result["frequencies"]


class TestFullCaesarAnalysis:
    """Test combined attack"""

    def test_full_analysis_returns_complete_result(self):
        """Full analysis should include both attack methods"""
        ciphertext = encrypt_caesar("HELLO WORLD SECURITY TEST", 10)
        result = run_full_caesar_analysis(ciphertext)
        assert "brute_force" in result
        assert "frequency_analysis" in result
        assert "final_answer" in result

    def test_methods_agree_on_long_text(self):
        """Both methods should agree when text is long enough"""
        long_text = "INFORMATION AND NETWORK SECURITY " * 10
        key = 15
        ciphertext = encrypt_caesar(long_text, key)
        result = run_full_caesar_analysis(ciphertext)
        assert result["methods_agree"] == True
