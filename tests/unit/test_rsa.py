"""
tests/unit/test_rsa.py

Unit tests for RSA factorization module.
"""

import pytest
from threatforge.core.crypto_attacks.rsa_factor import (
    is_prime,
    mod_inverse,
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    trial_division_factorization,
    attack_small_rsa,
    demo_full_rsa_attack
)


class TestPrimalityTesting:

    def test_is_prime_known_primes(self):
        for p in [2, 3, 5, 7, 11, 13, 17, 53, 61]:
            assert is_prime(p), f"{p} should be prime"

    def test_is_prime_known_composites(self):
        for n in [1, 4, 6, 8, 9, 10, 15, 100]:
            assert not is_prime(n), f"{n} should not be prime"


class TestModularInverse:

    def test_mod_inverse_basic(self):
        assert mod_inverse(3, 26) == 9   # 3 * 9 = 27 ≡ 1 mod 26

    def test_mod_inverse_returns_none_when_not_invertible(self):
        assert mod_inverse(2, 26) is None  # gcd(2,26)=2, not invertible


class TestRSAEncryptDecrypt:

    def test_encrypt_decrypt_roundtrip(self):
        keypair = generate_rsa_keypair(53, 61, 17)
        assert keypair is not None
        message = 42
        ciphertext = rsa_encrypt(message, keypair["public_key"])
        decrypted = rsa_decrypt(ciphertext, keypair["private_key"])
        assert decrypted == message


class TestFactorizationAttack:

    def test_factorize_known_rsa_n(self):
        p, q = 53, 61
        n = p * q  # 3233
        result = trial_division_factorization(n)
        assert result is not None
        assert set(result) == {p, q}

    def test_full_attack_success(self):
        keypair = generate_rsa_keypair(53, 61, 17)
        message = 42
        ct = rsa_encrypt(message, keypair["public_key"])
        result = attack_small_rsa(keypair["n"], keypair["e"], ct)
        assert result["success"] == True
        assert result["decrypted_value"] == message

    def test_demo_attack_completes(self):
        result = demo_full_rsa_attack()
        assert "attack" in result
        assert result["attack"]["success"] == True
