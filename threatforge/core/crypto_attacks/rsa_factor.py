"""
threatforge/core/crypto_attacks/rsa_factor.py

RSA Small Prime Factorization Attack

SYLLABUS: Unit 6 - Simple RSA Algorithm with small numbers
COVERAGE: CO1, CO2

THEORY:
RSA encryption relies on the computational difficulty of factoring
the product of two large prime numbers.

PUBLIC KEY: (n, e) where n = p * q (two primes)
PRIVATE KEY: (n, d) where d = e^(-1) mod phi(n), phi(n) = (p-1)(q-1)

ENCRYPTION: C = M^e mod n
DECRYPTION: M = C^d mod n

VULNERABILITY:
If p and q are SMALL (e.g., < 1000 in our demo), then n = p*q is also
relatively small and can be factored by trial division in milliseconds.

ACADEMIC DEMO:
We use small primes (< 10000) to make the math understandable.
Real RSA uses primes of ~1024 bits (309+ decimal digits).
Factoring a 1024-bit number would take longer than the age of the universe.

REAL-WORLD CONTEXT:
Several incidents of weak RSA:
- 2012: Researchers found millions of RSA keys share prime factors
  (insufficient randomness in key generation)
- Heartbleed bug (2014): Exposed private keys in memory
- Coppersmith's attack: Works on small public exponent e
"""

import time
import math
import random
from typing import Optional, Dict, Any, List, Tuple


def is_prime(n: int) -> bool:
    """
    Check if n is prime using trial division.

    ALGORITHM:
    A number n is prime if it has no divisors from 2 to sqrt(n).
    We only check odd numbers after 2 for efficiency.

    TIME COMPLEXITY: O(sqrt(n))

    Args:
        n: Number to test

    Returns:
        True if prime, False otherwise
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    # Check odd divisors up to sqrt(n)
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False

    return True


def generate_small_prime(min_val: int = 50, max_val: int = 500) -> int:
    """
    Generate a random small prime for demonstration purposes.

    Args:
        min_val: Minimum prime value
        max_val: Maximum prime value

    Returns:
        A random prime between min_val and max_val
    """
    primes = [n for n in range(min_val, max_val) if is_prime(n)]
    return random.choice(primes)


def mod_inverse(a: int, m: int) -> Optional[int]:
    """
    Extended Euclidean Algorithm to find modular inverse.

    Finds x such that: a * x ≡ 1 (mod m)

    This is used to compute d = e^(-1) mod phi(n).

    ALGORITHM:
    Extended Euclidean Algorithm - extends GCD to find
    Bezout's identity coefficients x, y such that:
    a*x + m*y = gcd(a, m)

    If gcd(a, m) = 1, then a*x ≡ 1 (mod m), so x is our inverse.

    Args:
        a: Number to find inverse of
        m: Modulus

    Returns:
        Modular inverse or None if not invertible
    """
    if math.gcd(a, m) != 1:
        return None

    # Extended Euclidean Algorithm
    old_r, r = a, m
    old_s, s = 1, 0

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    return old_s % m


def generate_rsa_keypair(p: int, q: int, e: int = 65537) -> Optional[Dict[str, Any]]:
    """
    Generate RSA key pair from given primes p and q.

    This is used to generate demo keys that we then attack.

    Args:
        p: First prime
        q: Second prime
        e: Public exponent (commonly 65537, but we use 17 for small demos)

    Returns:
        Dictionary with public and private key components, or None if invalid
    """
    if not is_prime(p) or not is_prime(q) or p == q:
        return None

    # Compute public modulus
    n = p * q

    # Compute Euler's totient function: phi(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)

    # Verify e is valid (gcd(e, phi_n) must be 1)
    # Use smaller e for demo if 65537 doesn't work
    actual_e = e
    if math.gcd(e, phi_n) != 1:
        # Find valid e for demo
        for candidate_e in [3, 5, 7, 11, 13, 17, 19, 23]:
            if candidate_e < phi_n and math.gcd(candidate_e, phi_n) == 1:
                actual_e = candidate_e
                break
        else:
            return None

    # Compute private exponent d
    d = mod_inverse(actual_e, phi_n)
    if d is None:
        return None

    return {
        "p": p,
        "q": q,
        "n": n,
        "phi_n": phi_n,
        "e": actual_e,
        "d": d,
        "public_key": (n, actual_e),
        "private_key": (n, d)
    }


def rsa_encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """
    RSA encryption: C = M^e mod n

    Args:
        message: Integer plaintext (must be < n)
        public_key: Tuple (n, e)

    Returns:
        Encrypted ciphertext integer
    """
    n, e = public_key
    return pow(message, e, n)  # Python's pow with 3 args = fast modular exponentiation


def rsa_decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """
    RSA decryption: M = C^d mod n

    Args:
        ciphertext: Encrypted integer
        private_key: Tuple (n, d)

    Returns:
        Decrypted plaintext integer
    """
    n, d = private_key
    return pow(ciphertext, d, n)


def trial_division_factorization(n: int) -> Optional[Tuple[int, int]]:
    """
    Factor n by trial division.

    ALGORITHM:
    Try every integer from 2 to sqrt(n) as a potential factor.
    If n % i == 0, then i and n/i are the factors.

    TIME COMPLEXITY: O(sqrt(n))

    WHY THIS WORKS FOR SMALL RSA:
    If n = 3233 = 53 × 61, then sqrt(3233) ≈ 56.8.
    We only need to check divisors up to 56 to find 53.

    WHY THIS FAILS FOR REAL RSA:
    If n is 2048 bits, sqrt(n) is 1024 bits ≈ 10^308.
    Even at 10^18 divisions per second, this would take longer
    than the age of the universe.

    Args:
        n: Public modulus to factor

    Returns:
        Tuple (p, q) if found, None if not factorable by this method
    """
    if n < 2:
        return None

    # Check divisibility starting from 2
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            p = i
            q = n // i
            return (p, q)

    return None  # n is prime (shouldn't happen for valid RSA n)


def attack_small_rsa(n: int, e: int, ciphertext: int) -> Dict[str, Any]:
    """
    Complete attack on small RSA.

    STEPS:
    1. Factor n = p * q using trial division
    2. Compute phi(n) = (p-1) * (q-1)
    3. Compute d = e^(-1) mod phi(n)
    4. Decrypt: M = C^d mod n

    This demonstrates why RSA key size matters fundamentally.

    Args:
        n: Public modulus
        e: Public exponent
        ciphertext: Encrypted message to recover

    Returns:
        Complete attack results with every step shown
    """
    start_time = time.perf_counter()

    result = {
        "attack_type": "rsa_small_prime_factorization",
        "input": {"n": n, "e": e, "ciphertext": ciphertext},
        "steps": []
    }

    # Step 1: Factor n
    result["steps"].append({
        "step": 1,
        "description": "Factor public modulus n using trial division",
        "formula": "Find p, q such that n = p × q"
    })

    factors = trial_division_factorization(n)

    if factors is None:
        result["success"] = False
        result["error"] = f"Could not factor n={n} - may be too large or prime"
        result["time_taken_ms"] = round((time.perf_counter() - start_time) * 1000, 3)
        return result

    p, q = factors
    result["steps"][0]["result"] = f"n = {p} × {q}"
    result["steps"][0]["p"] = p
    result["steps"][0]["q"] = q

    # Step 2: Compute phi(n)
    phi_n = (p - 1) * (q - 1)
    result["steps"].append({
        "step": 2,
        "description": "Compute Euler's totient function",
        "formula": "φ(n) = (p-1)(q-1)",
        "calculation": f"φ({n}) = ({p}-1)({q}-1) = {p-1} × {q-1} = {phi_n}",
        "result": phi_n
    })

    # Step 3: Compute private key d
    d = mod_inverse(e, phi_n)
    if d is None:
        result["success"] = False
        result["error"] = "Could not compute private exponent d"
        result["time_taken_ms"] = round((time.perf_counter() - start_time) * 1000, 3)
        return result

    result["steps"].append({
        "step": 3,
        "description": "Compute private exponent d",
        "formula": "d = e⁻¹ mod φ(n)  [Extended Euclidean Algorithm]",
        "calculation": f"d = {e}⁻¹ mod {phi_n} = {d}",
        "result": d,
        "verification": f"e × d mod φ(n) = {e} × {d} mod {phi_n} = {(e * d) % phi_n} (should be 1)"
    })

    # Step 4: Decrypt
    decrypted = rsa_decrypt(ciphertext, (n, d))
    result["steps"].append({
        "step": 4,
        "description": "Decrypt ciphertext using recovered private key",
        "formula": "M = C^d mod n",
        "calculation": f"M = {ciphertext}^{d} mod {n} = {decrypted}",
        "result": decrypted
    })

    end_time = time.perf_counter()

    result["success"] = True
    result["recovered_private_key"] = {"d": d, "n": n}
    result["decrypted_value"] = decrypted
    result["time_taken_ms"] = round((end_time - start_time) * 1000, 3)
    result["security_insight"] = (
        f"RSA with n={n} broken in {result['time_taken_ms']}ms. "
        f"Real RSA uses n with 600+ digits, making this attack computationally infeasible."
    )

    return result


def demo_full_rsa_attack() -> Dict[str, Any]:
    """
    Generate demo RSA scenario and attack it.

    Creates small RSA keys, encrypts a message, then attacks.
    Used for dashboard demo and testing.

    Returns:
        Complete demo scenario with all steps
    """
    # Generate small primes for demo
    p = generate_small_prime(50, 200)
    q = generate_small_prime(50, 200)
    while q == p:
        q = generate_small_prime(50, 200)

    # Generate key pair
    keypair = generate_rsa_keypair(p, q)
    if keypair is None:
        return {"error": "Failed to generate key pair"}

    # Encrypt a small message
    message = 42  # Demo message (must be < n)
    if message >= keypair["n"]:
        message = keypair["n"] - 10

    ciphertext = rsa_encrypt(message, keypair["public_key"])

    # Now attack!
    attack_result = attack_small_rsa(keypair["n"], keypair["e"], ciphertext)

    return {
        "demo_scenario": {
            "original_message": message,
            "primes_used": {"p": p, "q": q},
            "public_key": {"n": keypair["n"], "e": keypair["e"]},
            "ciphertext": ciphertext,
            "note": "Attacker only knows: n, e, ciphertext"
        },
        "attack": attack_result,
        "conclusion": (
            "Successfully recovered message without knowing private key. "
            f"Original: {message}, Recovered: {attack_result.get('decrypted_value', 'FAILED')}"
        )
    }
