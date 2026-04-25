"""
threatforge/core/crypto_attacks/frequency.py

Frequency Analysis Engine - Foundation of all cryptanalysis attacks.

THEORY:
Every natural language has statistical patterns in letter usage.
English has E as the most common letter (12.7%), followed by T, A, O, I, N.
Classical ciphers preserve these patterns even after encryption.
This module exploits that fundamental weakness.

ACADEMIC CONNECTION:
This same principle explains why:
- Caesar cipher is trivially broken (frequency still preserved, just shifted)
- Vigenere cipher is broken (Kasiski finds key length, then each position attacked separately)
- Any substitution cipher with large ciphertext is vulnerable to statistical analysis

SYLLABUS COVERAGE: CO1, CO2 (Cryptography fundamentals)
"""

from typing import Dict, List, Tuple
import math


# English letter frequency distribution (percentage)
# Source: Based on analysis of large English text corpora
# These are the expected frequencies in any sufficiently large English text
ENGLISH_FREQUENCIES: Dict[str, float] = {
    'A': 8.2,  'B': 1.5,  'C': 2.8,  'D': 4.3,
    'E': 12.7, 'F': 2.2,  'G': 2.0,  'H': 6.1,
    'I': 7.0,  'J': 0.15, 'K': 0.77, 'L': 4.0,
    'M': 2.4,  'N': 6.7,  'O': 7.5,  'P': 1.9,
    'Q': 0.10, 'R': 6.0,  'S': 6.3,  'T': 9.1,
    'U': 2.8,  'V': 0.98, 'W': 2.4,  'X': 0.15,
    'Y': 2.0,  'Z': 0.074
}

# Most common English letters in order
# Used for quick scoring and key guessing
ENGLISH_LETTER_ORDER: str = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

# Common English words for plaintext validation
# If decrypted text contains these, it's likely correct English
COMMON_ENGLISH_WORDS: List[str] = [
    "the", "and", "for", "are", "but", "not", "you", "all",
    "can", "her", "was", "one", "our", "had", "him", "his",
    "how", "man", "new", "now", "old", "see", "two", "way",
    "who", "boy", "did", "its", "let", "put", "say", "she",
    "too", "use", "that", "this", "have", "from", "they",
    "know", "want", "been", "good", "much", "some", "time",
    "very", "when", "come", "here", "just", "like", "long",
    "make", "many", "more", "only", "over", "such", "take",
    "than", "them", "well", "were", "with", "your", "could"
]


def compute_letter_frequency(text: str) -> Dict[str, float]:
    """
    Compute letter frequency distribution of a given text.

    HOW IT WORKS:
    1. Strip all non-alphabetic characters
    2. Count occurrences of each letter
    3. Convert to percentages

    Args:
        text: Any string (ciphertext or plaintext)

    Returns:
        Dictionary mapping each letter to its percentage frequency
        Example: {'A': 8.5, 'B': 1.2, ..., 'Z': 0.1}
    """
    # Remove non-alphabetic characters and convert to uppercase
    clean_text = ''.join(c.upper() for c in text if c.isalpha())

    if len(clean_text) == 0:
        # Return zero frequencies if no letters found
        return {chr(i): 0.0 for i in range(65, 91)}

    # Count each letter
    counts: Dict[str, int] = {}
    for letter in clean_text:
        counts[letter] = counts.get(letter, 0) + 1

    # Convert to percentages
    total_letters = len(clean_text)
    frequencies: Dict[str, float] = {}
    for i in range(65, 91):  # A=65 to Z=90
        letter = chr(i)
        freq_count = counts.get(letter, 0)
        frequencies[letter] = round((freq_count / total_letters) * 100, 3)

    return frequencies


def score_english_likelihood(text: str) -> float:
    """
    Score how likely a text is to be English using chi-squared test.

    THEORY:
    Chi-squared statistic measures how different the observed frequencies
    are from expected (English) frequencies.
    Lower chi-squared = closer to English = higher likelihood score.

    FORMULA:
    chi_squared = sum((observed - expected)^2 / expected) for each letter

    We then convert to a 0-100 score where:
    - 100 = perfect English frequency match
    - 0   = completely different from English

    Args:
        text: Decrypted candidate text

    Returns:
        Float 0-100, where 100 = most likely English
    """
    observed = compute_letter_frequency(text)

    # Compute chi-squared statistic
    chi_squared = 0.0
    for letter, expected_freq in ENGLISH_FREQUENCIES.items():
        observed_freq = observed.get(letter, 0.0)
        expected = expected_freq

        if expected > 0:
            chi_squared += ((observed_freq - expected) ** 2) / expected

    # Convert chi-squared to 0-100 score
    # Lower chi-squared = better match = higher score
    # We cap the score calculation to avoid division issues
    # Typical English text has chi-squared around 10-30
    # Random text has chi-squared around 200-400
    score = max(0.0, 100.0 - (chi_squared * 0.5))

    return round(score, 2)


def score_word_presence(text: str) -> float:
    """
    Score text based on presence of common English words.

    THEORY:
    If decrypted text contains words like "the", "and", "for",
    it's almost certainly correct English. This supplements
    frequency analysis for short texts where statistical
    analysis is less reliable.

    Args:
        text: Candidate decrypted text

    Returns:
        Float 0-100 based on percentage of words recognized
    """
    text_lower = text.lower()
    words_found = 0

    for word in COMMON_ENGLISH_WORDS:
        if word in text_lower:
            words_found += 1

    # Score based on how many common words appear
    max_expected = min(len(COMMON_ENGLISH_WORDS), max(1, len(text.split())))
    score = (words_found / max_expected) * 100

    return round(min(100.0, score), 2)


def combined_english_score(text: str) -> float:
    """
    Combine frequency analysis and word presence for robust scoring.

    This is the main scoring function used by all cipher attacks.

    WEIGHTING:
    - 70% chi-squared frequency score (reliable for long texts)
    - 30% word presence score (reliable for short texts)

    Args:
        text: Candidate decrypted text

    Returns:
        Float 0-100 where 100 = definitely English
    """
    freq_score = score_english_likelihood(text)
    word_score = score_word_presence(text)

    combined = (freq_score * 0.7) + (word_score * 0.3)
    return round(combined, 2)


def find_most_likely_shift(ciphertext_frequencies: Dict[str, float]) -> List[Tuple[int, float]]:
    """
    For Caesar cipher: find most likely shifts by comparing frequencies.

    ALGORITHM:
    For each possible shift (0-25):
    1. If this shift is correct, the most frequent letter in ciphertext
       should map to E (most common English letter)
    2. Score how well this shift explains the observed frequencies
    3. Return all shifts ranked by score

    Args:
        ciphertext_frequencies: Letter frequencies of ciphertext

    Returns:
        List of (shift, score) tuples sorted by score descending
    """
    results: List[Tuple[int, float]] = []

    for shift in range(26):
        # Score this shift
        score = 0.0
        for letter, observed_freq in ciphertext_frequencies.items():
            # What letter would this be if we apply this shift?
            original_letter_idx = (ord(letter) - 65 - shift) % 26
            original_letter = chr(original_letter_idx + 65)

            # Get expected frequency for this original letter
            expected_freq = ENGLISH_FREQUENCIES.get(original_letter, 0)

            # Score = correlation between observed and expected
            score += observed_freq * expected_freq

        results.append((shift, round(score, 3)))

    # Sort by score descending (higher = more likely)
    results.sort(key=lambda x: x[1], reverse=True)
    return results


def index_of_coincidence(text: str) -> float:
    """
    Compute Index of Coincidence (IC) for a text.

    THEORY (Important for Kasiski/Vigenere):
    IC measures the probability that two randomly chosen letters
    from a text are identical.

    For English text: IC ≈ 0.065 (because English is non-uniform)
    For random text:  IC ≈ 0.038 (because all letters equally likely)
    For Vigenere cipher with key length k:
        IC falls between 0.038 and 0.065

    By trying different key lengths and measuring IC,
    we can FIND the key length of Vigenere-encrypted text.

    FORMULA:
    IC = sum(n_i * (n_i - 1)) / (N * (N - 1))
    where n_i = count of letter i, N = total letters

    Args:
        text: Text to analyze

    Returns:
        Float IC value (English ≈ 0.065, random ≈ 0.038)
    """
    clean = ''.join(c.upper() for c in text if c.isalpha())
    n = len(clean)

    if n < 2:
        return 0.0

    counts = {}
    for char in clean:
        counts[char] = counts.get(char, 0) + 1

    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)

    return round(numerator / denominator, 6) if denominator > 0 else 0.0
