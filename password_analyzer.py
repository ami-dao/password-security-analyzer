import string
import math
import getpass


COMMON_TERMS = {
    "password", "admin", "welcome", "qwerty", "azerty",
    "letmein", "user", "test", "pharmacy", "drug", "health",
    "motdepasse", "bonjour", "soleil", "123456", "azerty123"
}

COMMON_SEQUENCES = [
    "123", "1234", "12345",
    "abc", "abcd",
    "qwerty", "azerty"
]


def detect_character_sets(password: str) -> tuple:
    """
    Detect the character categories present in the password.
    Returns booleans and an estimated character pool size.
    """
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    has_extended = any(ord(c) > 127 for c in password)

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        pool_size += len(string.punctuation)

    return has_lower, has_upper, has_digit, has_special, has_extended, pool_size


def calculate_entropy(length: int, pool_size: int) -> float:
    """
    Estimate password entropy in bits using:
    entropy = length * log2(pool_size)
    """
    if length == 0 or pool_size == 0:
        return 0.0
    return length * math.log2(pool_size)


def entropy_label(entropy: float) -> str:
    """
    Convert entropy into a qualitative category.
    """
    if entropy < 28:
        return "Very weak"
    if entropy < 36:
        return "Weak"
    if entropy < 60:
        return "Moderate"
    if entropy < 128:
        return "Strong"
    return "Very strong"


def detect_common_patterns(password: str) -> list:
    """
    Detect predictable patterns frequently found in weak passwords.
    """
    warnings = []
    lowered = password.lower()

    if lowered in COMMON_TERMS:
        warnings.append("The password is a very common word.")
    elif any(term in lowered for term in COMMON_TERMS):
        warnings.append("The password contains a predictable word.")

    if any(seq in lowered for seq in COMMON_SEQUENCES):
        warnings.append("The password contains a common sequence.")

    if len(set(password)) <= 2 and len(password) >= 6:
        warnings.append("The password has very little character variety.")

    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            warnings.append("The password contains repeated consecutive characters.")
            break

    if password.isdigit():
        warnings.append("The password contains only numbers.")

    if password.isalpha():
        warnings.append("The password contains only letters.")

    deleet = lowered.translate(str.maketrans({
        "@": "a",
        "3": "e",
        "1": "l",
        "0": "o",
        "$": "s",
        "7": "t",
        "!": "i"
    }))

    if deleet in COMMON_TERMS:
        warnings.append("The password resembles a common word written in leetspeak.")

    return warnings


def estimate_crack_time(entropy: float, guesses_per_second: int = 1_000_000_000) -> float:
    """
    Very simplified average brute-force estimate.
    Assumes an attacker tests about half of the search space on average.
    """
    if entropy <= 0:
        return 0.0
    return (2 ** (entropy - 1)) / guesses_per_second


def format_time(seconds: float) -> str:
    """
    Convert a duration in seconds into a readable string.
    """
    if seconds < 1:
        return "less than 1 second"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.2f} days"
    return f"{seconds / 31536000:.2e} years"


def calculate_score(password: str,
                    has_lower: bool,
                    has_upper: bool,
                    has_digit: bool,
                    has_special: bool,
                    warnings: list,
                    entropy: float) -> int:
    """
    Compute a score out of 100 based on length, diversity, entropy, and warnings.
    """
    score = 0
    length = len(password)

    # Length
    if length >= 8:
        score += 15
    if length >= 12:
        score += 15
    if length >= 16:
        score += 10
    if length >= 20:
        score += 5

    # Character diversity
    if has_lower:
        score += 8
    if has_upper:
        score += 8
    if has_digit:
        score += 8
    if has_special:
        score += 12

    categories = sum([has_lower, has_upper, has_digit, has_special])
    if categories >= 3:
        score += 8
    if categories == 4:
        score += 7

    # Entropy bonus
    if entropy >= 50:
        score += 5
    if entropy >= 80:
        score += 5

    # Penalties
    score -= 12 * len(warnings)

    return max(0, min(score, 100))


def classify_strength(score: int) -> str:
    """
    Convert the score into a strength category.
    """
    if score < 35:
        return "Weak"
    if score < 55:
        return "Moderate"
    if score < 75:
        return "Strong"
    return "Very strong"


def generate_recommendations(password: str,
                             has_lower: bool,
                             has_upper: bool,
                             has_digit: bool,
                             has_special: bool,
                             warnings: list) -> list:
    """
    Generate tailored recommendations to improve password strength.
    """
    recommendations = []

    if len(password) < 12:
        recommendations.append("Use at least 12 characters.")
    if not has_upper:
        recommendations.append("Add uppercase letters.")
    if not has_lower:
        recommendations.append("Add lowercase letters.")
    if not has_digit:
        recommendations.append("Add numbers.")
    if not has_special:
        recommendations.append("Add special characters.")
    if warnings:
        recommendations.append("Avoid predictable words, common sequences, and repeated characters.")
    if len(password) < 16:
        recommendations.append("Consider using a longer passphrase, for example: Purple-Horse!42Night")

    if not recommendations:
        recommendations.append("This password already follows strong basic security practices.")

    return recommendations


def analyze_password(password: str) -> None:
    """
    Main analysis function.
    """
    length = len(password)

    has_lower, has_upper, has_digit, has_special, has_extended, pool_size = detect_character_sets(password)
    warnings = detect_common_patterns(password)
    entropy = calculate_entropy(length, pool_size)
    crack_seconds = estimate_crack_time(entropy)

    score = calculate_score(
        password,
        has_lower,
        has_upper,
        has_digit,
        has_special,
        warnings,
        entropy
    )

    strength = classify_strength(score)
    recommendations = generate_recommendations(
        password,
        has_lower,
        has_upper,
        has_digit,
        has_special,
        warnings
    )

    print("\n=== Password Security Report ===")
    print(f"Length:                    {length} characters")
    print(f"Lowercase letters:         {'Yes' if has_lower else 'No'}")
    print(f"Uppercase letters:         {'Yes' if has_upper else 'No'}")
    print(f"Numbers:                   {'Yes' if has_digit else 'No'}")
    print(f"Special characters:        {'Yes' if has_special else 'No'}")
    print(f"Extended Unicode chars:    {'Yes' if has_extended else 'No'}")
    print(f"Estimated character pool:  {pool_size}")
    print(f"Estimated entropy:         {entropy:.1f} bits ({entropy_label(entropy)})")
    print(f"Estimated crack time:      {format_time(crack_seconds)}")
    print(f"Security score:            {score}/100")
    print(f"Strength category:         {strength}")

    print("\nWarnings:")
    if warnings:
        for warning in warnings:
            print(f"- {warning}")
    else:
        print("- No obvious weak pattern detected.")

    print("\nRecommendations:")
    for recommendation in recommendations:
        print(f"- {recommendation}")


def main() -> None:
    print("Password Security Analyzer")
    print("--------------------------")
    password = getpass.getpass("Enter a password to analyze: ")

    if not password:
        print("No password entered.")
        return

    analyze_password(password)


if __name__ == "__main__":
    main()
