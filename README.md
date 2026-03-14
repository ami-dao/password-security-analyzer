# password-security-analyzer

Python tool to evaluate password strength and detect common security weaknesses.

## Project goal

This project was created to practice Python programming and basic cybersecurity concepts by building a password analysis tool.

The program evaluates a password according to several criteria:

- password length
- presence of uppercase and lowercase letters
- presence of numbers
- presence of special characters
- estimated entropy
- detection of common weak patterns
- simplified brute-force resistance estimate

## Features

- strength score out of 100
- strength category (Weak, Moderate, Strong, Very strong)
- entropy estimation
- detection of predictable password patterns
- detection of common sequences and repeated characters
- leetspeak pattern detection
- tailored security recommendations

## Technologies used

- Python
- standard libraries: `string`, `math`, `getpass`

## How to run

```bash
python3 password_analyzer.py
