# Authenticated Diffie-Hellman Project

Author: Logan Dalton
Date: October 18, 2026

A local Python simulation of an authenticated Diffie-Hellman key exchange between Alice and Bob,
including Eve's attack against the unauthenticated and authenticated versions.

## Libraries

| Package        | Used for                                  | Version |
|----------------|-------------------------------------------|---------|
| `cryptography` | Ed25519 signatures                        | 50.0.1  |
| `pycryptodome` | Prime generation and primality validation | 4.2.0   |

Standard library: `secrets`, `json`, `time`.

## Setup

```
python -m pip install -r requirements.txt
```

## Running

```
python main.py
```

A menu asks for:

- 1 — successful authenticated exchange
- 2 — Eve's attack
- 3 — performance runs at 16, 24 and 32 bits

For 1 and 2 it also asks for a prime size from 16 to 32 (press Enter for 16).

## Files

| Module              | Responsibility                                                                                        |
|---------------------|-------------------------------------------------------------------------------------------------------|
| `modular_math.py`   | Square-and-multiply                                                                                   |
| `parameters.py`     | Library prime-generation wrapper, received-modulus validation, factorization, and generator selection |
| `participant.py`    | Local DH and signing state                                                                            |
| `authentication.py` | Trusted-key lookup, encoding, signatures                                                              |
| `protocol.py`       | Message processing and session state                                                                  |
| `eve.py`            | Interception, tampering, and replay                                                                   |
| `main.py`           | Demonstrations and timing                                                                             |

***AI assistance***

This project was written with help from Claude (Anthropic), an AI assistant, between October 18 and October 29, 2026. 
Claude helped with formatting and clearing up any incorrect code logic. It was also used for the writing of function 
descriptions and other code related comments. Lastly, claude helped clean up the 3 different outputs. Making them easier
to read and understand. I set the requirements and scope, installed and ran the program on my own machine, checked the 
outputs, and collected the sample output and timing results.

Citation:

    Anthropic. (2026). Claude (Opus 5.5) [Large language model]. https://claude.ai