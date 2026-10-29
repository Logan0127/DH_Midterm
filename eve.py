#Author: Logan Dalton
#Date: October 18, 2026
#Assignment: Authenticated Diffie-Hellman Project
#File: eve.py - interception, tampering, and replay
#
#Eve controls the simulated network messages, but she can not change the
#trusted setup or see anyone's private keys.

import json

from authentication import encode
from modular_math import modular_exponentiation


#changes one value but keeps the sender's original signature
def tamper(data, field, value):
    message = json.loads(data)
    values = message["payload"].get("transcript", message["payload"])
    values[field] = value
    return encode(message)


#Step 10: Eve's substitution against plain unauthenticated DH.
#she sends E1 to Alice as though it came from Bob, and E2 to Bob as though it came from Alice.
def unauthenticated_attack(p, g, a, b, e1, e2):
    A = modular_exponentiation(g, a, p)
    B = modular_exponentiation(g, b, p)
    E1 = modular_exponentiation(g, e1, p)
    E2 = modular_exponentiation(g, e2, p)
    return {
        "E1": E1,
        "E2": E2,
        "alice": modular_exponentiation(E1, a, p),
        "eve_with_alice": modular_exponentiation(A, e1, p),
        "bob": modular_exponentiation(E2, b, p),
        "eve_with_bob": modular_exponentiation(B, e2, p),
    }