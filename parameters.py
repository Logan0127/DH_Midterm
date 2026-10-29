#Author: Logan Dalton
#Date: October 18, 2026
#Assignment: Authenticated Diffie-Hellman Project
#File: parameters.py - library prime generation, received modulus validation,
#      factoring p - 1, and generator selection

import secrets

from Crypto.Util.number import getPrime, isPrime

from modular_math import is_int, modular_exponentiation


# ---------------- Step 2: generate the public modulus ----------------

def generate_prime(bits=16):
    # 1. bits has to be an integer from 16 through 32
    if not is_int(bits) or bits < 16 or bits > 32:
        raise ValueError("prime size must be between 16 and 32 bits.")
    # 2. Library generates an exact bits-bit prime
    p = getPrime(bits, randfunc=secrets.token_bytes)
    # 3. Confirm the bit length and that p is odd
    if p.bit_length() != bits or p % 2 == 0:
        raise ValueError("library returned a bad prime")
    # 4. Return p
    return p


#Bob checks a p he receives: type, then size, then the library's primality check
def validate_received_modulus(p):
    if not is_int(p):
        raise ValueError("p must be an integer")
    if not 16 <= p.bit_length() <= 32:
        raise ValueError("p must be 16 to 32 bits")
    if not isPrime(p):
        raise ValueError("p is not prime")


# ---------------- Step 3: factor p - 1 ----------------

#returns every distinct prime factor of n using trial division
def prime_factors(n):
    if not is_int(n) or n < 1:
        raise ValueError("n must be a positive integer")
    factors = set()

    # 1. Divide out all factors of 2, recording 2 once
    while n % 2 == 0:
        factors.add(2)
        n = n // 2

    # 2. Try odd divisors starting at 3
    divisor = 3
    # 4. Stop when divisor * divisor is bigger than what is left
    while divisor * divisor <= n:
        # 3. Divide out every occurrence of the divisor and record it once
        while n % divisor == 0:
            factors.add(divisor)
            n = n // divisor
        divisor = divisor + 2

    # 5. Whatever is left over 1 is also a prime factor
    if n > 1:
        factors.add(n)
    return factors


# ---------------- Step 4: find and verify a generator ----------------

#g is a generator if g^((p-1)/r) mod p is never 1 for any distinct prime factor r of p - 1
def is_generator(g, p, factors):
    if g < 2 or g > p - 2:
        return False
    for r in factors:
        if modular_exponentiation(g, (p - 1) // r, p) == 1:
            return False
    return True


#tries every candidate g from 2 through p - 2 and returns the first one that passes
def find_generator(p, factors):
    for g in range(2, p - 1):
        if is_generator(g, p, factors):
            return g