#Author: Logan Dalton
#Date: October 18, 2026
#Assignment: Authenticated Diffie-Hellman Project
#File: modular_math.py - square-and-multiply


#True and False count as integers in python, so they are rejected here
def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


#calculates base^exponent mod modulus without building the full power
def modular_exponentiation(base, exponent, modulus):
    if not (is_int(base) and is_int(exponent) and is_int(modulus)):
        raise ValueError("base, exponent, and modulus must be integers")
    if exponent < 0 or modulus <= 0:
        raise ValueError("exponent must be 0 or more and modulus must be positive")

    # 1. Set result = 1 % modulus
    result = 1 % modulus
    # 2. Set base = base % modulus
    base = base % modulus
    # 3. While exponent is greater than zero
    while exponent > 0:
        #odd exponent means the lowest binary digit is 1, so this power is part of the answer
        if exponent % 2 == 1:
            result = (result * base) % modulus
        #squaring gives the next power of two
        base = (base * base) % modulus
        #halving moves to the next binary digit
        exponent = exponent // 2
    # 4. Return result
    return result
