#Author: Logan Dalton
#Date: October 18, 2026
#Assignment: Authenticated Diffie-Hellman Project
#File: main.py - demonstrations and timing

import time

import Crypto
import cryptography

from authentication import trusted_setup
from eve import tamper, unauthenticated_attack
from parameters import find_generator, generate_prime, prime_factors
from participant import new_key_pair, new_participant
from protocol import run_exchange


#creates Alice and Bob and runs the trusted setup
def make_alice_and_bob():
    alice = new_participant("Alice")
    bob = new_participant("Bob")
    trusted_setup(alice, bob)
    return alice, bob


#generates p, factors p - 1, and finds g, timing each step with time.perf_counter
def make_parameters(bits):
    start = time.perf_counter()
    p = generate_prime(bits)
    prime_time = time.perf_counter() - start

    start = time.perf_counter()
    factors = prime_factors(p - 1)
    factor_time = time.perf_counter() - start

    start = time.perf_counter()
    g = find_generator(p, factors)
    generator_time = time.perf_counter() - start
    return p, g, prime_time, factor_time, generator_time


# ---------------- Demonstrations ----------------

def demo_exchange(bits):
    print(f"Requested prime size: {bits} bits")
    p, g = make_parameters(bits)[:2]
    print("Modulus: generated using library prime generator")
    print(f"Modulus bit length: {p.bit_length()}")
    alice, bob = make_alice_and_bob()
    try:
        result = run_exchange(alice, bob, p, g)
    except ValueError as error:
        print(f"Exchange aborted: {error}")
        return
    #getting here means every check passed, since any failed check raises an error
    print("Received modulus library validation: PASS")
    print("Generator: validated")
    print("Alice initiation signature: VALID")
    print("Bob response signature: VALID")
    print("Alice finish signature: VALID")
    print("Transcript authenticated: YES")
    #the test coordinator compares both local results. the secrets are never sent over the network.
    if result["alice"]["secret"] == result["bob"]["secret"]:
        print("Shared-secret equality in local test: PASS")
    else:
        print("Shared-secret equality in local test: FAIL")
    print("Explicit key confirmation: NOT IMPLEMENTED")


def demo_attack(bits):
    print("Attack against the unauthenticated version (p = 23, g = 5, a = 6, b = 15):")
    r = unauthenticated_attack(23, 5, 6, 15, 3, 7)
    print(f"  e1 = 3, public value E1 = 5^3 mod 23 = {r['E1']}")
    print(f"  e2 = 7, public value E2 = 5^7 mod 23 = {r['E2']}")
    print("  Eve sends E1 to Alice as though it came from Bob, and E2 to Bob as though it came from Alice.")
    print(f"  Alice computes: {r['E1']}^6 mod 23 = {r['alice']}")
    print(f"  Eve computes:   8^3 mod 23 = {r['eve_with_alice']}")
    print(f"  Bob computes:   {r['E2']}^15 mod 23 = {r['bob']}")
    print(f"  Eve computes:   19^7 mod 23 = {r['eve_with_bob']}")
    print("  Alice and Bob now hold different secrets, and Eve knows both.")
    print()

    print(f"Attack against the authenticated version ({bits}-bit prime):")
    p, g = make_parameters(bits)[:2]
    alice, bob = make_alice_and_bob()
    E1 = new_key_pair(p, g)[1]

    #Eve swaps Bob's B for her own value but can not make a new Bob signature
    def replace_B(step, data):
        if step == "response":
            return tamper(data, "B", E1)
        return data

    try:
        run_exchange(alice, bob, p, g, replace_B)
    except ValueError:
        print("  Eve modified Bob's public value.")
        print("  Bob response signature: INVALID")
        print("  Exchange aborted.")


def benchmark():
    print(f"Libraries: cryptography {cryptography.__version__}, pycryptodome {Crypto.__version__}")
    print()
    print("| Bits | Trial | Prime generation (s) | Factorization (s) | Generator search (s) | Authenticated | Secrets match |")
    print("|------|-------|----------------------|-------------------|----------------------|---------------|---------------|")
    times = {}
    for bits in (16, 24, 32):
        times[bits] = []
        for trial in (1, 2, 3):
            p, g, prime_time, factor_time, generator_time = make_parameters(bits)
            alice, bob = make_alice_and_bob()
            try:
                result = run_exchange(alice, bob, p, g)
                authenticated = "YES"
                match = "YES" if result["alice"]["secret"] == result["bob"]["secret"] else "NO"
            except ValueError:
                authenticated = "NO"
                match = "NO"
            times[bits].append((prime_time, factor_time, generator_time))
            print(f"|  {  bits  }  |   {trial}   |       {prime_time:.6f}       |      {factor_time:.6f}     |       {generator_time:.6f}       "
                  f"|      {authenticated}      |      {match}      |")

    #summarizing the timing variation for each size
    print()
    print("Timing variation (mean / min / max seconds):")
    print("| Bits |        Prime generation        |          Factorization         |        Generator search        |")
    print("|------|--------------------------------|--------------------------------|--------------------------------|")
    for bits in times:
        columns = []
        for step in (0, 1, 2):
            values = [trial[step] for trial in times[bits]]
            columns.append(f"{sum(values) / len(values):.6f} / {min(values):.6f} / {max(values):.6f}")
        print(f"|  {bits}  | " + " | ".join(columns) + " |")


# ---------------- Menu ----------------

def main():
    choice = input("1 = exchange, 2 = Eve's attack, 3 = benchmark: ").strip()
    if choice == "3":
        benchmark()
        return

    bits_text = input("Prime size in bits, 16 to 32 (press Enter for 16): ").strip()
    if bits_text == "":
        bits_text = "16"
    if not bits_text.isdigit() or int(bits_text) < 16 or int(bits_text) > 32:
        print("Error: prime size must be between 16 and 32 bits.")
        return

    if choice == "2":
        demo_attack(int(bits_text))
    else:
        demo_exchange(int(bits_text))


if __name__ == "__main__":
    main()