#Author: Logan Dalton
#Date: October 18, 2026
#Assignment: Authenticated Diffie-Hellman Project
#File: participant.py - local DH and signing state for Alice or Bob

import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modular_math import modular_exponentiation


#each person keeps their own signing key private.
#trusted_keys gets filled in by the trusted setup in authentication.py.
def new_participant(name):
    return {
        "name": name,
        "signing_key": Ed25519PrivateKey.generate(),
        "trusted_keys": {},
        "sessions": {},
    }


#Step 5: a fresh private exponent and its public value, both in 2 .. p - 2
def new_key_pair(p, g):
    while True:
        private = secrets.randbelow(p - 3) + 2
        public = modular_exponentiation(g, private, p)
        #if the public value is out of range, generate another private exponent
        if 2 <= public <= p - 2:
            return private, public


#Step 7: a fresh 32-byte nonce as 64 hex characters (public, not secret)
def new_nonce():
    return secrets.token_bytes(32).hex()


#on rejection the session is aborted and everything usable in it is cleared
def abort(session):
    session.clear()
    session["state"] = "aborted"