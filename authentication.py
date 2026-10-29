#Author: Logan Dalton
#Date: October 18, 2026
#Assignment: Authenticated Diffie-Hellman Project
#File: authentication.py - trusted-key lookup, encoding, signatures

import json

from cryptography.exceptions import InvalidSignature

MAX_MESSAGE_BYTES = 4096


#Step 6: trusted setup. Alice trusts Bob's real public key and Bob trusts Alice's.
def trusted_setup(alice, bob):
    alice["trusted_keys"]["Bob"] = bob["signing_key"].public_key()
    bob["trusted_keys"]["Alice"] = alice["signing_key"].public_key()


#Step 7: the same message always turns into the exact same bytes
def encode(message):
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


#json normally keeps the last copy of a duplicate key, so duplicates are rejected here
def reject_duplicate_keys(pairs):
    keys = [key for key, value in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate JSON key")
    return dict(pairs)


#size is checked before parsing. every json error is a ValueError.
def decode(data):
    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError("message is too big")
    return json.loads(data, object_pairs_hook=reject_duplicate_keys)


#every network message is {"payload": {...}, "signature": "<hex>"}.
#the signature is outside the signed payload.
def sign(person, payload):
    signature = person["signing_key"].sign(encode(payload))
    return encode({"payload": payload, "signature": signature.hex()})


#a good signature returns normally and a bad one raises InvalidSignature,
#which aborts the exchange. the key always comes from the trusted setup.
def verify(person, signer_name, payload, signature):
    try:
        person["trusted_keys"][signer_name].verify(signature, encode(payload))
    except InvalidSignature:
        raise ValueError("signature INVALID")


def is_hex(value, length):
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)
