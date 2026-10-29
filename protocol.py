#Author: Logan Dalton
#Date: October 18, 2026
#Assignment: Authenticated Diffie-Hellman Project
#File: protocol.py - message processing and session state
#
#   Message 1: Alice -> Bob    init      signed by Alice
#   Message 2: Bob   -> Alice  response  signed by Bob, covers the complete transcript
#   Message 3: Alice -> Bob    finish    signed by Alice, covers the same transcript
#
#Every failed check raises ValueError and the exchange is aborted.

from authentication import decode, is_hex, sign, verify
from modular_math import is_int, modular_exponentiation
from parameters import is_generator, prime_factors, validate_received_modulus
from participant import abort, new_key_pair, new_nonce

PROTOCOL = "DH-CLASSROOM-AUTH-v1"
INIT_FIELDS = {"protocol", "message_type", "initiator", "responder", "p", "g", "A", "nonce_A"}
TRANSCRIPT_FIELDS = {"protocol", "initiator", "responder", "p", "g", "A", "B", "nonce_A", "nonce_B"}


# ---------------- Message checks ----------------

#checks the size, JSON, fields and message type. returns (payload, signature bytes).
def open_message(data, message_type):
    message = decode(data)
    if not isinstance(message, dict) or set(message) != {"payload", "signature"}:
        raise ValueError("malformed message")
    payload = message["payload"]
    expected_fields = INIT_FIELDS if message_type == "init" else {"message_type", "transcript"}
    if not isinstance(payload, dict) or set(payload) != expected_fields:
        raise ValueError("missing or unexpected fields")
    if payload["message_type"] != message_type:
        raise ValueError(f"out of order: expected {message_type}")
    if not is_hex(message["signature"], 128):
        raise ValueError("malformed signature")

    #the values are inside the transcript for the response and finish
    values = payload if message_type == "init" else payload["transcript"]
    if message_type != "init" and (not isinstance(values, dict) or set(values) != TRANSCRIPT_FIELDS):
        raise ValueError("missing or unexpected transcript fields")
    check_values(values)
    return payload, bytes.fromhex(message["signature"])


#protocol label, expected identities, integer fields, and nonces.
#strings are never turned into integers, and big integers are rejected before any math.
def check_values(values):
    if values["protocol"] != PROTOCOL:
        raise ValueError("wrong protocol label")
    if values["initiator"] != "Alice" or values["responder"] != "Bob":
        raise ValueError("unexpected identities")
    for name in ("p", "g", "A", "B"):
        if name in values and (not is_int(values[name]) or not 0 <= values[name] < 2 ** 32):
            raise ValueError(f"{name} must be an integer of at most 32 bits")
    for name in ("nonce_A", "nonce_B"):
        if name in values and not is_hex(values[name], 64):
            raise ValueError(f"{name} must be 64 hex characters")


#received public values must be from 2 through p - 2
def check_range(value, p):
    if value < 2 or value > p - 2:
        raise ValueError("public value out of range")


#finds the pending session a message belongs to
def pending_session(person, nonce):
    session = person["sessions"].get(nonce)
    if session is None or session["state"] != "pending":
        raise ValueError("no matching pending session (stale, duplicate, or already completed)")
    return session


# ---------------- Message 1: Alice's signed initiation ----------------

def create_init(alice, p, g):
    a, A = new_key_pair(p, g)
    nonce_A = new_nonce()
    alice["sessions"][nonce_A] = {"state": "pending", "p": p, "g": g, "a": a, "A": A}
    payload = {"protocol": PROTOCOL, "message_type": "init", "initiator": "Alice", "responder": "Bob",
               "p": p, "g": g, "A": A, "nonce_A": nonce_A}
    return sign(alice, payload)


# ---------------- Message 2: Bob's signed response ----------------

def handle_init(bob, data):
    # 1. Check format, size limits, protocol, message type, and expected identities
    payload, signature = open_message(data, "init")
    # 2. Verify the signature using Alice's trusted signing public key
    verify(bob, "Alice", payload, signature)
    # 3. Independently validate p with the library, factor p - 1, and verify g
    p, g, A = payload["p"], payload["g"], payload["A"]
    validate_received_modulus(p)
    if not is_generator(g, p, prime_factors(p - 1)):
        raise ValueError("g is not a generator")
    # 4. Check A is in the permitted range
    check_range(A, p)

    b, B = new_key_pair(p, g)
    nonce_B = new_nonce()
    transcript = {"protocol": PROTOCOL, "initiator": "Alice", "responder": "Bob",
                  "p": p, "g": g, "A": A, "B": B, "nonce_A": payload["nonce_A"], "nonce_B": nonce_B}
    #Bob does not calculate his secret until he accepts Alice's finish
    bob["sessions"][nonce_B] = {"state": "pending", "b": b, "transcript": transcript}
    return sign(bob, {"message_type": "response", "transcript": transcript})


# ---------------- Message 3: Alice's signed finish ----------------

def handle_response(alice, data):
    # 1. Validate the response schema and expected identities
    payload, signature = open_message(data, "response")
    transcript = payload["transcript"]
    session = pending_session(alice, transcript["nonce_A"])
    try:
        # 2. p, g, A and nonce_A must match her pending session exactly
        for name in ("p", "g", "A"):
            if transcript[name] != session[name]:
                raise ValueError(f"{name} does not match the pending session")
        # 3. Check B is in the permitted range
        check_range(transcript["B"], session["p"])
        # 4. Verify Bob's signature using Bob's trusted signing key
        verify(alice, "Bob", payload, signature)
    # 5. Abort on any failure
    except ValueError:
        abort(session)
        raise

    #Step 9: after verifying Bob's signature on the complete transcript, S_A = B^a mod p
    session["secret"] = modular_exponentiation(transcript["B"], session["a"], session["p"])
    session["state"] = "authenticated"
    return sign(alice, {"message_type": "finish", "transcript": transcript})


# ---------------- Bob accepts the finish ----------------

def handle_finish(bob, data):
    payload, signature = open_message(data, "finish")
    transcript = payload["transcript"]
    session = pending_session(bob, transcript["nonce_B"])
    try:
        #exact agreement with Bob's pending transcript, then Alice's signature
        if transcript != session["transcript"]:
            raise ValueError("transcript does not match the pending session")
        verify(bob, "Alice", payload, signature)
    except ValueError:
        abort(session)
        raise

    #Step 9: S_B = A^b mod p
    session["secret"] = modular_exponentiation(transcript["A"], session["b"], transcript["p"])
    session["state"] = "authenticated"


# ---------------- The whole exchange ----------------

#the network just passes messages along unless Eve replaces it
def no_attack(step, data):
    return data


#sends the three messages through network(step, data), where Eve can change them.
#returns the messages plus Alice's and Bob's sessions so the test coordinator can compare secrets.
def run_exchange(alice, bob, p, g, network=no_attack):
    init = create_init(alice, p, g)
    alice_session = list(alice["sessions"].values())[-1]
    init = network("init", init)

    response = network("response", handle_init(bob, init))
    bob_session = list(bob["sessions"].values())[-1]

    finish = network("finish", handle_response(alice, response))
    handle_finish(bob, finish)
    return {"init": init, "response": response, "finish": finish, "alice": alice_session, "bob": bob_session}
