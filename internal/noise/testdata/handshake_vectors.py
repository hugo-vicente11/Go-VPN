#!/usr/bin/env python3
"""Reference values for TestHandshakeKnownAnswer in handshake_test.go.

This is an independent implementation of the WireGuard handshake, written
from section 5.4 of the whitepaper and not from the Go code, so that a
mistake shared by both sides of the Go handshake still shows up. It uses only
the standard library: BLAKE2s and HMAC come from hashlib and hmac, and X25519
and ChaCha20-Poly1305 are written out below and checked against their RFC
test vectors before anything else runs.

Run it with: python3 -I handshake_vectors.py
"""

import base64
import hashlib
import hmac
import struct

# --- X25519, RFC 7748 --------------------------------------------------------

P = 2**255 - 19
A24 = 121665


def x25519(k: bytes, u: bytes) -> bytes:
    """Return X25519(k, u) with the Montgomery ladder of RFC 7748, section 5."""
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    scalar = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def public_key(private: bytes) -> bytes:
    return x25519(private, (9).to_bytes(32, "little"))


# --- ChaCha20-Poly1305, RFC 8439 ---------------------------------------------


def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += [counter]
    state += list(struct.unpack("<3I", nonce))
    s = state[:]
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12); _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14); _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15); _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13); _quarter(s, 3, 4, 9, 14)
    return struct.pack("<16I", *((s[i] + state[i]) & 0xFFFFFFFF for i in range(16)))


def _chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = _chacha_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], block))
    return bytes(out)


def _poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p, acc = 2**130 - 5, 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) % 2**128).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b"\x00" * (-len(b) % 16)


def aead_encrypt(key: bytes, counter: int, plaintext: bytes, ad: bytes) -> bytes:
    """AEAD(key, counter, plaintext, ad) from the whitepaper: the nonce is 32
    zero bits followed by the counter as a 64-bit little-endian integer."""
    nonce = b"\x00" * 4 + struct.pack("<Q", counter)
    otk = _chacha_block(key, 0, nonce)[:32]
    ct = _chacha20(key, 1, nonce, plaintext)
    mac_data = ad + _pad16(ad) + ct + _pad16(ct) + struct.pack("<QQ", len(ad), len(ct))
    return ct + _poly1305(otk, mac_data)


# --- WireGuard primitives, whitepaper section 5.4 ----------------------------


def HASH(*parts: bytes) -> bytes:
    return hashlib.blake2s(b"".join(parts)).digest()


def MAC(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def HMAC(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def KDF(n: int, key: bytes, data: bytes) -> list:
    t0 = HMAC(key, data)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = HMAC(t0, prev + bytes([i]))
        out.append(prev)
    return out


def TAI64N(unix_seconds: int, nanoseconds: int) -> bytes:
    return struct.pack(">QI", 0x400000000000000A + unix_seconds, nanoseconds)


CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"


# --- Self-tests against the RFCs ---------------------------------------------


def self_test():
    # RFC 7748, section 6.1.
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    assert public_key(a).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert public_key(b).hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert x25519(a, public_key(b)).hex() == shared
    assert x25519(b, public_key(a)).hex() == shared

    # RFC 8439, section 2.8.2.
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    ad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
    otk = _chacha_block(key, 0, nonce)[:32]
    ct = _chacha20(key, 1, nonce, pt)
    tag = _poly1305(otk, ad + _pad16(ad) + ct + _pad16(ct) + struct.pack("<QQ", len(ad), len(ct)))
    assert ct.hex().startswith("d31a8d34648e60db7b86afbc53ef7ec2")
    assert tag.hex() == "1ae10b594f09e26a7e902ecbd0600691"


# --- The handshake ------------------------------------------------------------


def main():
    self_test()

    # The same fixed inputs as handshake_test.go.
    alice_priv = base64.b64decode("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=")
    bob_priv = base64.b64decode("XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=")
    ei_priv = base64.b64decode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
    er_priv = base64.b64decode("ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=")
    initiator_index = 0x01020304
    responder_index = 0x05060708
    unix_seconds = 1795348800  # 2026-11-22 12:00:00 UTC
    q = b"\x00" * 32  # no preshared key

    si_pub, sr_pub = public_key(alice_priv), public_key(bob_priv)
    ei_pub, er_pub = public_key(ei_priv), public_key(er_priv)

    # Section 5.4.2: the initiator creates message 1.
    c = HASH(CONSTRUCTION)
    h = HASH(c, IDENTIFIER)
    h = HASH(h, sr_pub)
    (c,) = KDF(1, c, ei_pub)
    h = HASH(h, ei_pub)
    c, k = KDF(2, c, x25519(ei_priv, sr_pub))
    encrypted_static = aead_encrypt(k, 0, si_pub, h)
    h = HASH(h, encrypted_static)
    c, k = KDF(2, c, x25519(alice_priv, sr_pub))
    encrypted_timestamp = aead_encrypt(k, 0, TAI64N(unix_seconds, 0), h)
    h = HASH(h, encrypted_timestamp)

    msg1 = struct.pack("<II", 1, initiator_index) + ei_pub + encrypted_static + encrypted_timestamp
    msg1 += MAC(HASH(LABEL_MAC1, sr_pub), msg1) + b"\x00" * 16
    assert len(msg1) == 148

    # Section 5.4.3: the responder creates message 2, continuing from the
    # same C and H, which it reaches by consuming message 1.
    (c,) = KDF(1, c, er_pub)
    h = HASH(h, er_pub)
    (c,) = KDF(1, c, x25519(er_priv, ei_pub))
    (c,) = KDF(1, c, x25519(er_priv, si_pub))
    c, tau, k = KDF(3, c, q)
    h = HASH(h, tau)
    encrypted_nothing = aead_encrypt(k, 0, b"", h)
    h = HASH(h, encrypted_nothing)

    msg2 = struct.pack("<III", 2, responder_index, initiator_index) + er_pub + encrypted_nothing
    msg2 += MAC(HASH(LABEL_MAC1, si_pub), msg2) + b"\x00" * 16
    assert len(msg2) == 92

    # Section 5.4.5: the transport keys.
    send_i, recv_i = KDF(2, c, b"")

    print("initiation:", msg1.hex())
    print("response:  ", msg2.hex())
    print("initiator to responder:", send_i.hex())
    print("responder to initiator:", recv_i.hex())


if __name__ == "__main__":
    main()
