#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Solver harness and cryptanalysis toolkit for the "sphinx" challenge.

The challenge (``challenge/sphinx.py``) ships an 8-byte (64-bit) keyed block
cipher.  Stripped of its hieroglyph identifiers it is the 16-round variant of
Merkle's *Khafre* (US patent US5003597, which ``metadata.yaml`` says the code
is "compatible with"); the differential break is the one in Biham & Shamir's
book *Differential Cryptanalysis of the Data Encryption Standard* -- the
"Biham's book" hinted at in the flavour text.

Cipher structure (verified byte-for-byte against the challenge, see
``self_test``).  With ``rounds=16`` and a single 64-bit key ``K=(a,b)``::

    P --(xor W0)--> octet(S0) --(xor W1)--> octet(S1) --(xor W2)--> C

where the three whitenings are rotations of the *same* key::

    W0 = (a,        b)
    W1 = (a >>> 1,  b >>> 1)
    W2 = (a >>> 2,  b >>> 2)

``octet`` is 8 keyless Feistel-like rounds; ``S0``/``S1`` are public,
key-independent S-boxes.  Every rotation amount is a multiple of 8, so the
whole primitive is byte-oriented, and each S-box output byte is a bijection of
its input byte.

The remote service is an encryption-only oracle: it prints
``flag_ct = E_K(flag_plaintext)`` (the flag is exactly one 8-byte block), then
echoes ``E_K(block)`` for every hex block we send.  It reveals the flag when we
send ``block == D_K(flag_ct)``.  So winning requires inverting the cipher
without the key, i.e. recovering ``K`` (equivalently ``W2``) by cryptanalysis.

This file provides:

  * ``load_cipher`` / ``reference_encrypt`` / ``reference_decrypt`` - a
    *verified* handle on the exact challenge primitive, obtained by exec'ing
    the challenge source up to (but not including) its interactive ``main``
    block.  Identifiers are discovered by introspection so the harness does not
    depend on fragile hieroglyph code points.
  * ``CleanCipher`` - a small ASCII reimplementation of the same cipher, used
    by the differential tooling.  ``self_test`` checks it against the real
    primitive on random keys/blocks.
  * ``Oracle`` - a thin client for the live service (or a local process).
  * Differential helpers built around the verified probability-1 truncated
    differential of a single octet, plus ``w2_filter`` (the key-recovery
    distinguisher) with statistical self-tests of its soundness/selectivity.
  * ``recover_w2`` / ``recover_key`` - the key-recovery entry points and an
    honest description of the remaining heavy search.

Usage::

    python3 solve.py --self-test               # verify model + differential
    python3 solve.py --host HOST --port PORT --attack
"""

import argparse
import inspect
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHALLENGE = os.path.join(HERE, "challenge", "sphinx.py")

# ---------------------------------------------------------------------------
# 1. Load the *exact* challenge primitive (no re-implementation risk).
# ---------------------------------------------------------------------------
#
# The challenge module uses Egyptian-hieroglyph identifiers and ends with an
# interactive ``main`` block (banner + ``input()`` loop).  We exec only the
# part before that block and then locate the cipher class and its encrypt /
# decrypt methods by *introspection* rather than by hard-coding code points.

_BANNER_MARKER = "\U00013086\U000133b3\U0001320d\U00013191\U00013087="  # 𓊆𓇳𓈍𓆑𓊇=
_cache = None


def _load():
    """Exec the challenge core and discover its public primitive.

    Returns ``(cipher_cls, encrypt_name, decrypt_name, sboxes)``.
    """
    global _cache
    if _cache is not None:
        return _cache

    with open(CHALLENGE, encoding="utf-8") as fh:
        src = fh.read()
    idx = src.find(_BANNER_MARKER)
    if idx == -1:
        # Fall back to the first top-level banner print.
        idx = src.index("print(")
    namespace = {}
    exec(compile(src[:idx], "sphinx_core", "exec"), namespace)  # noqa: S102

    # The cipher class is the one that constructs from (key_bytes, rounds).
    cipher_cls = None
    for value in namespace.values():
        if inspect.isclass(value):
            try:
                value(b"\x00" * 8, 16)
            except Exception:  # noqa: BLE001 - probing constructors
                continue
            cipher_cls = value
            break
    if cipher_cls is None:
        raise RuntimeError("could not locate the cipher class in sphinx.py")

    # Among the block methods, encrypt is the one taking extra parameters
    # (is_template / debug flags); decrypt takes only the block.
    block_methods = [
        name
        for name, fn in cipher_cls.__dict__.items()
        if callable(fn) and not name.startswith("__")
    ]
    encrypt_name = max(
        block_methods,
        key=lambda n: len(inspect.signature(cipher_cls.__dict__[n]).parameters),
    )
    inst = cipher_cls(b"ABCDEFGH", 16)
    decrypt_name = None
    ct = getattr(inst, encrypt_name)(b"ABCDEFGH")
    for name in block_methods:
        if name == encrypt_name:
            continue
        try:
            if getattr(inst, name)(ct) == b"ABCDEFGH":
                decrypt_name = name
                break
        except Exception:  # noqa: BLE001
            continue
    if decrypt_name is None:
        raise RuntimeError("could not identify the decrypt method")

    # The S-boxes are stored on the instance as a list of >=2 lists of 256 ints.
    sboxes = None
    for value in vars(inst).values():
        if (
            isinstance(value, list)
            and len(value) >= 2
            and all(isinstance(x, list) and len(x) == 256 for x in value)
        ):
            sboxes = value
            break
    if sboxes is None:
        raise RuntimeError("could not locate the S-boxes")

    _cache = (cipher_cls, encrypt_name, decrypt_name, sboxes)
    return _cache


def load_cipher():
    """Return ``(make_cipher, get_sboxes)`` bound to the challenge primitive."""
    cipher_cls, _, _, sboxes = _load()

    def make_cipher(key: bytes, rounds: int = 16):
        return cipher_cls(key, rounds)

    return make_cipher, (lambda: sboxes)


def reference_encrypt(key: bytes, block: bytes, rounds: int = 16) -> bytes:
    cipher_cls, enc, _, _ = _load()
    return getattr(cipher_cls(key, rounds), enc)(block)


def reference_decrypt(key: bytes, block: bytes, rounds: int = 16) -> bytes:
    cipher_cls, _, dec, _ = _load()
    return getattr(cipher_cls(key, rounds), dec)(block)


# ---------------------------------------------------------------------------
# 2. Clean ASCII reimplementation (for cryptanalysis tooling).
# ---------------------------------------------------------------------------

ROT = [16, 16, 8, 8, 16, 16, 24, 24]
MASK = 0xFFFFFFFF


def rotl(x, n):
    return ((x << n) & MASK) | (x >> (32 - n))


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def octet(L, R, S):
    """One 8-round keyless Khafre octet (forward)."""
    for r in range(8):
        R ^= S[L & 0xFF]
        L = rotr(L, ROT[r])
        L, R = R, L
    return L, R


def octet_inv(L, R, S):
    """Inverse of :func:`octet`."""
    for r in reversed(range(8)):
        L, R = R, L
        L = rotl(L, ROT[r])
        R ^= S[L & 0xFF]
    return L, R


class CleanCipher:
    """Readable reimplementation; equivalent to the challenge for rounds=16."""

    def __init__(self, sboxes):
        self.S = sboxes  # list of S-boxes (lists of 256 32-bit ints)

    def enc_block(self, block: bytes, key: bytes) -> bytes:
        a, b = struct.unpack(">II", key)
        L, R = struct.unpack(">II", block)
        L ^= a
        R ^= b
        L, R = octet(L, R, self.S[0])
        L ^= rotr(a, 1)
        R ^= rotr(b, 1)
        L, R = octet(L, R, self.S[1])
        L ^= rotr(a, 2)
        R ^= rotr(b, 2)
        return struct.pack(">II", L & MASK, R & MASK)

    def dec_block(self, block: bytes, key: bytes) -> bytes:
        a, b = struct.unpack(">II", key)
        L, R = struct.unpack(">II", block)
        L ^= rotr(a, 2)
        R ^= rotr(b, 2)
        L, R = octet_inv(L, R, self.S[1])
        L ^= rotr(a, 1)
        R ^= rotr(b, 1)
        L, R = octet_inv(L, R, self.S[0])
        L ^= a
        R ^= b
        return struct.pack(">II", L & MASK, R & MASK)


# ---------------------------------------------------------------------------
# 3. Oracle client.
# ---------------------------------------------------------------------------


class Oracle:
    """Client for the encryption-only service.

    Protocol (see the ``main`` block of ``challenge/sphinx.py``):
        - prints a banner, then  ``I say you:  <HEX(flag_ct)>``
        - then repeatedly prompts ``You say I: ``, reads a hex block, and
          prints ``I say you:  <HEX(E_K(block))>``.  When the submitted block
          equals ``D_K(flag_ct)`` it prints the flag and exits.
    """

    def __init__(self, host=None, port=None):
        from pwn import remote  # imported lazily; only needed for live attack

        self.io = remote(host, port)
        self.flag_ct = self._read_flag_ct()

    def _read_flag_ct(self) -> bytes:
        import base64

        self.io.recvuntil(b"I say you: ")
        line = self.io.recvline().strip()
        return base64.b16decode(line)

    def encrypt(self, block: bytes) -> bytes:
        import base64

        self.io.recvuntil(b"You say I: ")
        self.io.sendline(base64.b16encode(block))
        self.io.recvuntil(b"I say you: ")
        return base64.b16decode(self.io.recvline().strip())

    def submit(self, block: bytes) -> str:
        """Send a candidate preimage of ``flag_ct`` and return the reply."""
        import base64

        self.io.recvuntil(b"You say I: ")
        self.io.sendline(base64.b16encode(block))
        return self.io.recvall(timeout=5).decode(errors="replace")


class LocalOracle:
    """In-process oracle backed by the real primitive, for validation/demos."""

    def __init__(self, key: bytes = None):
        self.key = key or os.urandom(8)
        self.flag_ct = reference_encrypt(self.key, os.urandom(8))

    def encrypt(self, block: bytes) -> bytes:
        return reference_encrypt(self.key, block)


# ---------------------------------------------------------------------------
# 4. Differential cryptanalysis tooling.
# ---------------------------------------------------------------------------
#
# Verified properties of this cipher (all checked by ``self_test``):
#
#   * Probability-1 truncated differential over ONE octet: input difference
#     (dL=0, dR=delta) with `delta` non-zero only in byte 1 (bits 8..15)
#     propagates passively through rounds 0..6 and activates only round 7, so
#     the octet output difference has its R-word EXACTLY equal to `delta`.
#     (Bytes only ever feed the S-box through L&0xff, and the byte-aligned
#     rotations carry the active byte away from position 0 until round 7.)
#
#   * Consequently, for the full cipher the value M = octet0(P ^ W0) (the input
#     to the second octet, before ^W1) satisfies  dM_R == delta  with prob 1.
#     dM_L is the round-7 S-box output difference and is effectively uniform,
#     so it fully diffuses through octet1 and the 16-round ciphertext
#     difference is not clean -- which is why this is a genuine (heavy)
#     differential attack rather than a 1-round distinguisher.
#
# Key-recovery distinguisher (``w2_filter``).  Because W1 cancels in a
# difference and octet1 is keyless, for the correct last whitening
# W2 = (a>>>2, b>>>2):
#
#     octet_inv(C  ^ W2, S1)_R  XOR  octet_inv(C* ^ W2, S1)_R  ==  delta
#
# holds for every chosen-plaintext pair with input difference (0, delta).
# This is a 32-bit condition on the 64-bit W2 and is empirically ~2^-32 per
# pair for wrong W2 (see ``self_test``), so ~2-3 pairs pin W2 uniquely.

# A delta whose only non-zero byte is byte 1 (bits 8..15).
DELTA = 0x0000_AB00


def make_truncated_pairs(oracle, delta: int, count: int):
    """Query `count` chosen-plaintext pairs with input difference (0, delta)."""
    pairs = []
    for _ in range(count):
        pl = int.from_bytes(os.urandom(4), "big")
        pr = int.from_bytes(os.urandom(4), "big")
        c1 = oracle.encrypt(struct.pack(">II", pl, pr))
        c2 = oracle.encrypt(struct.pack(">II", pl, pr ^ delta))
        pairs.append((c1, c2))
    return pairs


def w2_filter(sboxes, pairs, delta: int, w2_l: int, w2_r: int) -> bool:
    """Return True iff candidate W2=(w2_l,w2_r) is consistent with all pairs."""
    S1 = sboxes[1]
    for c1, c2 in pairs:
        l1, r1 = struct.unpack(">II", c1)
        l2, r2 = struct.unpack(">II", c2)
        y1 = octet_inv(l1 ^ w2_l, r1 ^ w2_r, S1)
        y2 = octet_inv(l2 ^ w2_l, r2 ^ w2_r, S1)
        if (y1[1] ^ y2[1]) != delta:
            return False
    return True


def key_from_w2(w2_l: int, w2_r: int) -> bytes:
    """Recover the 64-bit key K=(a,b) from W2=(a>>>2, b>>>2)."""
    return struct.pack(">II", rotl(w2_l, 2), rotl(w2_r, 2))


# ---------------------------------------------------------------------------
# 5. Key recovery.
# ---------------------------------------------------------------------------


def recover_w2(oracle, sboxes, pairs=None, search=None):
    """Recover the last whitening ``W2 = (a>>>2, b>>>2)``.

    ``w2_filter`` is a sound, ~32-bit-per-pair distinguisher for W2, but the
    delta condition only becomes checkable once *all eight* key bytes are
    fixed (the byte-oriented key bytes are introduced one per inverse-octet
    round, yet the constraint lives on the final R-word -- so there is no early
    pruning).  Enumerating W2 with the filter is therefore the full Khafre
    differential search (~2^64 naive; the official Biham-Shamir attack reaches
    it with ~2^15 chosen plaintexts and substantial offline compute, run on a
    GPU/Colab in the released solution).  That heavy enumeration is the only
    missing piece and is impractical to run inside this harness.

    ``search`` may be supplied as a callable ``search(filter_fn) -> (w2_l,
    w2_r)`` that performs (or accelerates) the enumeration; ``filter_fn`` is a
    bound :func:`w2_filter` over the collected pairs.  When omitted this raises
    so callers do not silently believe the key was recovered.
    """
    if pairs is None:
        pairs = make_truncated_pairs(oracle, DELTA, 4)

    def filter_fn(w2_l, w2_r):
        return w2_filter(sboxes, pairs, DELTA, w2_l, w2_r)

    if search is None:
        raise NotImplementedError(
            "recover_w2 needs a W2 enumeration strategy: pass search=... "
            "(the Biham-Shamir differential search over the 64-bit W2 using "
            "filter_fn). The rest of the pipeline -- pair collection, the "
            "verified filter, key_from_w2, decrypt and submit -- is complete "
            "and validated by --self-test."
        )
    return search(filter_fn)


def recover_key(oracle, sboxes, search=None) -> bytes:
    """Recover the key and return ``D_K(flag_ct)`` (the preimage to submit)."""
    pairs = make_truncated_pairs(oracle, DELTA, 4)
    w2_l, w2_r = recover_w2(oracle, sboxes, pairs=pairs, search=search)
    key = key_from_w2(w2_l, w2_r)
    return CleanCipher(sboxes).dec_block(oracle.flag_ct, key)


# ---------------------------------------------------------------------------
# 6. Self-tests (verify the model and the cryptanalytic claims).
# ---------------------------------------------------------------------------


def self_test(trials: int = 200) -> None:
    make_cipher, sbox_fn = load_cipher()
    sboxes = sbox_fn()
    clean = CleanCipher(sboxes)

    # (a) CleanCipher matches the real primitive (encrypt and decrypt).
    for _ in range(trials):
        key = os.urandom(8)
        block = os.urandom(8)
        ref_ct = reference_encrypt(key, block)
        assert clean.enc_block(block, key) == ref_ct
        assert clean.dec_block(ref_ct, key) == block
        assert reference_decrypt(key, ref_ct) == block
    print(f"[+] model: CleanCipher matches challenge on {trials} cases")

    # (b) Probability-1 octet differential: delta in byte 1 -> output R == delta.
    S0 = sboxes[0]
    for _ in range(5000):
        L = int.from_bytes(os.urandom(4), "big")
        R = int.from_bytes(os.urandom(4), "big")
        d = int.from_bytes(os.urandom(4), "big") & 0x0000FF00
        if d == 0:
            continue
        o1 = octet(L, R, S0)
        o2 = octet(L, R ^ d, S0)
        assert (o1[1] ^ o2[1]) == d, "prob-1 differential violated"
    print("[+] differential: octet output R-word == delta (prob 1) holds")

    # (c) Filter soundness + selectivity against the real primitive.
    key = os.urandom(8)
    a, b = struct.unpack(">II", key)
    true_w2 = (rotr(a, 2), rotr(b, 2))
    local = LocalOracle(key)
    pairs = make_truncated_pairs(local, DELTA, 4)
    assert w2_filter(sboxes, pairs, DELTA, *true_w2), "true W2 rejected!"
    assert key_from_w2(*true_w2) == key, "key_from_w2 inverse wrong"
    import random

    false_hits = 0
    samples = 200_000
    for _ in range(samples):
        if w2_filter(
            sboxes, pairs[:1], DELTA, random.getrandbits(32), random.getrandbits(32)
        ):
            false_hits += 1
    print(
        f"[+] filter: true W2 accepted; {false_hits}/{samples} wrong W2 pass a "
        f"single pair (expected ~{samples / 2**32:.4g}, i.e. ~2^-32)"
    )

    # (d) End-to-end pipeline given W2 (mirrors the live attack tail).
    preimage = CleanCipher(sboxes).dec_block(local.flag_ct, key_from_w2(*true_w2))
    assert reference_encrypt(key, preimage) == local.flag_ct
    print("[+] pipeline: key_from_w2 -> decrypt -> re-encrypt == flag_ct")
    print("[+] self-test passed")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--self-test", action="store_true", help="verify the model")
    ap.add_argument("--host", default="sphinx.2025.ctfcompetition.com")
    ap.add_argument("--port", type=int, default=1337)
    ap.add_argument("--attack", action="store_true", help="run the live attack")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if args.attack:
        _, sbox_fn = load_cipher()
        sboxes = sbox_fn()
        oracle = Oracle(args.host, args.port)
        print(f"[+] flag ciphertext: {oracle.flag_ct.hex()}")
        preimage = recover_key(oracle, sboxes)
        print(oracle.submit(preimage))
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
