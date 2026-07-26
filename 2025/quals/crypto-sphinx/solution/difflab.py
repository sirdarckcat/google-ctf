"""
difflab -- a hands-on laboratory for learning differential cryptanalysis,
using the GoogleCTF 2025 "sphinx" cipher (Ralph Merkle's Khafre, 16 rounds).

This module is deliberately small and readable. Nothing here is optimised;
it exists so you can poke at differences and watch what happens.

Quick start:

    >>> import difflab as L
    >>> k = L.key_from_hex("cafebabecafebabe")
    >>> L.enc(bytes(8), k).hex()
    ...
    >>> p1, p2 = L.pair(bytes(8), byte_pos=6, delta=0x01)
    >>> L.active_rounds(p1, p2, k)
    [7, 8, 9, 10, 11, 12, 13, 14, 15]

Everything is byte-oriented; "state byte i" means byte i of the 8-byte block,
with bytes 0..3 in the left word (`lo`) and bytes 4..7 in the right word (`hi`).
"""

import os
import re
import struct
from collections import Counter

MASK = 0xFFFFFFFF

# The in-round rotation schedule. NOTE: the challenge source *looks* like it
# rotates left (homoglyph trap) but actually rotates RIGHT by these amounts.
ROT = [16, 16, 8, 8, 16, 16, 24, 24]

ROUNDS = 16


def rol(x, r):
    return (((x << r) & MASK) | (x >> (32 - r))) if r else x & MASK


def ror(x, r):
    return (((x >> r) | (x << (32 - r))) & MASK) if r else x & MASK


# --------------------------------------------------------------------------
# The two S-boxes. They are FIXED and PUBLIC -- they do not depend on the key.
# We read them from sboxes.h, which ships in this directory.
# --------------------------------------------------------------------------
def _load_sboxes():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "sboxes.h")) as f:
        text = f.read()
    boxes = []
    for i in (0, 1):
        m = re.search(r"SB%d\[256\]\s*=\s*\{(.*?)\}" % i, text, re.S)
        if not m:
            raise RuntimeError("could not find SB%d in sboxes.h" % i)
        vals = [int(v.strip().rstrip("u"), 16) for v in m.group(1).split(",")]
        if len(vals) != 256:
            raise RuntimeError("SB%d has %d entries, expected 256" % (i, len(vals)))
        boxes.append(vals)
    return boxes


SB0, SB1 = _load_sboxes()
SBOXES = [SB0, SB1]


# --------------------------------------------------------------------------
# The cipher.  C = W2 ^ R1( W1 ^ R0( P ^ W0 ) ),  Wj = (ror(k0,j), ror(k1,j))
# Each round:  hi ^= SB[lo & 0xff] ; lo = ror(lo, ROT[r]) ; swap(lo, hi)
# --------------------------------------------------------------------------
def key_from_hex(h):
    """8-byte key from a 16-char hex string."""
    b = bytes.fromhex(h)
    if len(b) != 8:
        raise ValueError("key must be 8 bytes")
    return b


def random_key():
    return os.urandom(8)


def random_block():
    return os.urandom(8)


def _words(b):
    return list(struct.unpack(">II", b))


def _bytes(lo, hi):
    return struct.pack(">II", lo & MASK, hi & MASK)


def enc(block, key):
    """Encrypt one 8-byte block."""
    lo, hi = _words(block)
    k0, k1 = _words(key)
    lo ^= k0
    hi ^= k1
    for r in range(8):
        hi ^= SB0[lo & 0xFF]
        lo = ror(lo, ROT[r])
        lo, hi = hi, lo
    lo ^= ror(k0, 1)
    hi ^= ror(k1, 1)
    for r in range(8):
        hi ^= SB1[lo & 0xFF]
        lo = ror(lo, ROT[r])
        lo, hi = hi, lo
    return _bytes(lo ^ ror(k0, 2), hi ^ ror(k1, 2))


def dec(block, key):
    """Decrypt one 8-byte block."""
    lo, hi = _words(block)
    k0, k1 = _words(key)
    lo ^= ror(k0, 2)
    hi ^= ror(k1, 2)
    for r in reversed(range(8)):
        lo, hi = hi, lo
        lo = rol(lo, ROT[r])
        hi ^= SB1[lo & 0xFF]
    lo ^= ror(k0, 1)
    hi ^= ror(k1, 1)
    for r in reversed(range(8)):
        lo, hi = hi, lo
        lo = rol(lo, ROT[r])
        hi ^= SB0[lo & 0xFF]
    return _bytes(lo ^ k0, hi ^ k1)


# --------------------------------------------------------------------------
# Introspection: watch what happens INSIDE the cipher.
# --------------------------------------------------------------------------
def trace(block, key):
    """
    Encrypt, recording what each round did.

    Returns a list of 16 dicts, one per round, each with:
        round    : round index 0..15
        octet    : 0 for rounds 0-7 (uses SB0), 1 for rounds 8-15 (uses SB1)
        sbox_in  : the single byte that fed the S-box this round
        lo, hi   : the two state words at the START of the round
    """
    lo, hi = _words(block)
    k0, k1 = _words(key)
    lo ^= k0
    hi ^= k1
    out = []
    for octet in (0, 1):
        if octet == 1:
            lo ^= ror(k0, 1)
            hi ^= ror(k1, 1)
        sb = SBOXES[octet]
        for r in range(8):
            out.append({
                "round": octet * 8 + r,
                "octet": octet,
                "sbox_in": lo & 0xFF,
                "lo": lo,
                "hi": hi,
            })
            hi ^= sb[lo & 0xFF]
            lo = ror(lo, ROT[r])
            lo, hi = hi, lo
    return out


def state_byte(lo, hi, i):
    """Byte i of the 8-byte state (0..3 in lo, 4..7 in hi)."""
    w = lo if i < 4 else hi
    return (w >> (8 * (3 - (i % 4)))) & 0xFF


# --------------------------------------------------------------------------
# Differential tools
# --------------------------------------------------------------------------
def pair(block, byte_pos, delta):
    """
    Build a plaintext pair differing by `delta` in plaintext byte `byte_pos`.
    Returns (p1, p2).
    """
    if not 0 <= byte_pos < 8:
        raise ValueError("byte_pos must be 0..7")
    b = bytearray(block)
    b[byte_pos] ^= delta
    return bytes(block), bytes(b)


def diff_trace(p1, p2, key):
    """
    Trace BOTH encryptions and report, per round:
        round      : round index
        sbox_in1/2 : the S-box input byte in each encryption
        active     : True if those bytes differ (the S-box sees a difference)
        in_diff    : sbox_in1 ^ sbox_in2   (0 exactly when inactive)
        state_diff : the 8-byte state difference at the start of the round
    """
    t1, t2 = trace(p1, key), trace(p2, key)
    out = []
    for a, b in zip(t1, t2):
        dlo = a["lo"] ^ b["lo"]
        dhi = a["hi"] ^ b["hi"]
        out.append({
            "round": a["round"],
            "sbox_in1": a["sbox_in"],
            "sbox_in2": b["sbox_in"],
            "in_diff": a["sbox_in"] ^ b["sbox_in"],
            "active": a["sbox_in"] != b["sbox_in"],
            "state_diff": _bytes(dlo, dhi),
        })
    return out


def active_rounds(p1, p2, key):
    """Which rounds have an ACTIVE S-box for this pair."""
    return [d["round"] for d in diff_trace(p1, p2, key) if d["active"]]


def inactive_rounds(p1, p2, key):
    """Which rounds have an INACTIVE S-box (the difference passes untouched)."""
    return [d["round"] for d in diff_trace(p1, p2, key) if not d["active"]]


def first_active_round(p1, p2, key):
    """The first round whose S-box sees a difference (None if never)."""
    a = active_rounds(p1, p2, key)
    return a[0] if a else None


def show_diff_trace(p1, p2, key):
    """Human-readable difference trail. Great for a first look."""
    print("round  octet  S-box   in_diff   state difference")
    for d in diff_trace(p1, p2, key):
        print("  %2d      %d   %-8s  %02x       %s" % (
            d["round"], 0 if d["round"] < 8 else 1,
            "ACTIVE" if d["active"] else "inactive",
            d["in_diff"], d["state_diff"].hex()))


# --- S-box difference behaviour -------------------------------------------
def sbox_out_diff(delta, x, sb=SB1):
    """Output difference of the S-box for input pair (x, x^delta)."""
    return sb[x] ^ sb[x ^ delta]


def ddt_row(delta, sb=SB1):
    """
    One row of the difference distribution table: how often each output
    difference occurs, over all 256 input values x, for input difference
    `delta`.  Returns a Counter {output_difference: count}.
    """
    return Counter(sbox_out_diff(delta, x, sb) for x in range(256))


def zero_output_diff_bytes(sb=SB1):
    """
    Count how many (delta != 0, x) pairs make ANY byte of the S-box output
    difference equal to zero.  For this cipher's S-boxes the answer is 0 --
    that is the structural fact that shapes every trail.
    """
    hits = 0
    for delta in range(1, 256):
        for x in range(256):
            d = sbox_out_diff(delta, x, sb)
            if any(((d >> (8 * i)) & 0xFF) == 0 for i in range(4)):
                hits += 1
    return hits


# --- measurement ----------------------------------------------------------
def measure_inactive(byte_pos=6, trials=4000, key=None, seed_blocks=None):
    """
    For a one-byte input difference at plaintext byte `byte_pos`, estimate
    P(S-box inactive) for every round.

    Returns {round: (count_inactive, trials)}.
    `trials` counts (block, delta) pairs; pure Python, so keep it modest.
    """
    key = key or random_key()
    counts = {r: 0 for r in range(ROUNDS)}
    n = 0
    for i in range(trials):
        blk = seed_blocks[i] if seed_blocks else random_block()
        delta = (os.urandom(1)[0] or 1)
        p1, p2 = pair(blk, byte_pos, delta)
        for d in diff_trace(p1, p2, key):
            if not d["active"]:
                counts[d["round"]] += 1
        n += 1
    return {r: (counts[r], n) for r in range(ROUNDS)}


def measure_joint(rounds=(12, 14), byte_pos=6, trials=20000, key=None):
    """
    Estimate P(all the given rounds are inactive simultaneously) -- i.e. the
    probability of the characteristic the intended attack relies on.

    Returns (hits, trials).
    """
    key = key or random_key()
    hits = 0
    for _ in range(trials):
        p1, p2 = pair(random_block(), byte_pos, os.urandom(1)[0] or 1)
        t = diff_trace(p1, p2, key)
        if all(not t[r]["active"] for r in rounds):
            hits += 1
    return hits, trials


def measure_joint_fast(rounds=(12, 14), byte_pos=6, trials=1_000_000, key=None):
    """
    Same as measure_joint but vectorised with numpy, so you can actually reach
    the ~1/60000 event.  Requires numpy.  Returns (hits, trials).
    """
    import numpy as np

    key = key or random_key()
    k0, k1 = _words(key)
    SBv = [np.array(sb, dtype=np.uint32) for sb in SBOXES]

    def rorv(x, r):
        return ((x >> np.uint32(r)) | (x << np.uint32(32 - r))).astype(np.uint32)

    lo = np.frombuffer(os.urandom(4 * trials), dtype=">u4").astype(np.uint32)
    hi = np.frombuffer(os.urandom(4 * trials), dtype=">u4").astype(np.uint32)
    d = np.frombuffer(os.urandom(trials), dtype=np.uint8).astype(np.uint32)
    d[d == 0] = 1
    # plaintext byte 6 == byte 2 of `hi` == bits 8..15
    shift = np.uint32(8 * (3 - (byte_pos % 4)))
    if byte_pos < 4:
        lo2, hi2 = (lo ^ (d << shift)).astype(np.uint32), hi
    else:
        lo2, hi2 = lo, (hi ^ (d << shift)).astype(np.uint32)

    def run(a, b):
        ins = []
        a = a ^ np.uint32(k0)
        b = b ^ np.uint32(k1)
        for octet in (0, 1):
            if octet == 1:
                a = a ^ np.uint32(ror(k0, 1))
                b = b ^ np.uint32(ror(k1, 1))
            for r in range(8):
                ins.append(a & np.uint32(0xFF))
                b = b ^ SBv[octet][a & np.uint32(0xFF)]
                a = rorv(a, ROT[r])
                a, b = b, a
        return ins

    i1, i2 = run(lo, hi), run(lo2, hi2)
    ok = np.ones(trials, dtype=bool)
    for r in rounds:
        ok &= (i1[r] == i2[r])
    return int(np.count_nonzero(ok)), trials


# --- integral (saturation) tools, for the bridge at the end --------------
def saturate(block, byte_positions):
    """
    Build the integral SET: every combination of values in the given state
    byte positions, everything else fixed.  len == 256**len(byte_positions).
    """
    sets = [bytes(block)]
    for pos in byte_positions:
        nxt = []
        for b in sets:
            for v in range(256):
                bb = bytearray(b)
                bb[pos] = v
                nxt.append(bytes(bb))
        sets = nxt
    return sets


def balanced_bytes_after_round(blocks, key, upto_round):
    """
    Encrypt every block, stop after `upto_round` rounds, and report which of
    the 8 state bytes XOR-sum to zero across the whole set ("balanced").
    """
    acc_lo = acc_hi = 0
    for b in blocks:
        t = trace(b, key)
        if upto_round + 1 < len(t):
            st = t[upto_round + 1]
            lo, hi = st["lo"], st["hi"]
        else:  # after the final round: recompute the tail
            lo, hi = _words(enc(b, key))
            k0, k1 = _words(key)
            lo ^= ror(k0, 2)
            hi ^= ror(k1, 2)
        acc_lo ^= lo
        acc_hi ^= hi
    return [i for i in range(8) if state_byte(acc_lo, acc_hi, i) == 0]


def self_test():
    """Sanity-check the cipher and the headline structural facts."""
    k = key_from_hex("cafebabecafebabe")
    for _ in range(200):
        b = random_block()
        assert dec(enc(b, k), k) == b, "enc/dec mismatch"
    assert zero_output_diff_bytes(SB1) == 0, "expected no zero output-diff byte"
    p1, p2 = pair(bytes(8), 6, 0x01)
    assert first_active_round(p1, p2, k) == 7, "byte-6 free ride broken"
    print("difflab self-test OK  (enc/dec, S-box property, byte-6 free ride)")


if __name__ == "__main__":
    self_test()
