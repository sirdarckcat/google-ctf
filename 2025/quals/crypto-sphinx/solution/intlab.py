"""
intlab -- a hands-on laboratory for learning INTEGRAL (Square) cryptanalysis,
using the GoogleCTF 2025 "sphinx" cipher (Merkle's Khafre, 16 rounds).

Companion to difflab.py (differential cryptanalysis). Where difflab studies
PAIRS and their differences, intlab studies structured SETS and their sums.

Quick start:

    >>> import intlab as I
    >>> I.show_prediction([6])          # symbolic A/C/B/? propagation
    >>> I.show_measured([6])            # what actually happens
    >>> I.self_test()

The four labels (standard integral notation):
    A  "active" / saturated : the byte takes all 256 values exactly once
    C  "constant"           : the byte is the same in every text
    B  "balanced"           : the bytes XOR-sum to zero over the set
    ?  "unknown"            : no guarantee
Note A implies B, and C implies B only for even-sized sets (we always have
even-sized sets, but we keep C separate because it is much stronger).
"""

import os
import struct
from collections import Counter

import difflab as D

MASK = D.MASK
ROT = D.ROT
SB0, SB1 = D.SB0, D.SB1
SBOXES = D.SBOXES
ror, rol = D.ror, D.rol
enc, dec = D.enc, D.dec
random_key, random_block, key_from_hex = D.random_key, D.random_block, D.key_from_hex
saturate = D.saturate
state_byte = D.state_byte
_words, _bytes = D._words, D._bytes


# ==========================================================================
# 1. SYMBOLIC PROPAGATION -- the heart of integral cryptanalysis
# ==========================================================================
# Every byte of the state carries one of the four labels. We push the labels
# through the cipher using rules that are *guaranteed* (probability 1).

def xor_labels(a, b):
    """
    Label of (x ^ y) given the labels of x and y.

    Balance is LINEAR: if both operands sum to zero over the set, so does
    their XOR.  That single fact drives almost everything.
    """
    if a == "?" or b == "?":
        return "?"
    if a == "C" and b == "C":
        return "C"
    if a == "C":                      # constant ^ (A or B)
        return b                      #   saturation and balance both survive
    if b == "C":
        return a
    # both non-constant: A^A, A^B, B^B  -> still balanced, but no longer
    # necessarily saturated
    return "B"


def sbox_out_labels(in_label):
    """
    Labels of the 4 output bytes of SB[x] given the label of the input byte x.

    - C  : same lookup every time            -> all 4 outputs constant
    - A  : x hits all 256 values once, and EACH output byte of this S-box is a
           permutation of x, so each output byte also hits all 256 values once
                                             -> all 4 outputs saturated
    - B  : balanced is NOT enough. The S-box is nonlinear, so knowing only that
           the inputs sum to zero tells you nothing about the outputs -> ?
    - ?  : ?
    """
    if in_label == "C":
        return ["C"] * 4
    if in_label == "A":
        return ["A"] * 4
    return ["?"] * 4                  # B or ? both degrade to unknown


def predict(sat_positions, rounds=16):
    """
    Propagate labels through the cipher for an integral set that saturates the
    given state byte positions (everything else constant).

    Returns a list `states` where states[r] is the 8 labels BEFORE round r,
    plus states[rounds] = the labels after the last round.

    Note this is a *guarantee*: a byte predicted B is certainly balanced. A byte
    predicted ? may still be balanced by accident for a particular key.
    """
    labels = ["C"] * 8
    for p in sat_positions:
        labels[p] = "A"

    states = [labels[:]]
    for r in range(rounds):
        lo = labels[0:4]
        hi = labels[4:8]
        # hi ^= SB[lo & 0xff]   -- the S-box input is byte 3 of lo
        outs = sbox_out_labels(lo[3])
        hi = [xor_labels(hi[j], outs[j]) for j in range(4)]
        # lo = ror(lo, ROT[r]) -- ROT is always a multiple of 8, so this is a
        # pure BYTE rotation and labels simply move.  (If it were not
        # byte-aligned, byte-level labels would not survive at all.)
        sh = ROT[r % 8] // 8      # ROT is indexed within the octet
        lo = [lo[(j - sh) % 4] for j in range(4)]
        # swap halves
        labels = hi + lo
        states.append(labels[:])
    return states


def show_prediction(sat_positions, rounds=16):
    """Print the guaranteed label evolution. This is the picture to internalise."""
    states = predict(sat_positions, rounds)
    print("integral set: saturate state bytes %s  ->  %d chosen plaintexts"
          % (list(sat_positions), 256 ** len(sat_positions)))
    print()
    print("             byte: 0 1 2 3 4 5 6 7")
    print("  before round  0: %s" % " ".join(states[0]))
    for r in range(rounds):
        bal = [i for i, L in enumerate(states[r + 1]) if L in ("A", "B", "C")]
        print("   after round %2d: %s    guaranteed balanced: %s"
              % (r, " ".join(states[r + 1]), bal if bal else "-"))


def guaranteed_balanced(sat_positions, after_round, rounds=16):
    """Which byte positions are *provably* balanced after the given round."""
    st = predict(sat_positions, rounds)[after_round + 1]
    return [i for i, L in enumerate(st) if L in ("A", "B", "C")]


def guaranteed_balanced_union(sat_positions, after_round, rounds=16):
    """
    A BETTER (still sound) guarantee for higher-order sets.

    A set saturating {a, b} is a union of 256 sets that saturate {a} alone (one
    for each fixed value of b), and also a union of 256 sets saturating {b}
    alone.  If a byte is balanced in every slice, it is balanced in the union
    (a XOR of zeros is zero).  So we may take the UNION of the single-byte
    guarantees -- which is strictly better than running `predict` on the whole
    set, because the first-order label calculus cannot express
    "balanced for each fixed value of the other active byte".

    Still only a lower bound: real higher-order integrals go deeper again
    (see the tutorial -- the true reason is algebraic degree).
    """
    out = set(guaranteed_balanced(sat_positions, after_round, rounds))
    for p in sat_positions:
        out |= set(guaranteed_balanced([p], after_round, rounds))
    return sorted(out)


# ==========================================================================
# 2. EMPIRICAL CHECK -- does reality match the prediction?
# ==========================================================================
def measure(sat_positions, key=None, base=None, rounds=16):
    """
    Actually build the set, encrypt, and label every byte at every round from
    observation:  A if saturated, C if constant, B if XOR-sum is 0, else '?'.

    Returns a list: measured[r] = 8 observed labels after round r
    (measured[-1] is after the final round).
    """
    key = key or random_key()
    base = base or random_block()
    blocks = saturate(base, list(sat_positions))
    n = len(blocks)

    # collect the per-round state of every text
    cols = [[[] for _ in range(8)] for _ in range(rounds + 1)]
    for b in blocks:
        t = D.trace(b, key)
        for r in range(rounds):
            lo, hi = t[r]["lo"], t[r]["hi"]
            for i in range(8):
                cols[r][i].append(state_byte(lo, hi, i))
        # after the final round: strip the output whitening back off
        lo, hi = _words(enc(b, key))
        k0, k1 = _words(key)
        lo ^= ror(k0, 2)
        hi ^= ror(k1, 2)
        for i in range(8):
            cols[rounds][i].append(state_byte(lo, hi, i))

    out = []
    for r in range(rounds + 1):
        row = []
        for i in range(8):
            v = cols[r][i]
            x = 0
            for y in v:
                x ^= y
            if len(set(v)) == 1:
                row.append("C")
            elif len(set(v)) == 256 and n % 256 == 0 and \
                    all(c == n // 256 for c in Counter(v).values()):
                row.append("A")
            elif x == 0:
                row.append("B")
            else:
                row.append("?")
        out.append(row)
    return out


def show_measured(sat_positions, key=None, base=None, rounds=16):
    """Print observed labels alongside the prediction, so you can compare."""
    pred = predict(sat_positions, rounds)
    meas = measure(sat_positions, key, base, rounds)
    print("saturate %s (%d texts)   predicted vs MEASURED"
          % (list(sat_positions), 256 ** len(sat_positions)))
    print("                  bytes 0..7")
    for r in range(rounds):
        p = " ".join(pred[r + 1])
        m = " ".join(meas[r + 1])
        flag = "" if p == m else "   <- differ"
        print("  after round %2d:  pred %s | meas %s%s" % (r, p, m, flag))


# ==========================================================================
# 3. REDUCED-ROUND CIPHER -- so key recovery is runnable in pure Python
# ==========================================================================
def enc_reduced(block, key, r1_rounds):
    """
    Same cipher, but the SECOND octet is shortened to `r1_rounds` rounds:
        C = W2 ^ R1_short( W1 ^ R0( P ^ W0 ) )
    r1_rounds = 8 reproduces the real cipher exactly.
    Total rounds = 8 + r1_rounds.
    """
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
    for r in range(r1_rounds):
        hi ^= SB1[lo & 0xFF]
        lo = ror(lo, ROT[r])
        lo, hi = hi, lo
    return _bytes(lo ^ ror(k0, 2), hi ^ ror(k1, 2))


def invert_rounds(cl, ch, w2lo, w2hi, n, r1_rounds):
    """
    Peel the output whitening (guess w2lo/w2hi) and run the last `n` rounds of
    the second octet BACKWARDS. Returns the state (lo, hi) that many rounds back.

    The rounds themselves contain NO key -- that is what makes this possible.
    """
    lo = cl ^ w2lo
    hi = ch ^ w2hi
    for i in range(n):
        r = r1_rounds - 1 - i
        lo, hi = hi, lo
        lo = rol(lo, ROT[r])
        hi ^= SB1[lo & 0xFF]
    return lo, hi


def key_bytes_that_matter(n, r1_rounds, trials=6, key=None, sat=(6,)):
    """
    Empirically find which of the 8 bytes of W2 actually affect the balance
    after inverting `n` rounds.  Returns a sorted list of names.

    This is the measurement that tells you how big your key search is.
    """
    key = key or random_key()
    k0, k1 = _words(key)
    w2lo, w2hi = ror(k0, 2), ror(k1, 2)
    blocks = saturate(random_block(), list(sat))
    cts = [_words(enc_reduced(b, key, r1_rounds)) for b in blocks]

    def bal(gl, gh):
        al = ah = 0
        for cl, ch in cts:
            a, b = invert_rounds(cl, ch, gl, gh, n, r1_rounds)
            al ^= a
            ah ^= b
        return [state_byte(al, ah, i) for i in range(8)]

    base = bal(w2lo, w2hi)
    names = ["lo0", "lo1", "lo2", "lo3", "hi0", "hi1", "hi2", "hi3"]
    matter = set()
    for bi in range(8):
        for _ in range(trials):
            f = os.urandom(1)[0] or 1
            dl = dh = 0
            if bi < 4:
                dl = f << (8 * (3 - bi))
            else:
                dh = f << (8 * (3 - (bi % 4)))
            if bal(w2lo ^ dl, w2hi ^ dh) != base:
                matter.add(names[bi])
                break
    return sorted(matter), base


def recover_reduced(r1_rounds=3, sat=(6,), key=None, verbose=True):
    """
    A COMPLETE, runnable integral key-recovery against the reduced cipher.

    Strategy: build one integral set, then try every value of the W2 bytes that
    matter, keeping the guesses for which the guaranteed-balanced bytes really
    do come out balanced after inverting `n` rounds.

    Returns (survivors, truth) where each survivor is a dict of byte->value.
    """
    key = key or random_key()
    k0, k1 = _words(key)
    w2lo, w2hi = ror(k0, 2), ror(k1, 2)

    total_rounds = 8 + r1_rounds
    # the deepest round where our set still guarantees some balance
    best = None
    for after in range(total_rounds - 1, -1, -1):
        g = guaranteed_balanced(sat, after, rounds=total_rounds)
        if g:
            best = (after, g)
            break
    after_round, bal_bytes = best
    n_inv = (total_rounds - 1) - after_round     # rounds to invert

    if verbose:
        print("reduced cipher: 8 + %d = %d rounds" % (r1_rounds, total_rounds))
        print("integral set  : saturate %s -> %d texts"
              % (list(sat), 256 ** len(sat)))
        print("deepest guarantee: bytes %s balanced after round %d"
              % (bal_bytes, after_round))
        print("so we invert %d round(s) from the ciphertext" % n_inv)

    matter, _ = key_bytes_that_matter(n_inv, r1_rounds, key=key, sat=sat)
    if verbose:
        print("W2 bytes affecting that balance: %s  -> %d guesses"
              % (matter, 256 ** len(matter)))

    blocks = saturate(random_block(), list(sat))
    cts = [_words(enc_reduced(b, key, r1_rounds)) for b in blocks]

    idx = {"lo0": (0, 0), "lo1": (0, 1), "lo2": (0, 2), "lo3": (0, 3),
           "hi0": (1, 0), "hi1": (1, 1), "hi2": (1, 2), "hi3": (1, 3)}
    order = [m for m in matter]

    survivors = []

    def rec(pos, gl, gh):
        if pos == len(order):
            al = ah = 0
            for cl, ch in cts:
                a, b = invert_rounds(cl, ch, gl, gh, n_inv, r1_rounds)
                al ^= a
                ah ^= b
            if all(state_byte(al, ah, i) == 0 for i in ary):
                survivors.append({m: (gl if idx[m][0] == 0 else gh)
                                  >> (8 * (3 - idx[m][1])) & 0xFF
                                  for m in order})
            return
        half, bpos = idx[order[pos]]
        sh = 8 * (3 - bpos)
        for v in range(256):
            if half == 0:
                rec(pos + 1, gl | (v << sh), gh)
            else:
                rec(pos + 1, gl, gh | (v << sh))

    ary = bal_bytes
    rec(0, 0, 0)

    truth = {m: (w2lo if idx[m][0] == 0 else w2hi) >> (8 * (3 - idx[m][1])) & 0xFF
             for m in order}
    if verbose:
        print("survivors: %d" % len(survivors))
        print("truth    : %s" % truth)
        print("found    : %s" % ("YES" if truth in survivors else "NO"))
    return survivors, truth


# ==========================================================================
# 4. THE REAL THING -- full 16-round cipher, via a Walsh-Hadamard transform
# ==========================================================================
def _fwht_u32(a):
    """
    In-place-ish Fast Walsh-Hadamard transform over uint32 with NATURAL
    WRAPAROUND (i.e. modulo 2**32).  No modular reduction needed:
    FWHT(FWHT(f) * FWHT(g)) == N * (f XOR-convolved with g), and with
    N = 2**24 the parity we want sits at bit 24 of the result.
    """
    import numpy as np
    n = a.size
    h = 1
    while h < n:
        a = a.reshape(-1, 2 * h)
        x = a[:, :h].copy()
        y = a[:, h:].copy()
        a[:, :h] = x + y
        a[:, h:] = x - y
        a = a.reshape(-1)
        h *= 2
    return a


def g5_table():
    """
    The fixed 3-byte S-box chain behind balanced byte 5 after 4 inverse rounds:
        M  = D ^ S1[B ^ S1[A]]
        g5 = S3[A] ^ S1[M]
    Index = (A << 16) | (B << 8) | D.  Key-independent, so build it once.
    """
    import numpy as np
    sb = np.array(SB1, dtype=np.uint32)
    # byte i of a word is at shift 8*(3-i)  (big-endian convention, as in
    # state_byte / the C solver) -- NOT 8*i.  Getting this backwards produces a
    # table that is wrong but still statistically plausible, which is a nasty
    # bug: the candidate count looks perfect and the true key is simply absent.
    b1 = ((sb >> np.uint32(16)) & np.uint32(0xFF)).astype(np.uint8)   # byte 1
    b3 = (sb & np.uint32(0xFF)).astype(np.uint8)                      # byte 3
    A = np.arange(256, dtype=np.uint8)[:, None, None]
    B = np.arange(256, dtype=np.uint8)[None, :, None]
    D = np.arange(256, dtype=np.uint8)[None, None, :]
    inner = b1[(B ^ b1[A])]
    M = (D ^ inner).astype(np.uint8)
    return (b3[A] ^ b1[M]).astype(np.uint8).reshape(-1)


def recover_full_given_byte(whi2=None, key=None, base=None, verbose=True):
    """
    Attack the REAL 16-round cipher with numpy, in about half a minute.

    The full attack must try all 256 values of W2_hi2 in an outer loop; that is
    what the C solver does, and it is why the C solver takes ~5 minutes. Here we
    hand you that one byte so a single pass is enough -- everything else is
    identical to the real attack, including the transform.

    Returns (candidates, truth) for the remaining three key bytes
    (W2_lo2, W2_hi0, W2_lo0), packed as (lo2 << 16) | (hi0 << 8) | lo0.
    """
    import numpy as np

    key = key or random_key()
    k0, k1 = _words(key)
    w2lo, w2hi = ror(k0, 2), ror(k1, 2)
    if whi2 is None:
        whi2 = (w2hi >> 8) & 0xFF          # byte 2 of W2_hi, handed to us

    base = base or random_block()
    blocks = saturate(base, [2, 6])        # 65536 chosen plaintexts
    n = len(blocks)
    cl = np.empty(n, dtype=np.uint32)
    ch = np.empty(n, dtype=np.uint32)
    for i, b in enumerate(blocks):
        a, c = _words(enc(b, key))
        cl[i] = a
        ch[i] = c
    if verbose:
        print("full 16-round cipher, %d chosen plaintexts (saturate bytes 2,6)" % n)

    def byte(x, i):
        return ((x >> np.uint32(8 * (3 - i))) & np.uint32(0xFF))

    sb = np.array(SB1, dtype=np.uint32)
    X6 = byte(ch, 2) ^ np.uint32(whi2)
    s = sb[X6]
    A0 = byte(cl, 2) ^ byte(s, 2)
    D0 = byte(cl, 0) ^ byte(s, 0)
    B0 = byte(ch, 0)
    C5 = int(np.bitwise_xor.reduce(byte(ch, 2)))   # linear term of balanced byte 5

    N = 1 << 24
    H = np.zeros(N, dtype=np.uint32)
    idx = (A0.astype(np.uint32) << np.uint32(16)) | \
          (B0.astype(np.uint32) << np.uint32(8)) | D0.astype(np.uint32)
    np.bitwise_xor.at(H, idx, np.uint32(1))        # parity histogram

    g5 = g5_table()
    Hh = _fwht_u32(H.copy())
    bal = np.zeros(N, dtype=np.uint8)
    for bit in range(8):
        gb = ((g5 >> bit) & 1).astype(np.uint32)
        conv = _fwht_u32((Hh * _fwht_u32(gb)).astype(np.uint32))
        bal |= (((conv >> np.uint32(24)) & np.uint32(1)).astype(np.uint8) << bit)

    cands = np.nonzero(bal == (C5 & 0xFF))[0]
    truth = (((w2lo >> 8) & 0xFF) << 16) | (((w2hi >> 24) & 0xFF) << 8) | \
            ((w2lo >> 24) & 0xFF)
    if verbose:
        print("given W2_hi2 = %02x" % whi2)
        print("candidates for (W2_lo2, W2_hi0, W2_lo0): %d out of 2^24" % len(cands))
        print("truth = %06x   present: %s"
              % (truth, "YES" if truth in set(cands.tolist()) else "NO"))
    return cands, truth


# ==========================================================================
def self_test():
    """Check the symbolic rules against reality."""
    k = key_from_hex("cafebabecafebabe")
    base = bytes.fromhex("0011223344556677")
    for sat in ([6], [2, 6]):
        pred = predict(sat)
        meas = measure(sat, k, base)
        for r in range(16):
            for i in range(8):
                if pred[r + 1][i] in ("A", "B", "C"):
                    assert meas[r + 1][i] in ("A", "B", "C"), (
                        "prediction claimed balance at round %d byte %d but "
                        "measurement disagrees (sat=%s)" % (r, i, sat))
    print("intlab self-test OK  (symbolic predictions are sound vs measurement)")
    try:
        import numpy  # noqa: F401
    except ImportError:
        print("  (numpy absent: skipping the full-cipher FWHT check)")
        return
    cands, truth = recover_full_given_byte(verbose=False)
    assert truth in set(cands.tolist()), "full-cipher FWHT lost the true key"
    print("  full 16-round FWHT recovery OK  (%d candidates, truth present)"
          % len(cands))


if __name__ == "__main__":
    self_test()
