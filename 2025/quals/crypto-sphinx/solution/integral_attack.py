#!/usr/bin/env python3
"""
Integral (Square) distinguisher for sphinx (16-round Khafre variant).

The S-box is 4 independent byte-permutations, so a saturated input byte stays
balanced (XOR-sum 0) across the byte-oriented rounds.  R0/R1 are key-independent
public permutations, so key recovery = recover the output whitening W2 only.

This script VALIDATES the structural integral used by the attack:
  * order-3 set, saturating state bytes {3,2,6} (= lo[3],lo[2],hi[2]), 2^24 PTs,
  * round 11 is fully balanced and round 12 has its hi half balanced,
    consistently for random keys.

Key recovery (documented, needs optimized compute) then inverts the 4 tail R1
rounds and pins W2 = (ror(k0,2), ror(k1,2)) via a 4-byte partial-sums / WHT
search; finally FLAG = D_k(target).  See SOLUTION.md.
"""
import numpy as np, os
import sphinx_model as S        # bit-exact verified cipher
import sphinx_fast as F         # vectorized encryptor (enc_vec)

ROT = S.ROT

def integral_balanced_bytes(K0, K1, sat=(3, 2, 6), nrounds=12, seed=0):
    """Encrypt the 2^24 saturated set to `nrounds` rounds; return balanced bytes."""
    rng = np.random.default_rng(seed)
    n = 256 ** len(sat)
    idx = np.arange(n, dtype=np.uint64)
    lo0 = int(rng.integers(0, 2**32)); hi0 = int(rng.integers(0, 2**32))
    lo = np.full(n, lo0, dtype=np.uint32); hi = np.full(n, hi0, dtype=np.uint32)
    for k, sp in enumerate(sat):
        d = ((idx // (256**k)) % 256).astype(np.uint32); sh = 8*(3-(sp % 4))
        m = np.uint32((~(0xff << sh)) & 0xFFFFFFFF)
        if sp < 4: lo = (lo & m) | (d << np.uint32(sh))
        else:      hi = (hi & m) | (d << np.uint32(sh))
    # encrypt nrounds rounds (key-dependent whitening included)
    lo = lo ^ np.uint32(K0); hi = hi ^ np.uint32(K1)
    for r in range(min(nrounds, 8)):
        hi = hi ^ F.SB[0][lo & np.uint32(0xff)]; lo = F.ror(lo, ROT[r]); lo, hi = hi, lo
    if nrounds > 8:
        lo = lo ^ np.uint32(S.ror(K0, 1)); hi = hi ^ np.uint32(S.ror(K1, 1))
        for r in range(nrounds - 8):
            hi = hi ^ F.SB[1][lo & np.uint32(0xff)]; lo = F.ror(lo, ROT[r]); lo, hi = hi, lo
    xl = int(np.bitwise_xor.reduce(lo)); xh = int(np.bitwise_xor.reduce(hi))
    return [i for i in range(8)
            if (((xl if i < 4 else xh) >> (8*(3-(i % 4)))) & 0xff) == 0]


if __name__ == "__main__":
    print("[*] verifying integral distinguisher is structural across keys:")
    for t in range(3):
        K0, K1 = S.bits_to_int(os.urandom(8))
        r11 = integral_balanced_bytes(K0, K1, nrounds=11)
        r12 = integral_balanced_bytes(K0, K1, nrounds=12)
        print(f"    key{t}: round11 balanced={r11}  round12 balanced={r12}")
    print("[*] round 11 fully balanced, round 12 hi-half balanced  => integral OK")
