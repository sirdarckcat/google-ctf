# GoogleCTF 2025 — `crypto-sphinx` — analysis & solver

The challenge (`challenge/sphinx.py`) is a software block cipher whose source is
obfuscated with Egyptian-hieroglyph identifiers and a homoglyph trap. The server
gives an **encryption oracle** for a random 8-byte key and the encryption of the
flag (`target = E_k(FLAG)`), and wins only when you submit `inp` with
`E_k(inp) == target`, i.e. you must compute `inp = D_k(target) = FLAG`. So the
task is **key recovery / single-block decryption** of a chosen-plaintext
encryption oracle.

## 1. Reverse engineering the cipher (the hard, *verified* part)

`solution/sphinx_model.py` is a clean re-implementation **bit-exact verified**
against the original obfuscated module (2000 random keys × blocks, encrypt and
decrypt). Two traps had to be defeated:

* **Homoglyph trap.** Two functions are named with near-identical glyph strings:
  `𓂋𓂋𓂋` (rotate-left) and `𓂋𓂋𓂋𓂋` (rotate-right). The round and whitening code
  actually call **ror**, not rol, despite *looking* like the rol name. The
  effective in-round rotation schedule is therefore `ror` by
  `ROT=[16,16,8,8,16,16,24,24]`.
* The S-boxes and round structure are **key-independent** and deterministic
  (built from the RAND "million random digits" table shipped in
  `attachments/manuscript.txt` — this is Ralph Merkle's **Khafre**, US patent
  5,003,597, hinted by the attachments + "Biham's book").

### Structure

```
C = W2 ⊕ R1( W1 ⊕ R0( P ⊕ W0 ) )
W0 = (k0, k1)                 # only secret = 64-bit key (k0,k1)
W1 = (ror(k0,1), ror(k1,1))
W2 = (ror(k0,2), ror(k1,2))
R0 = 8 Feistel rounds w/ sbox0   (public, key-independent permutation)
R1 = 8 Feistel rounds w/ sbox1   (public, key-independent permutation)
round r: hi ^= sbox[lo & 0xff]; lo = ror(lo, ROT[r]); (lo,hi)=(hi,lo)
```

So it is a **2-round Even–Mansour** with two *public* permutations `R0,R1` and
three *related* whitening keys (1- and 2-bit rotations of the same 64-bit key).

### Key structural facts (validated)

* **S-box = 4 independent byte-permutations.** `sbox[x] = P0[x]|P1[x]|P2[x]|P3[x]`
  where each `Pi` is a bijection on bytes (built by per-column Fisher–Yates from
  the digit stream). Consequence (verified): for **any** nonzero input
  difference, the S-box output difference has **all four bytes nonzero** — the
  S-box never emits a zero output-difference byte.

## 2. Why the textbook Khafre differential attack does *not* port

Biham–Shamir break 16-round standard Khafre with ~1500 CP using a sparse
differential characteristic: a 1-byte difference crosses the first octet for
free (it lives in the half that doesn't feed the S-box), then the trail is kept
sparse through the second octet by **byte-cancellations** (forcing an S-box
output byte to equal a left-half byte). For *this* cipher:

* The free byte (Δ = `(0, A@byte6)`) does cross R0 rounds 0–6 with the S-box
  inactive (verified), activating only at **R0 round 7**. Good so far.
* But at that activation the left half (`hi`) is **all zero**, so the only way to
  cancel is to force S-box output bytes to **0** — which the permutation S-box
  **never** produces (proved by exhaustive search: 0 of 255×256 `(A,u)`
  achieve even a single zero output byte). The difference therefore spreads to 4
  nonzero bytes and R1 fully diffuses it.
* Exhaustive trail search confirms: **no usable sparse trail exists** for our
  rotation schedule (cheapest 2-active-round trail needs an impossible 3-byte
  cancellation; achievable trails are fully diffused). Differential / last-round
  counting attacks are therefore **not** the route here.

## 3. The route that *does* work: integral (Square) attack

The 4-permutation S-box makes a saturated byte stay balanced (XOR-sum 0) through
the byte-oriented round function. Measured integral survival depth
(`sphinx_fast.py` style tests):

| order (chosen-plaintexts) | balanced byte survives through round |
|---|---|
| 1 (2^8)  | 4  |
| 2 (2^16) | 6  |
| 3 (2^24) | 10 |
| 4 (2^32) | ~14 (extrapolated) |

Because `R0,R1` are **key-independent**, key recovery reduces to: guess only the
**output whitening `W2`** (→ the whole key, since `k0=rol(W2_lo,2)`,
`k1=rol(W2_hi,2)`), invert the tail rounds of `R1` (no key needed), and verify
the integral balance holds. The cost is set by how many ciphertext bytes feed
the deepest balanced byte (measured dependency through `R1^{-1}`):

| invert N tail rounds | min ciphertext-byte dependency |
|---|---|
| 2 | 2  |
| 4 | 3  |
| 6 | 5  |

* **order-4 path:** 2^32 data, balanced at round 14 → invert 2 rounds → recover
  ~2 W2 bytes per balanced byte with ~2^16 partial-sums work, repeat → cheap key
  recovery. **Best for a server attack would still be 2^32 queries — too many.**
* **order-3 path:** 2^24 data (feasible), balanced at round 10 → invert 6 rounds
  → ≥5 ciphertext bytes → ~2^40 partial-sums key recovery.

Both are correct attacks; both need heavy compute (2^32 oracle queries, or ~2^40
offline partial-sums) that is impractical in pure Python and was the intended
"expensive but polynomial-ish" solve (the official solution is a Colab notebook).

## 4. Files

* `sphinx_model.py` — bit-exact verified cipher (`enc_block`/`dec_block`,
  `R_forward/R_inverse`, `SBOXES`). Run `python3 sphinx_model.py` to re-verify.
* `sphinx_fast.py` — vectorized (numpy) batch encryptor used for the integral
  measurements above.

> Status: cipher fully reverse-engineered and verified; attack class identified
> (integral attack via the permutation S-boxes) with concrete complexities. The
> full key-recovery (order-4 integral or order-3 + 2^40 partial sums) needs an
> optimized (C/GPU) implementation to actually pull the flag in reasonable time.
