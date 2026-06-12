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
the byte-oriented round function. Because `R0,R1` are **key-independent**, key
recovery reduces to: recover only the **output whitening `W2`** (→ the whole key,
since `k0=rol(W2_lo,2)`, `k1=rol(W2_hi,2)`), partially **invert the tail rounds
of `R1`** (no key in the rounds themselves, only `W2` at the very end), and keep
the guess for which the integral balance still holds.

### Confirmed integral (validated, key-independent / structural)

An **order-3** integral — saturate state bytes `{3,2,6}` (= `lo[3],lo[2],hi[2]`),
i.e. **2^24 chosen plaintexts** — gives, consistently across keys:

* **round 11 fully balanced** (all 8 state bytes XOR-sum to 0),
* **round 12 hi-half balanced** (state bytes 4,5,6,7).

So from a ciphertext you remove `W2` and invert **4** `R1` rounds (15,14,13,12)
and require the round-12 hi bytes to be balanced. The balanced byte
`b5 = byte1(hi)` of state-after-12 was traced to depend on exactly:

* ciphertext bytes `{C_lo0, C_lo2, C_hi0, C_hi2}` and
* key bytes `{W2_lo0, W2_lo2, W2_hi0, W2_hi2}` (each XORed with the same-index
  ciphertext byte: `Xi = C_i ⊕ W2_i`), in a **sequential S-box chain**
  `X6 → X2 → X4 → X0` (rounds 15→14→13→12). All four key bytes affect the
  *balance* (no linear cancellation), and the function does **not** factor, so a
  cheap meet-in-the-middle is ruled out (verified).

### Key-recovery cost

Recovering those 4 key bytes is a classic **partial-sums / Walsh–Hadamard**
problem over `GF(2)^32`:

* partial-sums (Ferguson) ≈ **2^40** S-box evaluations (chain of 4 bytes),
* or a Walsh–Hadamard correlation over `2^32` (needs ~32 GB for the int64 WHT).

Both are routine in optimized C but exceed pure-Python on this 15 GB / 4-core
box (numpy stage-A collapse is ~30 s, but the full 4-byte search is ~2^40).
Repeat with a handful of integral sets / the other balanced bytes to pin all of
`W2`, then `k0=rol(W2_lo,2)`, `k1=rol(W2_hi,2)`, and `D_k(target) = FLAG`.

This is the intended "expensive but structural" solve (official solution is a
Colab notebook). The cipher model and the integral distinguisher here are fully
validated; only the final 2^40/2^32-memory search needs an optimized runner.

## 4. Files

* `sphinx_model.py` — bit-exact verified cipher (`enc_block`/`dec_block`,
  `R_forward/R_inverse`, `SBOXES`). Run `python3 sphinx_model.py` to re-verify.
* `sphinx_fast.py` — vectorized (numpy) batch encryptor used for the integral
  measurements above.

> Status: cipher fully reverse-engineered and verified; attack class identified
> (integral attack via the permutation S-boxes) with concrete complexities. The
> full key-recovery (order-4 integral or order-3 + 2^40 partial sums) needs an
> optimized (C/GPU) implementation to actually pull the flag in reasonable time.
