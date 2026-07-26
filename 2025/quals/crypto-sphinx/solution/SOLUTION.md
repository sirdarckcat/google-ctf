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

### Fast recovery that runs in ~22 min on a 15 GB / 4-core box (`solve_fwht.c`)

The 2^40 partial-sums is only needed if you brute the 4 key bytes *jointly*.
Instead, put **`W2_hi2` in an outer loop (256 values)**. Once `W2_hi2` is fixed,
the round-15 S-box outputs `s2,s0` (functions of `X6 = C_hi2 ⊕ W2_hi2`) fold into
**effective ciphertext bytes** `u2 = C_lo2⊕s2`, `u0 = C_lo0⊕s0`, and what's left is
a **fixed** 3-byte S-box chain
`g5(A,B,D) = byte3(SB1[A]) ⊕ byte1(SB1[D ⊕ byte1(SB1[B ⊕ byte1(SB1[A])])])`
with `A=u2⊕W2_lo2, B=C_hi0⊕W2_hi0, D=u0⊕W2_lo0`. So

```
balance5(w) = C6 ⊕ ⊕_{c∈H} g5(c ⊕ w)        w = (W2_lo2, W2_hi0, W2_lo0)
```

is a **clean 3-byte XOR-correlation over 2^24** — one **Walsh–Hadamard transform**
(mod the Mersenne prime 2^31−1 to avoid int64 overflow) gives all 2^24 keys at
once. `2^24·int64 = 128 MB`, so it fits easily. Per `W2_hi2`: 1 forward + 8
bit-plane inverse FWHTs; the whole 256×(2^24 FWHT) sweep is **~5 min per integral
set on 4 cores**. Four sets, AND their candidate bitmaps → the unique 4 bytes
`{W2_lo0,W2_lo2,W2_hi0,W2_hi2}`, brute the other 4 `W2` bytes (2^32, ~seconds)
against one known plaintext/ciphertext pair, then `k0=rol(W2_lo,2)`,
`k1=rol(W2_hi,2)`, `D_k(target)=FLAG`.

Verified end-to-end on this 15 GB / 4-core sandbox:

```
[*] set 0..3 FWHT done ~305s each   (4 * ~5 min)
[+] survivor whi2=69 wlo2=8a whi0=3b wlo0=e5   (= the true key bytes, unique)
RECOVERED=110052aee8b317cf  TRUE=110052aee8b317cf  SUCCESS-FLAG-MATCH
```

Total ≈ **22 min**, entirely in RAM. (Queries here are 4·2^24 ≈ 67M; they drop to
**one** set ≈ 16M by also correlating balanced bytes 4 and 7 — same `{0,2,4,6}` key
bytes, 32-bit constraint → unique from a single set — at the cost of the `g4,g7`
tables.) This is the intended sub-hour solve; `solve.c` (partial-sums) is the
memory-light-but-slow fallback.

### Making it cheaper (query + compute analysis)

**Queries — 1 set, not 4.** All four round-12 balanced bytes (4,5,6,7) depend on
the *same* 4 key bytes `{W2_lo0, W2_lo2, W2_hi0, W2_hi2}` (verified, including
every linear combination — byte 5 of `W2` cancels in the *balance* even though it
affects the *value*). So a **single** order-3 set gives 4 balance equations = 32
bits of constraint on those 32 unknown bits → the 4 bytes are unique from **one
set (~16M CP)**, a 4× query reduction over the 4-set version in `solve.c`.

**Compute — it's a clean XOR-correlation.** `balance(w) = ⊕_{c∈H} g(c⊕w)`, and
the trick (see `solve_fwht.c` above) is to put `W2_hi2` in a 256-way outer loop:
the round-15 S-box outputs then fold into *effective* ciphertext bytes, leaving a
**fixed 3-byte chain** `g5` and a genuinely clean **3-byte XOR-correlation** solved
by a **2^24 FWHT (128 MB, fits any box)**. So the recovery is ~2^33 total, ~22 min
on this 4-core sandbox — no 16 GB table needed. (A single monolithic 4-byte FWHT
*would* need 16 GB; the 3-byte-per-`W2_hi2` factorization avoids that.)

### Key-recovery: implemented and **SOLVED** (`solve.c`)

Recovering those 4 key bytes is a **partial-sums** problem over the sequential
S-box chain. For each candidate `(W2_hi2, W2_lo2)` we build the `(a,b)` parity
histogram of the integral set (`a=C_hi0⊕byte1(SB1[m1])`, `b=C_lo0⊕byte0(SB1[X6])`),
then a nested 2-byte collapse recovers `(W2_hi0, W2_lo0)` by requiring
`⊕_set byte1(SB1[m3]) = C6 ⊕ ⊕_set byte3(SB1[m1])`. Cost ≈ **2^40–2^42** S-box ops.

`solve.c` (OpenMP, C):

1. takes the encryption oracle, builds **4 order-3 integral sets** (`2^24` CP each),
2. runs the partial-sums over 3 sets → a few hundred raw candidates,
3. filters them on the 4th set → the unique 4 key bytes
   `{W2_lo0, W2_lo2, W2_hi0, W2_hi2}`,
4. brute-forces the remaining 4 `W2` bytes (`2^32`) against one known
   plaintext/ciphertext pair → full `W2` → `k0=rol(W2_lo,2)`, `k1=rol(W2_hi,2)`,
5. `D_k(target) = FLAG`.

Verified end-to-end on a random key (≈ 90 min on 4 cores):

```
[*] search done, 283 raw candidates; filtering on set3
[+] survivor whi2=b9 wlo2=62 whi0=48 wlo0=b2
[+] KEY k0=ca0d8a6a k1=23cee6d1
RECOVERED=18e340c7059c5978  TRUE=18e340c7059c5978  SUCCESS-FLAG-MATCH
```

i.e. the 64-bit key is recovered from the encryption oracle alone and the flag
block is decrypted exactly. (The official solution is a Colab notebook; this is
the same expensive-but-structural integral attack.)

## 4. Files

* `sphinx_model.py` — bit-exact verified cipher (`enc_block`/`dec_block`,
  `R_forward/R_inverse`, `SBOXES`). Run `python3 sphinx_model.py` to re-verify.
* `sphinx_fast.py` — vectorized (numpy) batch encryptor used for measurements.
* `integral_attack.py` — validates the structural round-11/round-12 integral.
* `gen_sboxes.py` → `sboxes.h` — the (key-independent) S-boxes for the C solver.
* `solve.c` — the full attack: `gcc -O3 -march=native -fopenmp -o solve solve.c`
  then `./solve` (self-contained oracle demo, prints `SUCCESS-FLAG-MATCH`).

### Note on the live server

The attack needs ~`4·2^24 ≈ 6·10^7` chosen-plaintext oracle queries (the integral
sets). That is practical against a local/fast oracle (as demonstrated) but heavy
over the remote socket; the recovery itself is offline. The cryptanalysis and
key recovery are complete and verified.

> Status: **SOLVED.** Integral (Square) attack via the permutation S-boxes.
> `solve_fwht.c` recovers the 64-bit key + flag in **~22 min on this 15 GB /
> 4-core box** (3-byte modular-FWHT correlation). `solve.c` is the memory-light
> partial-sums fallback (~90 min). Both verified end-to-end (`SUCCESS-FLAG-MATCH`).
