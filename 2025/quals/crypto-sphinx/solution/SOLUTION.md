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

## 2. The differential route (this **is** the intended solution)

> **Correction.** An earlier version of this document claimed no usable
> differential trail exists and that the differential route was a dead end. That
> was wrong, and the differential attack is in fact the *intended* solution. What
> follows is the corrected analysis, with measured probabilities.

Biham–Shamir break 16-round standard Khafre using a characteristic where a
1-byte difference crosses the first octet for free (it lives in the half that
doesn't feed the S-box), then is kept sparse by **byte-cancellations**. For this
cipher, measured over 102,000 pairs with Δ = `(0, A@byte6)`:

* The free byte **does** cross rounds 0–6 with the S-box inactive, activating at
  **round 7** — in 100% of pairs. So the entire first octet is transparent to it.
* At rounds **7, 8, 9** the cancellation probability is measured **exactly 0**.
  Here the original reasoning was right and for the right reason: the difference
  has just entered a half whose difference was zero, so cancelling would require a
  **zero S-box output-difference byte**, which 4-independent-permutation S-boxes
  never emit (0 of 255×256 `(A,u)` produce even one zero output byte).
* **But that only rules out cancelling *immediately* after activation.** Once the
  difference has spread into *both* halves, cancelling no longer needs a zero
  output difference — it only needs the S-box output-difference byte to **equal**
  the incoming difference byte. Measured per-round inactivity:

  | round | 7–9 | 10 | 11 | 12 | 13 | 14 | 15 |
  |---|---|---|---|---|---|---|---|
  | P(inactive) | **0** | 1/262 | 1/257 | 1/248 | 1/248 | 1/254 | 1/245 |

  Over 10^7 pairs, P(round 12 **and** round 14 inactive) = 167/10^7 =
  **1/59,880 ≈ 2^-15.9** (essentially independent 2^-8 · 2^-8).

The intended attack uses exactly that event: ~196k pairs (768 base texts × 255
one-byte differences) buy ~3 right pairs. Right pairs are identified with a
~1.08e9-row precomputed table over
`ror(SB[i]^SB[j],16) ^ (SB[k]^SB[l]) → (i,j,k,l)`, the remaining middle bytes are
enumerated under the cancellation constraints, and each consistent assignment
yields all 8 key bytes directly (`key = internal value ⊕ ciphertext byte`) as a
**vote**; majority wins.

Note the earlier observation that "differences cancel the whitening key, so a
differential can't point at the key" is true *of differences alone*, but it is not
an obstruction: the difference is only used to **filter right pairs**, and the key
falls out of the reconstructed internal **values** — the same values-not-differences
move the integral attack makes.

### The structural gift, and how to spend it better

The important discovery underneath the differential is not probabilistic at all:
**a byte-6 perturbation rides the whole first octet for free.** That fact is about
byte 6, not about differences — so it applies verbatim to **saturation**, which is
deterministic. Spending it that way is strictly cheaper; see §4.

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

## 4. The cost-optimal attack (`solve_integral_opt.c`)

This supersedes the earlier order-3 integral. It is built from the *union* of two
ideas: the structural fact that powers the intended differential attack, and the
FWHT correlation machinery from the integral attack.

### What the intended differential attack really gave away

The published solution uses a one-byte plaintext difference in **state byte 6**
(`p2[6] ^= r`). Measured over 102,000 pairs, that difference leaves the S-box
**inactive for rounds 0–6 and first activates at round 7, in 100% of cases** —
the whole first octet is transparent to it. The differential attack spends that
gift on a probabilistic trail (cancellations at rounds 12 and 14, joint
probability measured **1/59,880 ≈ 2^-15.9**, so ~196k pairs buy ~3 right pairs).

But that "free first octet" is a statement about **byte 6**, not about
differences. It applies verbatim to *saturation* — and saturation is
deterministic. That is the whole idea.

### Consequence: an order-2 integral is enough

Saturating state byte 6 keeps the round-0..6 S-box inputs **constant across the
whole set**, so an integral on byte 6 inherits 7 free rounds. Measured balance
depth (structural — identical across keys):

| saturated bytes | queries | round 10 | round 11 | round 12 |
|---|---|---|---|---|
| `{6}` (order-1) | 256 | all 8 | 4,5,6,7 | — |
| `{2,6}` (order-2) | 65,536 | all 8 | all 8 | **4,5,6,7** |
| `{3,2,6}` (order-3) | 16,777,216 | all 8 | all 8 | 4,5,6,7 |

`sat(2,6)` reaches **exactly the same depth as the order-3 set with 256× fewer
queries**, and a scan of all 28 order-2 pairs shows `(2,6)` is the *only* one that
gets there. Order-1 is one round shallower, and that extra inversion pulls in a
5th key byte (`W2_hi1`) → 2^40, so order-2 is the sweet spot.

### One set, 32 bits: all four balanced bytes share one histogram

A symbolic trace of 4 inverse rounds (all rotations are byte-aligned: 24,24,16,16)
gives, with

```
A = C_lo2 ^ W2_lo2 ^ S2[H2],   B = C_hi0 ^ W2_hi0,   D = C_lo0 ^ W2_lo0 ^ S0[H2]
H2 = C_hi2 ^ W2_hi2,           M = D ^ S1[B ^ S1[A]]
```

the four balanced bytes of round 12:

```
byte4 = C_hi1 ^ W2_hi1 ^ S2[A] ^ S0[M]        g4 = S2[A] ^ S0[M]
byte5 = C_hi2 ^ W2_hi2 ^ S3[A] ^ S1[M]        g5 = S3[A] ^ S1[M]
byte6 = C_hi3 ^ W2_hi3 ^ S0[A] ^ S2[M]        g6 = S0[A] ^ S2[M]
byte7 = C_hi0 ^ W2_hi0 ^ S1[A] ^ S3[M]        g7 = S1[A] ^ S3[M]
```

Two things fall out:

1. **The stray key bytes cancel.** `W2_hi1`, `W2_hi3` (and `W2_hi0`, `W2_hi2` in
   their linear positions) appear only linearly, so over an **even-sized** set they
   XOR away: `⊕(C ^ W) = ⊕C`. Every balance constant is a pure XOR of ciphertext
   bytes. That is why all four balanced bytes depend on exactly the same four key
   bytes `{W2_lo0, W2_lo2, W2_hi0, W2_hi2}` (verified by flipping each key byte).
2. **All four share the same `(A,B,D)`.** So after peeling `W2_hi2` into a 256-way
   outer loop, *one* forward FWHT of the histogram serves every bit-plane of every
   balanced byte. Four bytes = **32 bits of constraint on 32 unknown bits from a
   single set** — no multi-set intersection needed.

### Faster FWHT: pure uint32, no modular reduction

The earlier solver did the transform in `int64` mod the Mersenne prime `2^31-1`
to stop intermediates overflowing. That is unnecessary. Let the butterflies wrap
naturally mod `2^32`:

* `FWHT(FWHT(f)·FWHT(g)) = N·(f*g)` with `N = 2^24`, so the uint32 result is
  `2^24·(f*g) mod 2^32`, hence `(x >> 24) & 1` **is** the parity we want.
* No `%` anywhere, and the arrays halve to 64 MB — and a 2^24 FWHT is
  memory-bandwidth-bound, so that matters.

Measured: **119 s vs 305 s** per set for the identical computation — a **2.6×**
speedup.

### The algorithm

1. **One** integral set: saturate state bytes 2 and 6 → `2^16 = 65,536` chosen
   plaintexts. Reuse any member as the known plaintext/ciphertext pair, so the
   total query cost is exactly `2^16`.
2. For each of 256 guesses of `W2_hi2`: fold the round-15 S-box outputs into
   effective ciphertext bytes, build the 2^24 parity histogram, one forward FWHT,
   then 16 bit-plane inverse FWHTs for balanced bytes 5 and 7 (16 bits) → keep
   `(W2_lo2, W2_hi0, W2_lo0)` whose correlations match the ciphertext constants.
3. Verify the ~2^16 survivors with a **real** 4-round inversion over the set,
   requiring all four balanced bytes to vanish (the other four `W2` bytes can be
   set to zero — they cancel). Expect one survivor.
4. Brute the remaining four `W2` bytes (2^32, seconds) against the known pair, then
   `k0 = rol(W2_lo,2)`, `k1 = rol(W2_hi,2)`, and `D_k(target) = FLAG`.

### Cost — verified end-to-end

```
[*] precomputed FWHT(g5),FWHT(g7) in 9.5s
[*] one integral set built: 65536 chosen plaintexts (sat bytes 2,6)
[*] FWHT stage 229s -> 65719 candidates after 16-bit filter
[*] verify 2s -> 2 survivor(s)
[+] survivor whi2=69 wlo2=8a whi0=3b wlo0=e5     <-- the true key bytes
[+] survivor whi2=d6 wlo2=5d whi0=e6 wlo0=78     <-- 1 spurious, killed by the PC-pair brute force
RECOVERED=110052aee8b317cf TRUE=110052aee8b317cf SUCCESS-FLAG-MATCH  (queries=65536)
```

**~5 minutes wall clock, 65,536 queries, 1.7 GB RSS, on a 15 GB / 4-core box.**
The 16-bit FWHT filter left 65,719 candidates — within 0.3% of the predicted
`2^24 · 2^-16 · 256 = 65,536` — and the 32-bit verification left 2, exactly the
expected 1 true + ~1 spurious.

| attack | queries | recovery time | precomputation | result |
|---|---|---|---|---|
| order-3 integral (`solve_fwht.c`) | 67,108,864 = 2^26 | ~20 min | 128 MB, 7 s | deterministic |
| intended differential (gist) | 195,840 ≈ 2^17.6 | — | ~1.08e9-row DB, tens of GB | majority vote |
| **this (`solve_integral_opt.c`)** | **65,536 = 2^16** | **~5 min** | **2 × 128 MB, 9.5 s** | **deterministic** |

**1024× fewer queries than the order-3 integral and 3× fewer than the intended
differential attack**, 4× faster than the order-3 version, with a precomputation
of two in-RAM tables built in 9.5 s rather than a multi-gigabyte database, and a
unique answer instead of a vote.

A 4-set variant (262,144 queries, `solve_best.c` logic, g5 only) was also run and
confirmed: `survivors=2 ... SUCCESS-FLAG-MATCH`, 8.7 min. It needs 4× the queries
for the same result, so the single-set version above supersedes it.

---

### Earlier version: order-3 integral, ~22 min (`solve_fwht.c`)

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

## 5. Files

* `sphinx_model.py` — bit-exact verified cipher (`enc_block`/`dec_block`,
  `R_forward/R_inverse`, `SBOXES`). Run `python3 sphinx_model.py` to re-verify.
* `sphinx_fast.py` — vectorized (numpy) batch encryptor used for measurements.
* `integral_attack.py` — validates the structural round-11/round-12 integral.
* `gen_sboxes.py` → `sboxes.h` — the (key-independent) S-boxes for the C solver.
* **`solve_integral_opt.c` — the cost-optimal solver (§4). 2^16 queries, one
  integral set.** `gcc -O3 -march=native -fopenmp -o solve_opt solve_integral_opt.c`
  then `./solve_opt`.
* `symtrace.py` — symbolic byte-level tracer that derives the `g4,g5,g6,g7` chains
  used by §4 (prints the formula for every state byte after each inverse round).
* `solve_fwht.c` — previous version: order-3 integral, 2^26 queries, ~22 min.
* `solve.c` — memory-light partial-sums fallback (2^40, ~90 min).

### Note on the live server

The cost-optimal attack needs **2^16 = 65,536** chosen-plaintext queries — one
integral set, small enough to be practical over a remote socket (the earlier
order-3 version needed ~6·10^7, which was not). All recovery is offline. The
cryptanalysis and key recovery are complete and verified.

> Status: **SOLVED**, cost-optimally. `solve_integral_opt.c` recovers the 64-bit
> key + flag from **2^16 = 65,536 chosen plaintexts in ~5 min** on a 15 GB /
> 4-core box — 1024× fewer queries than the earlier order-3 integral and 3× fewer
> than the intended differential attack, deterministic rather than a vote. Built
> by spending the differential attack's structural gift (a byte-6 perturbation
> rides the whole first octet free) on *saturation* instead of a probabilistic
> trail. Earlier solvers kept for reference: `solve_fwht.c` (2^26 queries,
> ~22 min), `solve.c` (partial sums, ~90 min). All verified `SUCCESS-FLAG-MATCH`.
