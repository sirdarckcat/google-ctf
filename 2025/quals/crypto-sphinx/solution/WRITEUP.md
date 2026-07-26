# Breaking "sphinx" — a from-scratch walkthrough

**Audience:** a first-year university student who has seen a little programming
but no cryptography. Every technical term is defined the first time it appears.
Take your time; the ideas are simple once unpacked, they're just stacked deep.

> **Want to learn differential cryptanalysis specifically, by doing it?** Read
> **[`DIFFERENTIAL.md`](DIFFERENTIAL.md)** instead (or first) — it is a hands-on
> tutorial built around a runnable playground, `difflab.py`, with measured
> experiments and exercises. This document is the broader walkthrough of the whole
> challenge.

This is the story of solving the `crypto-sphinx` challenge from Google CTF 2025:
what the puzzle was, the two attacks that break it, and how to make the
recovery as cheap as possible —
ending in a program that recovers the secret from 65,536 queries in about five
minutes on an ordinary laptop-class machine.

---

## Part 0 — Vocabulary you need before anything else

Let's define the absolute basics first. If you know these, skim.

- **Bit:** a single 0 or 1.
- **Byte:** a group of 8 bits. A byte can hold one of `2^8 = 256` values, i.e.
  the numbers 0–255.
- **Hexadecimal ("hex"):** a way of writing numbers in base 16, using digits
  `0-9` and `a-f` (where `a=10, …, f=15`). One byte is exactly two hex digits,
  e.g. the byte with value 255 is `ff`, and `4a` is `4*16 + 10 = 74`. We write
  8-byte blocks as 16 hex characters, like `18e340c7059c5978`.
- **XOR ("exclusive or"), written `⊕` or `^`:** an operation on two bits that
  gives 1 when the bits *differ* and 0 when they're the *same*:
  `0⊕0=0, 0⊕1=1, 1⊕0=1, 1⊕1=0`. On bytes/words you XOR bit-by-bit. Two facts we
  use constantly: **`x ⊕ x = 0`** (anything XORed with itself vanishes) and
  **`x ⊕ 0 = x`**. XOR is its own inverse: if `c = a ⊕ b` then `a = c ⊕ b`.
- **Word:** here, a 32-bit chunk (4 bytes). The cipher works on two 32-bit words
  at a time, which together make a 64-bit **block** (8 bytes).

- **Plaintext (P):** the message before encryption (here, an 8-byte block).
- **Ciphertext (C):** the scrambled output after encryption (also 8 bytes).
- **Key (k):** the secret that controls the scrambling. Here it's 64 bits (8
  bytes). Whoever knows the key can both scramble and unscramble.
- **Cipher / block cipher:** a pair of functions — **encryption** `E_k` that
  turns a fixed-size plaintext block into a ciphertext block using the key, and
  **decryption** `D_k` that reverses it. "Block" means it always eats exactly one
  block (8 bytes) at a time. For any key, `E_k` is a **bijection** (see below):
  `D_k(E_k(P)) = P` for every P.

- **Bijection / permutation (of blocks):** a function that is a perfect
  one-to-one shuffling of its inputs — every possible output is hit by exactly
  one input, and nothing is lost or duplicated. A block cipher's `E_k` is a
  permutation of the `2^64` possible blocks. Because it's a permutation, it has
  an inverse (that's `D_k`), and **two different inputs never collide to the same
  output.**

- **Rotation (bit rotation):** shifting the bits of a word sideways and wrapping
  the ones that fall off the end back around to the other end. `ror(x, r)`
  ("rotate right by `r`") moves every bit `r` places toward the low end;
  `rol(x, r)` rotates left. No bits are lost — it's a reversible reshuffling of
  the same bits.

---

## Part 1 — The challenge: an "encryption oracle" and a target

When you connect to the challenge server, it does this (simplified):

1. It picks a **random 64-bit key** `k` (you never see it).
2. It computes `target = E_k(FLAG)` — the encryption of the secret flag (the flag
   is exactly one 8-byte block) — and prints `target` to you.
3. Then it loops: **you send it any 8-byte block, it sends you back its
   encryption** under the same secret key. If the block you send happens to
   encrypt to `target`, you win and it prints the flag.

- **Encryption oracle:** a service that will encrypt *any plaintext you choose*
  for you, under a key you don't know. That's exactly what step 3 is. Being able
  to freely choose the inputs makes this a **chosen-plaintext** setting — the
  strongest, most convenient position an attacker can be in.
- **CTF (Capture The Flag):** a hacking competition where each puzzle hides a
  secret string called the **flag** (formatted like `CTF{...}`); you "capture"
  it by breaking the puzzle.

**What must we actually do?** We win when we submit an `inp` with
`E_k(inp) = target`. Since `E_k` is a bijection (no two inputs collide), the only
`inp` that works is `inp = D_k(target) = FLAG`. In plain words:

> We must **decrypt one specific ciphertext** (the target), but we only have an
> *encryption* oracle and we don't know the key.

There are two ways to get there: (a) somehow decrypt that one block directly, or
(b) **recover the key** and then decrypt it ourselves. This challenge is solved
by (b): figure out the 64-bit key from the encryption oracle's behavior. That
subject — deducing a secret key from input/output behavior — is called
**cryptanalysis**.

---

## Part 2 — What is the cipher? (reverse engineering)

We're given the cipher's source code (`challenge/sphinx.py`), but it's
deliberately hard to read. Two obstacles:

**(a) Hieroglyph identifiers.** Every variable and function is named with
Egyptian-hieroglyph characters, so you can't tell at a glance what anything is.
Annoying but not fundamental — you just rename things as you decode them.

**(b) A "homoglyph" trap.** Two functions have names that look identical but
aren't: one is `𓂋𓂋𓂋` (three copies of a glyph) and the other is `𓂋𓂋𓂋𓂋` (four
copies). One is rotate-left, the other rotate-right. The code *looks* like it
rotates left but actually rotates right. If you assume "left" you get a cipher
that doesn't match the real one, and every later step silently breaks.

- **Homoglyph:** two characters (or strings) that render nearly identically but
  are different underneath. A classic way to hide a bug in plain sight.

The way to beat both traps is **differential testing**: write your own clean
version of the cipher, then feed thousands of random keys and blocks through
*both* your version and the original and check they agree exactly. When they
disagree, you've localized a bug. Doing this pinned down the ror/rol trap and
produced a **bit-exact verified** clean implementation (our `sphinx_model.py`).

### The building blocks

Now we can describe what the cipher does. It needs three more definitions.

- **S-box (substitution box):** a fixed lookup table that substitutes one small
  value for another. This cipher's S-box takes an 8-bit input (a byte, 0–255) and
  returns a 32-bit output (a word). Think of it as an array `SB` of 256 words:
  you feed in a byte `b` and get out `SB[b]`. It is *fixed and public* — the same
  table for everyone; it does **not** depend on the key. (It's built once at
  startup from a famous table of random digits — Merkle's design detail — but for
  us it's just a known constant.)

- **Feistel network:** a way to build an invertible scrambler out of a function
  that need not itself be invertible. Split the block into two halves, "left"
  and "right". Each **round** mixes one half into the other using the S-box and
  then swaps the halves. Because each step is easily undone (XOR is reversible,
  swaps are reversible), the whole thing can be run backwards to decrypt — even
  though the S-box itself is a one-way lookup.

- **Round:** one repetition of the mixing step. Ciphers repeat many rounds so
  that each output bit depends on all input bits in a complicated way. We'll call
  the two 32-bit halves `lo` and `hi`. One round does:

  ```
  hi  = hi ⊕ SB[ lo & 0xff ]   # take the lowest byte of lo, look it up, XOR into hi
  lo  = ror(lo, r)             # rotate lo right by some amount r
  swap lo and hi               # the two halves trade places
  ```

  Here `lo & 0xff` means "keep only the lowest 8 bits of `lo`" — that single byte
  is the only thing that feeds the S-box each round. Remember that: **just one
  byte per round drives the substitution.**

### The whole cipher

The cipher runs **16 rounds**, in two groups of 8 (each group of 8 rounds is
called an **octet**). It uses a different S-box in each octet — call the first
octet's transformation `R0` and the second's `R1`. Both `R0` and `R1` are fixed,
public permutations that **contain no key at all**.

So where's the key? It's mixed in only by XOR, at three points: before `R0`,
between `R0` and `R1`, and after `R1`. These key-XOR steps are called
**whitening**.

- **Whitening key:** a value XORed into the data to hide it, at the entrance
  and/or exit of a cipher. Here there are three whitening keys, `W0, W1, W2`, all
  derived from the one 64-bit secret `k = (k0, k1)` (two 32-bit words) by tiny
  rotations:

  ```
  W0 = (k0,        k1)
  W1 = (ror(k0,1), ror(k1,1))
  W2 = (ror(k0,2), ror(k1,2))
  ```

Putting it together, the entire cipher is:

```
C  =  W2  ⊕  R1( W1 ⊕ R0( P ⊕ W0 ) )
```

Read it inside-out: XOR the plaintext with `W0`, run the public permutation `R0`,
XOR with `W1`, run the public permutation `R1`, XOR with `W2` — done.

- This shape (public scrambling permutations with the secret added only by XOR
  before/between/after) is a classic construction called **Even–Mansour**. Ours
  is a two-permutation version. Recognizing it tells us where the leverage is:
  **all the secrecy lives in those three XORs.**

- **The cipher is Khafre**, a 1989 design by Ralph Merkle (US patent 5,003,597,
  and the challenge even ships Merkle's paper). The challenge hint "Biham's book"
  points at *differential cryptanalysis*, the technique Eli Biham and Adi Shamir
  famously used on Khafre. We'll see that hint is a bit of a red herring for this
  particular variant.

### One crucial, unusual property of this S-box

The S-box turns a byte into a word, and it does so in a very special way:
**each of the 4 output bytes is an independent permutation of the input byte.**
Concretely `SB[x] = P0[x] | P1[x] | P2[x] | P3[x]`, where each `Pi` is a bijection
on bytes (a perfect shuffle of 0–255). We verified a striking consequence:

> **For any two different inputs, the S-box outputs differ in all 4 bytes.**
> (Because each output byte is a permutation, different inputs → different output
> in *every* byte position. Exhaustive check: it never outputs a zero-difference
> byte.)

Hold onto this fact. It first *blocks* one attack, then *enables* the one that
wins.

---

## Part 3 — The differential attack (this is the *intended* solution)

The hint says Biham, so let's define his technique. This section originally
claimed the differential route was impossible. **That was wrong** — it is the
intended solution — so here is the corrected story, which is more interesting
anyway, because understanding *why* it works is what makes Part 6 possible.

- **Difference:** for a pair of blocks `A` and `A'`, their difference is
  `ΔA = A ⊕ A'`. It records *where the two blocks differ* (a 1 bit wherever they
  disagree), ignoring their actual values.
- **Differential cryptanalysis:** an attack that pushes a *chosen input
  difference* through the cipher and studies the *output difference*. You look
  for an input difference that, with useful probability, forces a predictable
  output difference; deviations from randomness leak key information.
- **Active / inactive S-box:** in a given round, the S-box is *active* for a pair
  if the byte feeding it differs between the two encryptions, and *inactive* if
  that byte is identical. An inactive S-box contributes **nothing** to the
  difference — the difference passes that round untouched.

### The free ride through the first octet

Here is the gift this cipher hands you. Take two plaintexts differing in **one
byte, at byte position 6**. Because only the low byte of `lo` feeds the S-box each
round, and byte 6 lives in the other half, that difference does not reach any
S-box for a long time. Measured over 102,000 random pairs:

> The S-box is **inactive for rounds 0–6** and first becomes active at **round 7**
> — in **100%** of pairs.

The entire first octet is transparent to a byte-6 difference. That is not
probabilistic; it is structural. Remember this fact — it is the single most
valuable thing in the whole challenge.

### Where the original reasoning was right, and where it broke

For the trail to stay useful, the difference must sometimes **cancel**: an S-box
output difference lands on a byte that already has a difference, and the two XOR
to zero, making a later round inactive again.

The original claim was that cancellation is impossible because our S-box (4
independent byte-permutations) **never outputs a zero difference byte**. That part
is true, and measurement confirms the consequence exactly:

| round | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|
| P(inactive) | **0** | **0** | **0** | 1/262 | 1/257 | 1/248 | 1/248 | 1/254 | 1/245 |

At rounds 7–9 cancellation is *literally impossible* (probability 0 over 102,000
pairs). The reason is exactly as argued: the difference has just landed in a half
whose difference was zero, so cancelling would require an S-box output difference
byte of **zero**, which never happens.

**But that only rules out cancelling right after activation.** From round 10 on,
the difference lives in *both* halves. Now cancelling does **not** need a zero
output difference — it only needs the S-box output difference byte to *equal* the
difference byte already sitting there. That happens with probability about
`1/256`, exactly as the table shows. The original argument confused

> "the S-box never outputs a zero difference"  (true)

with

> "differences can never cancel"  (false — they cancel against a *nonzero*
> difference).

Because the original trail search only looked for *sparse* trails (one active
S-box, cancelling immediately), it structurally could not see the trail the real
attack uses.

### The intended attack

The real characteristic asks for the S-box to be inactive at **rounds 12 and 14**.
Measured over 10 million pairs, that joint event has probability
`464/30,000,000 = 1/64,655 = 2^-15.98` (pooled over 5 keys; 68% CI
1/61,787..1/67,803) — essentially two independent `1/256` events. So ~196,000 pairs (768 base plaintexts × 255 one-byte differences) yield
about 3 **right pairs** (pairs that actually follow the trail).

- **Right pair:** a pair that happens to satisfy the characteristic.

Recovering the key from a right pair uses a big **precomputed table** (~1.08
billion rows) that, given an observed ciphertext difference, returns the candidate
S-box input pairs consistent with it. The few remaining unknown middle bytes are
enumerated subject to the cancellation constraints, and each consistent assignment
determines all 8 key bytes directly — because once you know an internal S-box
input **value** and the corresponding ciphertext byte, the key byte is just their
XOR. Each assignment casts a **vote** for a full 64-bit key; the true key
accumulates votes from every right pair while wrong keys scatter, so the most
common vote wins.

### And the "differences hide the key" objection?

It is worth seeing why an apparently fatal objection isn't fatal. At a whitening
step, if `P' = P ⊕ ΔP`, then

```
(P ⊕ W0) ⊕ (P' ⊕ W0) = P ⊕ P' = ΔP.
```

The `W0`'s **cancel**. So the whitening key is genuinely **invisible to
differences** — a pure differential can distinguish the cipher from random but can
never point at the key. True. The escape is that the attack does not stop at
differences: it uses the difference only to *identify right pairs*, then
reconstructs internal **values** and reads the key off as
`key = value ⊕ ciphertext byte`. Values, not differences. (Part 4's integral
attack makes the same move by a different road.)

## Part 4 — The attack that works: the integral (Square) attack

The idea that cracks this cipher is the **integral attack** (also called the
**Square attack**, after the cipher it was invented on). Instead of two blocks
and their difference, it feeds a whole *structured set* of blocks and watches a
property of the *entire set*.

Definitions first:

- **Multiset / set of blocks:** just a bag of many plaintext blocks that we'll
  encrypt together and reason about collectively.
- **Saturated byte:** a particular byte position that, across the set, takes
  *every* value 0–255 exactly once. If we build a set of 256 plaintexts that are
  identical everywhere except in one byte, and that byte runs through all 256
  values, that byte is "saturated". We can saturate several byte positions at
  once: saturating 3 bytes needs `256^3 = 2^24 ≈ 16.7 million` plaintexts (all
  combinations), which the oracle happily encrypts.
- **XOR-sum of a set (at some byte position):** take that one byte from every
  block in the set and XOR them all together into a single byte.
- **Balanced:** a byte position is *balanced* over the set if its XOR-sum is 0.

The magic starting fact: **a saturated byte is balanced.** If a byte takes each
value 0–255 exactly once, XOR them all: `0 ⊕ 1 ⊕ 2 ⊕ … ⊕ 255 = 0` (they pair up
and cancel). More importantly, our permutation S-boxes *preserve* this: push a
saturated byte through a permutation and it's still a permutation of 0–255, so
still balanced. This "balanced-ness" survives through several rounds of the
byte-oriented mixing before diffusion finally destroys it.

**What we measured.** Take `2^24` plaintexts saturating three specific byte
positions. Run them through the cipher and peek at the internal state after each
round. We found — and confirmed it holds for *every* key, i.e. it's a structural
property of the cipher, not luck:

- after **round 11**, *all 8 state bytes* are balanced (XOR-sum 0);
- after **round 12**, the *upper half* (4 bytes) is still balanced.

- **Distinguisher:** a test that tells the real cipher's behavior apart from
  random. "The upper half is balanced after round 12" is our distinguisher.

Why is this the lever? Recall the cipher is `C = W2 ⊕ R1(W1 ⊕ R0(P⊕W0))`, and the
rounds `R0, R1` contain **no key**. The only key at the output is `W2`. So if we
knew `W2`, we could take each ciphertext `C`, XOR off `W2`, and run `R1`
**backwards** — a public computation — to reconstruct the internal state and
*check* whether round 12 is balanced. Removing key + running keyless rounds
backward is called **partial decryption**.

That gives us a key test:

> Guess `W2`. Partially decrypt the whole set back to round 12. If the round-12
> upper half is balanced, the guess is (probably) right; if not, it's wrong.

And crucially, **`W2` is not invisible here** — it sits *inside* the `R1` inverse
we compute, so it does affect the balance test. Values, not differences: this is
why the integral attack recovers the key where the differential could not.

---

## Part 5 — From "test a guess" to "find the key" (cheaply)

Guessing all of `W2` is `2^64` — hopeless. Two observations shrink it.

**Observation 1 — you only need a few bytes of `W2`, not all of it.** To check
the round-12 balance we invert only the *last 4 rounds* of `R1`. Because just one
byte drives each round's S-box, undoing 4 rounds only pulls in a handful of
ciphertext and key bytes. We traced it exactly: a round-12 balanced byte depends
on precisely **4 bytes of `W2`** — call them `W2_lo0, W2_lo2, W2_hi0, W2_hi2`
(the "byte 0 and byte 2" of each 32-bit half). All four round-12 balanced bytes
depend on the *same* 4 key bytes. So the sub-problem is: **find these 4 key
bytes** (32 bits). Once we have them, the remaining 4 bytes of `W2` are found by
a quick brute force (try all `2^32 ≈ 4 billion` possibilities against one known
plaintext/ciphertext pair — a few seconds on a modern CPU), and from `W2` we get
the whole key by rotating: `k0 = rol(W2_lo, 2)`, `k1 = rol(W2_hi, 2)`.

- **Brute force:** just trying every possibility until one works. `2^32` tries is
  small enough to be practical; `2^64` is not.

**Observation 2 — the balance test is a "correlation", which has a fast
algorithm.** Even 4 bytes is `2^32 ≈ 4 billion` guesses, and naively each guess
would re-scan the `16.7`-million-block set — far too slow. Here's the structure
that saves us.

Write the balanced byte we test as a function `g` of the ciphertext bytes and the
key bytes. It turns out (this is the key algebraic observation) that

- `g` is a **fixed** function — it does *not* depend on the key; the key only
  enters as a plain XOR offset into the ciphertext bytes, i.e. the balance we
  test looks like

  ```
  balance(w) = XOR over all ciphertexts c of  g(c ⊕ w)
  ```

  where `w` packs the 4 unknown key bytes and `c` packs the 4 relevant ciphertext
  bytes.

- **Correlation (XOR-correlation):** the quantity `⊕_c g(c ⊕ w)` — sliding a
  fixed pattern `g` against your data by every possible XOR-offset `w` and
  recording the result for each `w`. We want the offset(s) `w` for which this is
  0 (balanced). Computing it separately for every `w` is `(#offsets) × (#data)` —
  way too slow. But there's a shortcut.

- **Walsh–Hadamard transform (WHT):** a mathematical transform that computes an
  XOR-correlation for **all offsets at once**, dramatically faster than doing
  them one by one. It plays the same role for XOR-based sliding that the more
  famous Fast Fourier Transform plays for ordinary sliding/convolution: instead
  of `N` offsets each costing `N` work (`N^2` total), the WHT does the whole
  thing in about `N·log N`. For us `N` is the number of key possibilities; one
  WHT gives the balance for *every* key guess in one sweep.

There's still a subtlety: the whole 4-byte problem at once would need a WHT over
`2^32` values, and that table (as 32-bit integers) is ~16 GB — too big for a
modest machine. The fix is to **peel off one of the four key bytes into an outer
loop.** We try all 256 values of `W2_hi2` (the byte that feeds the very last of
those 4 rounds) one at a time. Once `W2_hi2` is fixed, that last round's S-box
output becomes a *known* per-ciphertext constant, which we simply fold into the
ciphertext bytes ("effective ciphertext"). What's left is a **clean 3-byte
correlation** — a WHT over just `2^24 = 16.7` million values (128 MB as 64-bit
integers). That fits in memory easily, and one such WHT takes about half a
second.

- **Modular arithmetic (needed for a correct, fast WHT):** the WHT adds and
  multiplies large numbers internally; the intermediate values overflow a 64-bit
  integer. The standard cure is to do all the arithmetic **modulo** a prime `p`
  (i.e. keep only the remainder after dividing by `p` — written `x mod p`). We
  use the **Mersenne prime** `p = 2^31 − 1` (a prime of the form `2^n − 1`, which
  makes the remainder operation extremely fast). Because our true counts are
  always smaller than `p`, working mod `p` recovers them exactly, and we only need
  each count's lowest bit (its parity) to read off the balance. This is the one
  "trick" that turns a textbook-but-broken FWHT into a working one.

---

## Part 6 — A full recovery algorithm (~22 minutes)

> This is the first working version. Part 8 improves it to 65,536 queries and
> ~5 minutes; read this first, since Part 8 builds on it.

Here's the complete recipe, now that every piece is defined. It's implemented in
`solve_fwht.c`.

**Step A — Precompute the fixed pattern.** Build the fixed 3-byte function `g`
(the last-4-rounds chain of S-box lookups) as a table, and Walsh–Hadamard
transform it once. This is key-independent, so it's done a single time.

**Step B — Get the data.** Ask the oracle to encrypt an integral set of `2^24`
plaintexts (saturating three chosen byte positions). Keep only the 4 relevant
bytes of each ciphertext. (We use 4 such sets; see the note below.)

**Step C — Recover the 4 key bytes with WHTs.** For each set:
- For each of the 256 guesses of `W2_hi2`:
  1. Compute the "effective ciphertext" bytes for the set.
  2. Build a histogram (a tally) of them and Walsh–Hadamard transform it.
  3. Multiply it against the precomputed transform of `g`, transform back — this
     yields the **balance for all `2^24` remaining key guesses at once**.
  4. Mark every full 4-byte guess `(W2_hi2, W2_lo2, W2_hi0, W2_lo0)` whose balance
     is 0.
- One set doesn't uniquely pin the 4 bytes (many wrong guesses pass by luck), so
  we do this for **4 independent sets and keep only the guesses that pass all 4**
  (a logical AND of the four "marked" tables). The one true 4-byte value passes
  every set; essentially nothing else does. Result: the **unique** 4 key bytes.

  - **Why AND of several sets works:** a wrong key passes the balance test with
    probability about `1/256` per set; passing 4 independent sets is `~2^-32`,
    which knocks the `~2^32` wrong candidates down to essentially zero, leaving
    only the true key (which passes every set, always).

**Step D — Finish the key.** Brute-force the remaining 4 bytes of `W2` (`2^32`
tries, seconds) by checking each candidate key against one known
plaintext/ciphertext pair. Then `k0 = rol(W2_lo, 2)`, `k1 = rol(W2_hi, 2)`.

**Step E — Get the flag.** With the key in hand, compute `D_k(target) = FLAG`.

Real run on a 15 GB / 4-core machine:

```
[*] set 0..3 FWHT done ~305s each        (four sets, ~5 min each on 4 cores)
[+] survivor whi2=69 wlo2=8a whi0=3b wlo0=e5   (the unique true key bytes)
RECOVERED=110052aee8b317cf  TRUE=110052aee8b317cf  SUCCESS-FLAG-MATCH
```

Total: **~22 minutes, entirely in RAM.** The recovery is about `2^33` operations,
not the `2^40`/`2^64` a naive approach would demand.

> **Note on cost.** Using 4 sets is ~67 million oracle queries. You can drop to a
> **single** set (~16 million queries) by correlating *two* of the round-12
> balanced bytes (they depend on the same 4 key bytes, giving 32 bits of
> constraint from one set) — at the price of building one more fixed table. Either
> way, the recovery math is the same WHT.

---

## Part 7 — What to take away

- **Read the target exactly.** The whole puzzle was "decrypt one block with only
  an encryption oracle," which reduces to **recovering the key**. Half the battle
  is stating the goal precisely.
- **Where is the secret?** In this cipher the key is only ever XORed in
  (whitening) around **public, keyless permutations** (an Even–Mansour shape).
  That single structural fact decides which attacks can work.
- **Differences hide XOR keys; values expose them.** Differential attacks cancel
  the whitening key and stall. The **integral attack** watches a *set-wide value
  property* (balance) that the key *does* affect during partial decryption — so it
  recovers the key.
- **A distinguisher becomes a key-recovery** by partially decrypting the last few
  keyless rounds and keeping the key guesses under which the distinguisher still
  holds.
- **Recognize a correlation, then use the fast transform.** The balance test is an
  XOR-correlation; the **Walsh–Hadamard transform** evaluates it for all key
  guesses at once, turning an impossible search into ~22 minutes.
- **Engineering matters.** The homoglyph `ror/rol` trap, the `2^32`→`2^24` memory
  reduction (peel one byte into an outer loop), and doing the WHT **mod a Mersenne
  prime** to avoid integer overflow are each the difference between "works" and
  "doesn't".

### Files in this folder

- `sphinx_model.py` — clean, bit-exact-verified reference implementation of the
  cipher (defeats the obfuscation/homoglyph trap). Run it to re-verify.
- `sphinx_fast.py` — the same cipher vectorized with NumPy, used for the integral
  measurements.
- `integral_attack.py` — demonstrates the structural round-11/round-12 balance.
- **`solve_integral_opt.c` — the cost-optimal solver of Part 8 (2^16 queries, ~5
  min).** This is the one to read.
- `symtrace.py` — derives the S-box chains used by Part 8 symbolically.
- `solve_fwht.c` — the solver of Parts 5–6 (2^26 queries, ~22 min).
- `solve.c` — a slower, memory-light fallback using "partial sums" instead of the
  WHT (~90 min), kept for reference.
- `gen_sboxes.py` / `sboxes.h` — the (key-independent) S-boxes for the C solvers.
- `SOLUTION.md` — the terse, expert-level version of this same analysis.

---

## Part 8 — Making it as cheap as possible

Parts 3 and 4 give two different working attacks. The best attack comes from
noticing that they share a single structural fact, and spending it better.

**The fact.** A one-byte perturbation at **byte 6** rides the entire first octet
without ever touching an S-box (Part 3 measured this: inactive rounds 0–6, first
active at round 7, in 100% of pairs). The differential attack spends that gift on
a *probabilistic* trail — it then needs two lucky cancellations (`≈2^-16`), so it
needs ~196,000 pairs to get ~3 usable ones.

**The better use.** That fact is about byte 6, not about differences — so it works
just as well for **saturation**, and saturation is *deterministic*: no luck needed.
Saturating byte 6 makes the round-0..6 S-box inputs *constant* across the whole
set, so an integral on byte 6 inherits the same 7 free rounds.

Measured balance depth (structural — identical for every key):

| saturated bytes | queries | round 10 | round 11 | round 12 |
|---|---|---|---|---|
| `{6}` | 256 | all 8 | 4,5,6,7 | — |
| `{2,6}` | 65,536 | all 8 | all 8 | **4,5,6,7** |
| `{3,2,6}` | 16,777,216 | all 8 | all 8 | 4,5,6,7 |

So `{2,6}` — **65,536 plaintexts** — reaches exactly the same depth as the
16.7-million-plaintext set from Part 6. That is a **256× query saving for free**.
(Of all 28 possible two-byte choices, only `{2,6}` gets there. Using just one byte
is a round shallower, and that extra round drags in a 5th key byte, which would
blow the search up to `2^40` — so two bytes is the sweet spot.)

**One set is enough.** A symbolic trace of the four inverse rounds shows all four
balanced bytes are built from the *same* three quantities `A`, `B`, `D`, with the
leftover key bytes appearing only *linearly* — and anything linear **cancels** in
an XOR-sum over an even number of texts (`⊕(C ⊕ W) = ⊕C` when the set size is
even). Two consequences:

- all four balanced bytes depend on the same four key bytes, and
- one Walsh–Hadamard transform of the histogram serves *all* of them.

Four balanced bytes × 8 bits = **32 bits of constraint on exactly 32 unknown bits
from a single set** — so no multi-set intersection is needed at all.

**A faster transform.** Part 5 did the WHT in 64-bit integers modulo the prime
`2^31 − 1` to stop overflow. That turns out to be unnecessary: just let 32-bit
arithmetic **wrap around** (which is arithmetic modulo `2^32`, for free). The
double transform produces `2^24 × answer`, so bit 24 of the wrapped result *is*
the parity we want. No division, no remainder, and the tables halve to 64 MB —
which matters because this transform is limited by memory speed, not arithmetic.
Measured: **119 s instead of 305 s** for the identical computation.

**Result, measured end to end:**

```
[*] one integral set built: 65536 chosen plaintexts (sat bytes 2,6)
[*] FWHT stage 229s -> 65719 candidates after 16-bit filter
[*] verify 2s -> 2 survivor(s)
[+] survivor whi2=69 wlo2=8a whi0=3b wlo0=e5      <-- the true key bytes
RECOVERED=110052aee8b317cf TRUE=110052aee8b317cf SUCCESS-FLAG-MATCH  (queries=65536)
```

**~5 minutes, 65,536 queries** — 1024× fewer queries than Part 6's version and 3×
fewer than the intended differential attack, with no giant precomputed database
and a unique answer rather than a majority vote.

The lesson worth keeping: when an attack depends on luck, ask what *structural*
fact it is spending that luck on — and whether you can spend it deterministically
instead.
