# Integral (Square) cryptanalysis, hands-on

### Follow-up to [`DIFFERENTIAL.md`](DIFFERENTIAL.md), same lab

**Who this is for.** You've worked through the differential tutorial (or you know
what a difference and an S-box are) and want the *other* main workhorse of block
cipher cryptanalysis. Integral attacks broke the AES predecessor Square, still
give the best attacks on reduced-round AES, and — as it happens — beat the
intended solution on this very challenge.

**The one-sentence pitch.** Differential cryptanalysis studies a **pair** of texts
and hopes they behave; integral cryptanalysis studies a whole **structured set**
and *proves* it behaves. You trade data for certainty.

**What you'll be able to do by the end.** Push saturation/balance labels through a
cipher by hand, know exactly which step kills the property and why, explain why
higher-order integrals reach deeper, and run a **complete key recovery** yourself
in a few seconds.

Every number and code block below is real output from the code in this directory.

```bash
cd 2025/quals/crypto-sphinx/solution
python3 intlab.py
# intlab self-test OK  (symbolic predictions are sound vs measurement)
```

`intlab.py` builds on `difflab.py` (same verified cipher). Keep a REPL open:

```python
import intlab as I
```

---

## 1. The mindset shift: from pairs to sets

Differential cryptanalysis asks: *given two texts differing by `ΔP`, what is
`ΔC`?* The answer is probabilistic, so you need many pairs and you hunt for the
lucky ones.

Integral cryptanalysis asks something different: *given a whole **set** of
carefully chosen plaintexts, what can I say about the **sum** of the resulting
set?* And the answers are often **certainties**, not probabilities.

Four definitions, and they're the entire vocabulary. Consider one byte position,
looked at across every text in the set:

| label | name | meaning |
|---|---|---|
| `A` | **active** / **saturated** | takes all 256 values equally often |
| `C` | **constant** | identical in every text |
| `B` | **balanced** | the bytes XOR-sum to zero across the set |
| `?` | **unknown** | no guarantee |

The one arithmetic fact that starts everything:

```
0 ⊕ 1 ⊕ 2 ⊕ … ⊕ 255 = 0
```

(Pair them up: `0⊕1 = 1`, `2⊕3 = 1`, … 128 pairs, each giving `1`, and 128 copies
of `1` XOR to `0`.)

So **`A` implies `B`**: a saturated byte is automatically balanced. And since our
sets always have even size, **`C` implies `B`** too (the same value XORed an even
number of times vanishes). We keep them separate because `A` and `C` are *stronger*
claims that survive more steps, as you're about to see.

- **Integral set:** the chosen plaintexts. Saturate `d` byte positions and hold the
  rest constant; that's `256^d` texts and it's called a **`d`-th order** integral.

---

## 2. The propagation rules

This is the integral analogue of the differential propagation table, and it's
short. Recall one round:

```
hi = hi ⊕ SB[ lo & 0xff ]     # S-box input is byte 3 of lo
lo = ror(lo, ROT[r])          # ROT ∈ {8, 16, 24}
lo, hi = hi, lo
```

**Rule 1 — XOR is linear, so balance survives.** If `x` sums to zero over the set
and so does `y`, then `x ⊕ y` sums to zero. This is the engine of the whole
technique:

```python
I.xor_labels("A", "C")   # 'A'   saturated ⊕ constant is still saturated
I.xor_labels("A", "A")   # 'B'   both balanced ⇒ XOR balanced (but not saturated)
I.xor_labels("B", "C")   # 'B'
I.xor_labels("B", "?")   # '?'   one unknown poisons it
```

Note `A ⊕ A = B`, not `A`. Saturation is fragile; balance is robust. Most of the
decay you'll watch is `A` degrading into `B`.

**Rule 2 — the S-box.** Here is the whole game:

```python
I.sbox_out_labels("C")   # ['C','C','C','C']
I.sbox_out_labels("A")   # ['A','A','A','A']
I.sbox_out_labels("B")   # ['?','?','?','?']    <-- the death condition
```

- `C` in → same lookup every time → constant out. Fine.
- `A` in → each input value occurs once. This cipher's S-box has each of its 4
  output bytes a **permutation** of the input byte, so each output byte also hits
  all 256 values once: `A` out. (In general you need the S-box to be a bijection —
  if it weren't, saturation would not survive, and integral attacks would be much
  weaker. AES's S-box is a bijection for exactly this kind of reason.)
- **`B` in → `?` out.** And this is the crux. "The inputs sum to zero" says
  nothing about a *nonlinear* table's outputs. Knowing a sum tells you nothing
  about individual values, and the S-box needs individual values.

> **An integral dies at the first S-box whose input byte is merely balanced.**
> Everything else — the rotations, the swaps, the key XORs — is free.

**Rule 3 — rotations and swaps are free.** `ROT` is always 8, 16 or 24: whole
numbers of bytes. So a rotation just *moves* byte labels around. Worth pausing on:
if the rotations weren't byte-aligned, byte-level labels would be shredded
immediately and none of this would work. **The fact that this cipher rotates by
multiples of 8 is what makes it analysable byte-by-byte.**

**Rule 4 — the key is free.** Whitening XORs a constant into each position, and by
Rule 1 that preserves `A`, `B` and `C`. The key never interferes. (Compare the
differential tutorial §1: there the key cancelled out of *differences*; here it
cancels out of *sums*. Same reason — linearity.)

---

## 3. Your first integral: watch it propagate

Saturate state byte 6 — 256 chosen plaintexts — and push the labels through.

```python
I.show_prediction([6])
```

```
             byte: 0 1 2 3 4 5 6 7
  before round  0: C C C C C C A C
   after round  0: C C A C C C C C    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round  1: C C C C A C C C    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round  2: A C C C C C C C    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round  3: C C C C C A C C    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round  4: C A C C C C C C    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round  5: C C C C C C C A    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round  6: C C C A C C C C    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round  7: A A A A C C A C    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round  8: A A B A A A A A    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round  9: B B B B B A A A    guaranteed balanced: [0,1,2,3,4,5,6,7]
   after round 10: ? ? ? ? B B B B    guaranteed balanced: [4,5,6,7]
   after round 11: ? ? ? ? ? ? ? ?    guaranteed balanced: -
```

Read that top to bottom — it's the whole attack in one picture.

**Rounds 0–6: the free ride.** A single `A` wanders around, everything else `C`.
The S-box input is `C` every time, so nothing happens. This is *exactly* the
byte-6 free ride from the differential tutorial (§5), restated: there it was "the
S-box is inactive", here it's "the S-box input is constant". **Same structural
fact, and here it costs no probability at all.**

**Round 7:** the `A` finally lands in the lookup byte. `A` in → `A` out, and the
saturation spreads into four bytes of the other half.

**Rounds 8–9: decay.** `A ⊕ A = B`. Saturation starts collapsing into mere
balance. Still all 8 bytes guaranteed balanced.

**Round 10: death.** Look at the state after round 9: `B B B B | B A A A`. The
S-box input is byte 3 of `lo` — a `B`. Rule 2 fires: `B → ?`, and the whole `hi`
half becomes unknown. The four bytes that were *already* in `lo` survive one more
round (they just rotate), which is why bytes 4–7 are still balanced after round 10.

**Round 11:** nothing left.

### Is the prediction actually right?

The rules are *sufficient* conditions, so a byte labelled `B` **must** be
balanced. But is the calculus tight, or is it pessimistic?

```python
I.show_measured([6], key=I.key_from_hex("cafebabecafebabe"),
                base=bytes.fromhex("0011223344556677"))
```

```
  after round  8:  pred A A B A A A A A | meas A A B A A A A A
  after round  9:  pred B B B B B A A A | meas B B B B B A A A
  after round 10:  pred ? ? ? ? B B B B | meas ? ? ? ? B B B B
  after round 11:  pred ? ? ? ? ? ? ? ? | meas ? ? ? ? ? ? ? ?
```

Every round matches exactly. For a first-order integral this little calculus is
**perfectly tight** — you can predict the whole thing on paper.

### A bridge to the differential tutorial

Run the same prediction for each of the 8 possible saturated bytes and compare with
the differential free-ride table, and an exact law falls out (verified for all 8):

> **deepest guaranteed-balance round = first_active_round + 3**

| saturated byte | 3 | 7 | 1 | 5 | 0 | 4 | 2 | 6 |
|---|---|---|---|---|---|---|---|---|
| first active round (differential view) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | **7** |
| deepest balance after round (integral view) | 3 | 4 | 5 | 6 | 7 | 8 | 9 | **10** |

The `+3` is precisely the decay chain you just watched: the active byte enters the
S-box and spreads as `A` (+1), collapses to `B` (+2), and the bytes already sitting
in `lo` get one final free rotation (+3).

So the two techniques **rank the byte positions identically**. They are not rival
attacks that happen to agree — they are two ways of reading one structural fact
about where a perturbation can hide.

---

## 4. Probability 1 — what that buys you

Compare with the differential tutorial. There, the trail through rounds 12 and 14
held with probability `2^-16`; we needed ~196,000 pairs to get ~3 usable ones, and
we had to *identify* which pairs were the good ones.

Here there is no luck. "Bytes 4–7 are balanced after round 10" holds for **every**
key and **every** base text, always. No right pairs, no wrong pairs, no
signal-to-noise ratio, no statistics.

What you pay instead: the property is a statement about a whole **set**, so you
must query the entire set — you can't work with a couple of texts. Differential
cost is measured in *pairs*, integral cost in *sets*. That's the trade.

- **Distinguisher:** any test that tells the real cipher from a random
  permutation. "XOR bytes 4–7 across my 256 ciphertexts, get zero" is one, and it
  needs 256 queries and never fails.

---

## 5. Higher-order integrals — and the limits of the calculus

Deeper balance means a stronger attack. To get it, saturate **more** bytes: a
`d`-th order integral uses `256^d` texts.

Let's try order 2 on bytes `{2, 6}` — 65,536 texts:

```python
for r in range(8, 13):
    print(r, I.guaranteed_balanced([2, 6], r))
# 8 []
# 9 []
# ...
```

The calculus says the property dies after **round 7** — *worse* than the order-1
set. That's clearly wrong: adding structure cannot hurt. So what happened?

**The calculus is sound but incomplete.** With two active bytes, one of them
(byte 2, in `lo`) reaches the S-box early. The labels then say "two `A`s got
XORed, so `B`", and from a `B` everything collapses. But the *truth* is richer:
in the real set, byte 2 is saturated **for each fixed value of byte 6**, and the
first-order labels have no way to express that.

Two ways to do better.

**(a) A sound lower bound — slice it.** A set saturating `{2,6}` is a union of 256
sets that saturate `{6}` alone (one per value of byte 2), and also a union of 256
sets saturating `{2}` alone. If a byte is balanced in every slice, it's balanced in
the union — a XOR of zeros is zero. So we may take the *union* of the single-byte
guarantees:

```python
for r in range(8, 13):
    print(r, I.guaranteed_balanced_union([2, 6], r))
```

**(b) Just measure it.** `I.measure([2,6])` tells you the truth.

All three side by side:

| after round | naive calculus | union bound (sound) | **measured** |
|---|---|---|---|
| 8 | — | all 8 | all 8 |
| 9 | — | all 8 | all 8 |
| 10 | — | 4,5,6,7 | **all 8** |
| 11 | — | — | **4,5,6,7** |
| 12 | — | — | — |

The union bound recovers almost everything, and measurement shows one more round
of real balance that neither argument captures. **That last round is exactly what
the attack needs**, which is why the practical workflow is: reason to get close,
then measure.

**Why higher order genuinely reaches deeper.** The honest reason isn't expressible
in the four labels — it's *algebraic degree*. Each state byte is a polynomial in
the saturated input bytes; each round roughly multiplies the degree. Summing over a
`d`-dimensional set annihilates every monomial of degree `< d`, so a higher-order
sum keeps vanishing for more rounds. (This is the higher-order differential view
of Lai and Knudsen; integral attacks are its set-flavoured cousin.)

**Practical note.** In the real solver, the best order-2 choice `{2,6}` was found by
*scanning all 28 pairs* and measuring — not by theory. Only afterwards did the
reason become clear: bytes 6 and 2 are the two positions whose perturbation takes
longest to reach the S-box (7 and 6 rounds; see `DIFFERENTIAL.md` exercise 2). Let
the machine find it, then explain it.

---

## 6. From distinguisher to key recovery — runnable

A distinguisher isn't a key. The bridge is the same shape as differential's
endgame: **guess a little key, undo a little cipher, and check whether the
property still holds.**

- **Partial decryption:** take a ciphertext, XOR off the *guessed* output whitening,
  and run the last few rounds backwards. Crucially, **the rounds contain no key** in
  this cipher — the key lives only in the whitening — so once you guess those few
  whitening bytes, running rounds backwards is a public computation.

The test: guess → partially decrypt every text in the set → XOR the bytes that
*should* be balanced. Right guess ⇒ zero, guaranteed. Wrong guess ⇒ zero only by
luck, `1/256` per byte checked.

### Why a round-reduced cipher for the demo?

Not because the real attack is out of reach — **the full 16-round attack runs on a
laptop in about five minutes**, and you'll run it in §7. The reduced variant exists
for a narrower reason: it is the largest version where the *naive* method —
literally enumerate every key guess and test it — still finishes in a REPL.

Naive enumeration on the real cipher needs `2^32` guesses, which is hopeless in
Python. Making that step efficient needs a genuinely different idea (a
Walsh–Hadamard transform), and that idea is much easier to appreciate *after*
you've watched the simple version work. So the ladder is:

| rung | cipher | method | cost | runs in |
|---|---|---|---|---|
| 1 | 12 rounds | naive enumeration | `2^8` | < 1 s, pure Python |
| 2 | 13 rounds | naive enumeration | `2^16` | ~11 s, pure Python |
| 3 | **full 16** | FWHT, one key byte given | `2^24` | ~40 s, numpy |
| 4 | **full 16** | FWHT, full search | `2^32` | ~4–6 min, C |

Every rung attacks a real cipher with the real property. Only the *search method*
changes.

### Rung 1 and 2: naive enumeration

```python
I.recover_reduced(r1_rounds=4, sat=(6,))
```

```
reduced cipher: 8 + 4 = 12 rounds
integral set  : saturate [6] -> 256 texts
deepest guarantee: bytes [4, 5, 6, 7] balanced after round 10
so we invert 1 round(s) from the ciphertext
W2 bytes affecting that balance: ['hi0']  -> 256 guesses
survivors: 1
truth    : {'hi0': 2}
found    : YES
```

**256 chosen plaintexts, 256 guesses, one survivor, and it's the right one** — in
well under a second. That's a complete integral key recovery, and you just ran it.

One more round deep:

```python
I.recover_reduced(r1_rounds=5, sat=(6,))
# so we invert 2 round(s) from the ciphertext
# W2 bytes affecting that balance: ['hi1', 'lo0']  -> 65536 guesses
# survivors: 1
# found    : YES        (11.4 s)
```

### Rung 3: the real cipher, in numpy

Now the actual 16-round cipher. The only concession: you're handed one of the four
key bytes (`W2_hi2`), which is exactly the byte the C solver puts in its 256-way
outer loop. Everything else — the set, the property, the transform — is the real
attack.

```python
I.recover_full_given_byte()
```

```
full 16-round cipher, 65536 chosen plaintexts (saturate bytes 2,6)
given W2_hi2 = 16
candidates for (W2_lo2, W2_hi0, W2_lo0): 65747 out of 2^24
truth = ad86eb   present: YES
```

**~40 seconds**, and it just cut `2^24` candidates down to `2^16` containing the
true key — a search no amount of Python `for` loops would have finished. What made
that possible:

```
balance(w) = ⊕ over the set of  g5(c ⊕ w)
```

is an **XOR-correlation**: a fixed table `g5` slid against your data by every
possible XOR-offset `w`. The Walsh–Hadamard transform evaluates it for **all**
`2^24` offsets at once, exactly as an FFT does for ordinary convolution. Three
transforms per bit-plane and you have every answer.

One implementation detail worth stealing (`_fwht_u32`): let 32-bit arithmetic
**wrap around** rather than reducing modulo a prime. `FWHT(FWHT(f)·FWHT(g))` equals
`N × (f ⊛ g)`, and with `N = 2^24` the parity you want sits at bit 24 of the
wrapped result. No division, no modulus, half the memory.

### The cost ladder

Measure how the work grows as you invert more rounds:

```python
I.key_bytes_that_matter(n, r1_rounds, sat=(6,))
```

| rounds inverted | W2 bytes that matter | guesses |
|---|---|---|
| 1 | `hi0` | 2^8 |
| 2 | `hi1`, `lo0` | 2^16 |
| 3 | `hi1`, `hi2`, `lo1` | 2^24 |
| 4 | 4 bytes | 2^32 |

**Each extra round of inversion costs exactly one more key byte** — a factor of
256. That's because only one byte feeds each S-box, so unwinding one more round
exposes exactly one new byte of unknown.

This single table explains the whole shape of the real attack.

### Counting: how much filtering do you need?

You're determining `m` key bytes = `8m` unknown bits. Each balanced byte you check
gives 8 bits of filter. So checking `b` balanced bytes leaves about `2^(8m - 8b)`
wrong survivors. With `m = 4` key bytes and `b = 4` balanced bytes: `2^0 ≈ 1`
spurious survivor alongside the true one — which is exactly what the real solver
sees (it reports 2 survivors and a known plaintext/ciphertext pair kills the
impostor).

---

## 7. Rung 4 — run the real attack yourself

Rung 3 handed you one key byte. Removing that crutch is the whole difference
between numpy and C: you must repeat the transform for all 256 values of
`W2_hi2`, which is 256 × the work. That's ~5 minutes in C, and it would be a
couple of hours in numpy — so the solver is C, not because the attack is heavy,
but because a factor of 256 is worth an hour of your afternoon.

Putting it together for the full cipher:

- Order-2 set `{2,6}`: **65,536** queries, bytes 4–7 balanced after round 11.
- Ciphertext is after round 15, so invert **4** rounds ⇒ **4 key bytes** ⇒ `2^32`.
- Peel `W2_hi2` into a 256-way outer loop; each iteration is exactly the `2^24`
  transform you ran in rung 3.
- All four balanced bytes share one histogram, so a single forward transform
  serves them all: 32 bits of filtering from one set — enough to pin 32 unknown
  bits without a second set.

**Build and run it:**

```bash
gcc -O3 -fopenmp -o solve_opt solve_integral_opt.c    # -march=native optional
./solve_opt
```

```
[*] one integral set built: 65536 chosen plaintexts (sat bytes 2,6)
[*] FWHT stage 229s -> 65719 candidates after 16-bit filter
[*] verify 2s -> 2 survivor(s)
[+] survivor whi2=69 wlo2=8a whi0=3b wlo0=e5     <- the true key bytes
[+] survivor whi2=d6 wlo2=5d whi0=e6 wlo0=78     <- one impostor, as predicted
RECOVERED=110052aee8b317cf TRUE=110052aee8b317cf SUCCESS-FLAG-MATCH  (queries=65536)
```

**What it needs:** any machine with a C compiler, OpenMP, and ~2 GB of RAM.
Measured on 4 cores, both builds run end to end to `SUCCESS-FLAG-MATCH`:

| build | FWHT stage | total | peak RSS |
|---|---|---|---|
| `-O3 -fopenmp` (portable) | 321 s | ~5.6 min | 1.74 GB |
| `-O3 -march=native -fopenmp` | 229 s | ~4.1 min | 1.74 GB |

So `-march=native` buys about 1.4×; it is a nicety, not a requirement. Memory is
`1 GB` of shared precomputed tables plus ~160 MB per thread, so on a many-core
laptop cap it with `OMP_NUM_THREADS=4` if RAM is tight.

Note the two survivors: with `m = 4` key bytes and `b = 4` balanced bytes, §6's
arithmetic predicts `2^(32-32) ≈ 1` impostor alongside the truth. The final
brute-force over the remaining `W2` bytes, checked against one known
plaintext/ciphertext pair, eliminates it.

For contrast, the intended *differential* attack needs ~195,840 pairs and a
billion-row precomputed table. Full details in [`SOLUTION.md`](SOLUTION.md) §4.

---

## 8. Integral vs differential: which to reach for

| | differential | integral |
|---|---|---|
| unit of study | a **pair** | a structured **set** |
| the property | difference trail | saturation / balance |
| holds with | probability (here `2^-16`) | **certainty** |
| needs statistics? | yes — right pairs, S/N | no |
| data | many pairs, individually cheap | whole sets, all-or-nothing |
| loves | sparse trails, weak S-box rows | **byte-aligned** structure, bijective S-boxes |
| hates | strong diffusion, strong S-boxes | non-byte-aligned mixing |
| here | intended solution, ~196k pairs | **best attack, 65,536 queries** |

Rules of thumb worth carrying away:

- **Byte-oriented cipher with bijective S-boxes and byte-aligned rotations?** Try
  integral first. That description fits AES, and it fits this cipher.
- **Bit-oriented cipher, non-aligned rotations, or a weak S-box row?** Differential
  is the better bet — integral labels get shredded.
- **Both attacks reward the same reconnaissance.** The single most valuable fact
  here — that byte 6 takes 7 rounds to reach an S-box — powers both. Differential
  spends it on a probabilistic trail; integral spends it deterministically. Find
  the structure first, choose the technique second.

---

## 9. Exercises

1. **By hand.** For `sat=[6]`, work out the label row after round 8 with pen and
   paper from the rules in §2, then check with `I.predict([6])[9]`.
2. **The death round.** Which round is the first whose S-box input is labelled `B`,
   and why is that the round where everything collapses?
3. **Bijection matters.** Suppose the S-box were *not* a bijection. Which of the
   three S-box rules breaks, and what happens to the attack?
4. **Pick a better byte.** Run `I.guaranteed_balanced([p], 10)` for every
   `p` in 0..7. Which single byte gives the deepest guarantee, and does it match
   the differential tutorial's free-ride table?
5. **Why is `C` balanced?** Our sets have size `256^d`. Where does the argument use
   evenness, and could a set size ever break it?
6. **The ladder.** Predict the number of key bytes needed to invert 5 rounds, then
   check with `I.key_bytes_that_matter(5, 6, sat=(6,))` on a longer reduced cipher.
7. **Do it yourself.** Run `I.recover_reduced(r1_rounds=4)` a few times with
   different random keys. Does it always give exactly one survivor? Explain the
   count using §6's filtering arithmetic.
8. **Why is rung 4 in C?** Rung 3 (`recover_full_given_byte`) attacks the real
   cipher in numpy in ~40 s. Rung 4 does the same thing 256 times. Estimate the
   numpy runtime, and decide for yourself whether the rewrite is worth it.
9. **Drop the crutch.** `recover_full_given_byte` is handed `W2_hi2`. What goes
   wrong if you pass a *wrong* value — do you get no candidates, or the usual
   `~2^16`? Try `I.recover_full_given_byte(whi2=(true^1))` and explain the result
   in terms of §6's filtering arithmetic.

### Solutions

1. After round 7 the state is `A A A A | C C A C`. Round 8: the S-box input is
   `lo[3] = A`, so the output is `A A A A`; XOR into `hi = [C,C,A,C]` giving
   `[A,A,B,A]` (note `A⊕A = B` in position 2). `lo` rotates by `ROT[0]=16` = 2
   bytes → `[A,A,A,A]`. Swap: `A A B A | A A A A`. ✓
2. **Round 10.** After round 9 the state is `B B B B | B A A A`, so `lo[3] = B`.
   By Rule 2, `B → ?`: the sum tells you nothing about individual values, and the
   S-box needs values. Bytes 4–7 survive one extra round only because they sit in
   `lo` and merely rotate.
3. The rule `A → A` breaks. A non-bijective table maps some values twice and others
   never, so a saturated input produces an unbalanced multiset — saturation no
   longer survives even one S-box. The free ride would still work (that only uses
   `C → C`), but the property would die the moment the active byte hit an S-box, and
   the distinguisher would reach nowhere near round 10. Bijectivity is *load-bearing*
   for integral attacks.
4. Byte 6 is the unique winner, and the relationship is an *exact law* — verified
   for all 8 positions:

   > **deepest guaranteed-balance round = first_active_round + 3**

   | saturated byte | 3 | 7 | 1 | 5 | 0 | 4 | 2 | 6 |
   |---|---|---|---|---|---|---|---|---|
   | first active round (differential) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | **7** |
   | deepest balance after round (integral) | 3 | 4 | 5 | 6 | 7 | 8 | 9 | **10** |

   The `+3` is the decay chain from §3: the active byte enters the S-box, spreads as
   `A` (+1), collapses to `B` (+2), and the bytes sitting in `lo` rotate through one
   final round (+3). So the two techniques rank the byte positions *identically* —
   they are reading the same structural fact.
5. `A ⇒ B` needs no evenness (each of the 256 values appears an equal number of
   times and `0⊕…⊕255 = 0`). `C ⇒ B` *does*: a constant `v` XORed `n` times is `0`
   iff `n` is even. `256^d` is always even, so we're safe — but an odd-sized set
   (e.g. dropping one text) would break `C ⇒ B` and quietly invalidate the
   bookkeeping.
6. Five rounds ⇒ **5 key bytes** ⇒ `2^40`. The pattern is one byte per round
   because exactly one byte feeds each S-box.
7. **Always exactly one** — measured 1 survivor in 8/8 runs with random keys, truth
   found every time. With `m = 1` key byte (8 bits of unknown) and `b = 4` balanced
   bytes (32 bits of filter), expected spurious survivors are `2^(8-32) = 2^-24`, so
   an impostor essentially never appears. Contrast the full attack, where
   `m = b = 4` gives `2^0 ≈ 1` expected impostor — and indeed the real solver
   reports 2 survivors.
8. About `256 × 40 s ≈ 2.8 hours` in numpy, versus ~5 minutes in C. The algorithm
   is identical; only the constant factor differs. Rewriting is worth it here, but
   note the *right* order of work: prototype the transform in numpy until it is
   provably correct, then port. (That is exactly how `solve_integral_opt.c` was
   built.)
9. You get the usual `~2^16` candidates — just without the true key among them.
   The filter is statistical: any `w` whose correlation happens to match passes,
   and a wrong `W2_hi2` produces an effectively random correlation, so about
   `2^24 / 2^8 = 2^16` values still survive by chance. That is precisely why the
   full attack must check all 256 outer values and then verify: "the candidate
   count looks right" is *not* evidence that the key is in there.

---

## 10. Further reading

- **The origin:** Daemen, Knudsen & Rijmen, *The Block Cipher Square* (1997) — the
  attack is named after the cipher it broke, and the AES designers then had to
  defend against their own technique.
- **The name:** Knudsen & Wagner, *Integral Cryptanalysis* (2002) — unifies these
  set-based attacks and coins the term.
- **The theory behind §5:** Lai, *Higher Order Derivatives and Differential
  Cryptanalysis* (1994), and Knudsen's truncated/higher-order differentials — where
  the algebraic-degree argument comes from.
- **The modern descendant:** division property and bit-based integral attacks
  (Todo, 2015) — automated search for exactly the propagation we did by hand here.
- **In this repo:** [`DIFFERENTIAL.md`](DIFFERENTIAL.md) for the companion
  technique, [`SOLUTION.md`](SOLUTION.md) §4 for the optimised real attack,
  `solve_integral_opt.c` for the code, `symtrace.py` for the symbolic derivation of
  the S-box chains the FWHT needs.

Same scope note as the differential tutorial: this is a published 1989 cipher and a
CTF challenge, attacked on keys we generate ourselves. Practise on targets you own
or that exist to be broken.
