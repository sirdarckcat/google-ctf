# Differential cryptanalysis, hands-on

### Using GoogleCTF 2025 `crypto-sphinx` as your lab

**Who this is for.** You can program, you've maybe heard "differential
cryptanalysis" and bounced off the papers. You want to *do* it, not read about
it. No crypto background assumed — every term is defined where it first appears.

**Why this cipher is a good first lab.** In most ciphers a single round touches
every byte at once, so difference propagation is a bookkeeping nightmare. Here
**exactly one byte drives the S-box each round**, so you can follow a difference
through the cipher *by hand* and check yourself against a one-line experiment.
It's also a real target: this is Ralph Merkle's **Khafre**, the cipher Biham and
Shamir famously attacked, and the challenge's intended solution is a genuine
differential attack.

**What you'll be able to do by the end.** Trace a difference through 16 rounds,
read a difference distribution table, compute a characteristic's probability from
first principles, predict how much data an attack needs — and explain why a
technique that seems to be blind to the key can still recover it.

Every number and every code block below was produced by running the code in this
directory. You should get the same (up to random sampling).

---

## 0. Set up — two minutes

```bash
cd 2025/quals/crypto-sphinx/solution
python3 difflab.py
# difflab self-test OK  (enc/dec, S-box property, byte-6 free ride)
```

`difflab.py` is a small, unoptimised, readable implementation of the cipher plus
tools for watching differences. It is **bit-exact** against a model that was
itself verified against the original challenge binary (3000 random key/block
pairs, encrypt and decrypt). Pure Python; numpy only for the two large
measurements.

Open a REPL and keep it open:

```python
import difflab as L
k = L.key_from_hex("cafebabecafebabe")
L.enc(bytes.fromhex("0011223344556677"), k).hex()
```

---

## 1. The one idea: differences

- **Block / plaintext / ciphertext.** This cipher works on 8-byte (64-bit)
  chunks. The **plaintext** `P` goes in, the **ciphertext** `C` comes out, under
  a secret 8-byte **key** `k`. Write `C = E_k(P)`.
- **XOR** (`^`, or `⊕`): bitwise "are these bits different?" Two facts do all the
  work: `x ⊕ x = 0` and `x ⊕ 0 = x`.
- **Difference.** Given *two* plaintexts `P` and `P'`, their difference is
  `ΔP = P ⊕ P'`. It records only *where they differ*, not their values.

Differential cryptanalysis studies **pairs**. You choose `ΔP`, encrypt both
texts, look at `ΔC = C ⊕ C'`, and exploit the fact that `ΔC` is not uniformly
random.

### Why differences are powerful: the key cancels

Here is the whole reason this technique exists. Suppose a step of the cipher XORs
in a secret key `K`. Follow both texts through it:

```
(P ⊕ K) ⊕ (P' ⊕ K) = P ⊕ P'   because K ⊕ K = 0
```

The key **vanishes**. The difference comes out unchanged, *whatever the key was*.

> **Consequence:** you can predict how a difference moves through key-XOR steps
> **without knowing the key.** Difference propagation is key-independent.

That is the superpower. (It is also, as we'll see in §8, the thing that makes
people wrongly conclude a differential can't *find* a key.)

**Experiment 1 — see key-independence.** The difference after the free rounds is
the same no matter the key:

```python
p1, p2 = L.pair(bytes.fromhex("0011223344556677"), byte_pos=6, delta=0x40)
for _ in range(3):
    kk = L.random_key()
    t = L.diff_trace(p1, p2, kk)
    print(kk.hex(), t[6]["state_diff"].hex())
```

You'll see three different keys and **the same difference** each time.

---

## 2. The cipher, in one paragraph

Two 32-bit halves, `lo` and `hi`. **16 rounds**, split into two groups of 8
called **octets**; each octet uses its own fixed, public **S-box**
(a lookup table — here it maps one byte to a 32-bit word, and it does *not*
depend on the key). One round is:

```
hi = hi ⊕ SB[ lo & 0xff ]     # only the LOWEST BYTE of lo is looked up
lo = ror(lo, ROT[r])          # rotate lo right (ROT = 16,16,8,8,16,16,24,24)
lo, hi = hi, lo               # swap halves
```

The key appears **only** as three XORs — before the first octet, between the
octets, and after the last (`W0`, `W1`, `W2`, all small rotations of the same
64-bit key). This shape — public keyless scrambling with the key added only by
XOR — is called **Even–Mansour**.

The thing to hold onto: **one byte per round feeds the S-box.** Everything below
follows from that.

"State byte *i*" means byte *i* of the 8-byte block: bytes 0–3 are in `lo`,
bytes 4–7 in `hi`. Rounds are numbered **0–15**, and we always say "after
round *N*" to mean the state once round *N* has finished.

---

## 3. How differences move: two kinds of step

Every step in this cipher is one of two kinds.

**Deterministic steps (probability 1).** The difference goes through in a way you
can compute exactly:

| step | what happens to the difference |
|---|---|
| XOR with key or constant | unchanged (the key cancels) |
| `ror` / rotation | rotates the same way |
| swap halves | swaps |

**The probabilistic step: the S-box.** `hi ^= SB[lo & 0xff]`. Two cases, and this
is the single most important distinction in the whole subject:

- **Inactive S-box:** the byte feeding the S-box is *identical* in both
  encryptions (its difference is 0). Then both look up the same entry, XOR in the
  same value, and it **cancels** — the S-box contributes *nothing*. The
  difference sails through untouched, with probability 1.
- **Active S-box:** that byte *differs*. Now the two lookups return different
  words, and the difference picks up `SB[x] ⊕ SB[x⊕δ]` — a value that depends on
  the actual **value** `x`, not just the difference `δ`. This is where
  unpredictability (and probability) enters.

> **The whole game:** keep S-boxes **inactive** for as long as possible. An
> inactive S-box is a free round.

---

## 4. The S-box is where all the uncertainty lives

- **Difference distribution table (DDT).** For an input difference `δ`, look at
  every possible input value `x` and record the output difference
  `SB[x] ⊕ SB[x⊕δ]`. Tallying those gives one **row** of the DDT. It tells you
  which output differences are possible for that input difference, and how likely
  each is.

**Experiment 2 — read a DDT row.**

```python
row = L.ddt_row(0x01, L.SB1)
print(len(row), max(row.values()))
# 128 2
```

128 distinct output differences, each occurring exactly twice (out of 256 values
of `x`). Twice because `x` and `x⊕δ` are the same *pair*, counted from both ends.
So each possible output difference has probability `2/256 = 1/128`. Nothing here
is unusually strong or weak — this S-box has no glaring differential weakness.

### The structural property that shapes everything

This cipher's S-box is built so that **each of the 4 output bytes is an
independent permutation** of the input byte. A permutation is a perfect one-to-one
shuffle: different inputs always give different outputs. So for *any* nonzero
input difference, **every one of the 4 output bytes differs too**:

**Experiment 3 — the S-box never emits a zero difference byte.**

```python
L.zero_output_diff_bytes(L.SB1)     # exhaustive over all 255*256 (delta, x)
# 0
```

Zero out of 65,280 cases produce even a single zero byte in the output
difference. Remember this — in §6 it does something surprising, and then
something *more* surprising.

---

## 5. Your first characteristic: the free ride

- **Characteristic (or trail):** a chosen sequence of round-by-round differences,
  together with the probability that a real pair follows it.

Now the fun part. Only `lo`'s lowest byte feeds the S-box. So if we put our
difference somewhere that takes a long time to *become* that byte, the S-box stays
inactive and we get free rounds.

**Exercise (do this by hand first).** Put a one-byte difference in state byte 6
(that's byte 2 of `hi`). Each round: `hi` is XORed (difference unchanged, since
the S-box is inactive), `lo` rotates, then the halves swap. Track where that
single difference byte sits, and predict the first round where it lands in `lo`'s
lowest byte.

**Experiment 4 — check yourself.**

```python
p1, p2 = L.pair(bytes.fromhex("0011223344556677"), byte_pos=6, delta=0x40)
L.show_diff_trace(p1, p2, k)
```

```
round  octet  S-box   in_diff   state difference
   0      0   inactive  00       0000000000004000
   1      0   inactive  00       0000400000000000
   2      0   inactive  00       0000000040000000
   3      0   inactive  00       4000000000000000
   4      0   inactive  00       0000000000400000
   5      0   inactive  00       0040000000000000
   6      0   inactive  00       0000000000000040
   7      0   ACTIVE    40       0000004000000000
   8      1   ACTIVE    fb       922dc9fb00004000
   9      1   ACTIVE    02       1674cd02c9fb922d
  ...
```

Watch it: a lone `40` byte wanders around the state for seven rounds, S-box
**inactive** the whole way, until round 7 — where it finally lands in the lookup
byte. One round later the difference has exploded into four nonzero bytes
(`922dc9fb`) and diffusion has begun.

Compare a difference placed in state byte 3 (already the lookup byte):

```python
q1, q2 = L.pair(bytes.fromhex("0011223344556677"), byte_pos=3, delta=0x40)
L.active_rounds(q1, q2, k)     # [0, 1, 2, ..., 15]  -- active immediately
L.active_rounds(p1, p2, k)     # [7, 8, 9, ..., 15]  -- 7 free rounds
```

**This is a probability-1 characteristic over seven rounds.** Measured over 4
million random pairs (random base texts, random nonzero one-byte differences at
byte 6):

```
round  0..6 : inactive in 4000000/4000000 pairs   -> free ride, always
```

Free rounds that cost no probability are gold. Half the cipher is already gone.

---

## 6. Cancellation — and a trap worth falling into

Seven free rounds, nine to go, and the difference is now spread over both halves.
To make progress we need the S-box to go **inactive again**, later.

- **Cancellation:** an S-box output difference lands on a byte that *already*
  carries a difference, and the two XOR to zero — making some later round's
  lookup byte difference-free, i.e. inactive again.

Now, a tempting argument. We proved in §4 that this S-box **never** produces a
zero output-difference byte. Doesn't that mean cancellation is impossible, and the
whole differential approach is dead?

**Run the measurement before you decide.**

**Experiment 5 — per-round inactivity probability.** (4 million pairs, one-byte
difference at byte 6.)

```
  round  0..6 : 4000000/4000000  -> always (free ride)
  round  7:          0/4000000   -> IMPOSSIBLE
  round  8:          0/4000000   -> IMPOSSIBLE
  round  9:          0/4000000   -> IMPOSSIBLE
  round 10:      15791/4000000   -> 1/253.3
  round 11:      15493/4000000   -> 1/258.2
  round 12:      15683/4000000   -> 1/255.1
  round 13:      15479/4000000   -> 1/258.4
  round 14:      15701/4000000   -> 1/254.8
  round 15:      15524/4000000   -> 1/257.7
```

Both halves of the argument are visible at once, and this is the lesson:

**Rounds 7–9: genuinely impossible.** Zero out of four million. And the reason is
exactly the §4 property. At round 7 the difference enters a half whose difference
was still **zero**, so the incoming byte difference there is 0 — and cancelling
against 0 would require the S-box output difference byte to *be* 0. It never is.
So no cancellation, guaranteed.

**Rounds 10 onwards: about 1/256 each.** From here the difference lives in *both*
halves, so the byte we want to zero out already has a **nonzero** difference.
Cancelling no longer needs a zero output difference — it just needs the S-box
output difference byte to **equal** the difference already sitting there. One byte
matching one byte: probability `1/256`. Exactly what we measure.

> **The trap:** "the S-box never outputs a zero difference byte" (true) is *not*
> "differences can never cancel" (false). Cancellation happens against a
> **nonzero** difference. Confusing the two makes you conclude a cipher is immune
> when it isn't.
>
> This is not hypothetical: an earlier draft of this repository's analysis made
> exactly that error, searched only for *sparse* trails (one active S-box,
> cancelling immediately), found none, and wrongly declared the differential route
> dead. The trail the real attack uses is not sparse — it lets the difference
> diffuse, then asks for cancellations deep in the second octet.

---

## 7. The attack's characteristic, and how much data it needs

The intended attack asks for the S-box to be inactive at **round 12 and round
14**. From the table, each is about `1/256`, so if they're independent the pair
should follow the whole trail with probability about `1/256 × 1/256 = 1/65,536`.

**Experiment 6 — measure it.** (Needs numpy; this is a rare event.)

```python
L.measure_joint_fast(rounds=(12, 14), trials=2_000_000)
```

Pooled over 5 random keys, 6 million pairs each — 30 million pairs total:

```
  key 84739eeca556bc6b:  96/6000000 -> 1/62500
  key b1f1126de16f3a9a:  98/6000000 -> 1/61224
  key f9e30d6074011659:  83/6000000 -> 1/72289
  key 94a57aa363f8eb4b:  98/6000000 -> 1/61224
  key 0a7a096a1656a93b:  89/6000000 -> 1/67416

POOLED: 464/30000000 -> 1/64655 = 2^-15.98   (68% CI 1/61787 .. 1/67803)
```

`2^-15.98` against a prediction of `2^-16`. The two cancellations really are
independent, and — worth noting — the probability does **not** depend on the key,
as §1 promised.

*(A methodological aside, since you'll hit this yourself: a single 2-million-pair
run of this gave `1/83,333`, and a single 10-million-pair run gave `1/59,880`.
Both are just Poisson noise on a couple of dozen hits. With rare events, pool
until your error bars are small enough to distinguish the hypotheses you care
about — here, `2^-16` vs anything else.)*

- **Right pair:** a pair that actually follows the characteristic. **Wrong pair:**
  one that doesn't.

So: with `N` pairs you expect `N / 65,000` right pairs. The intended attack uses
768 base plaintexts × 255 one-byte differences ≈ **195,840 pairs**, giving
`195840 / 64655 ≈ 3.0` right pairs. That's the entire reason for that data
volume — it isn't arbitrary, it's `≈ 3 / 2^-16`.

**Exercise.** How many pairs for ~10 right pairs? Would asking for cancellation at
rounds 12, 13 *and* 14 help or hurt? (Answers at the end.)

---

## 8. From "I can spot right pairs" to "I have the key"

Here's the objection that trips everyone up:

> In §1 we proved the key **cancels** in any difference. The key here appears
> *only* in XOR whitening. So differences are completely blind to it. How can a
> differential attack possibly recover the key?

The objection is correct as far as it goes, and it's worth taking seriously: a
pure differential **distinguisher** — "this cipher's ΔC isn't random" — genuinely
cannot point at the key.

**The resolution: differences find the pairs; values find the key.**

A right pair is one where you *know something about the internal state* — namely
that certain rounds were inactive, i.e. certain internal bytes were **equal**.
That's a constraint on internal **values**, not on differences. And the last
whitening step says

```
ciphertext byte = internal value ⊕ key byte
   ==>   key byte = internal value ⊕ ciphertext byte
```

So the moment you pin an internal value, a key byte falls out by XOR. The
difference was only ever the *filter* that told you which pairs are worth
inspecting.

Concretely, the intended solution:

1. **Filter.** For each pair, use the observed ciphertext difference to look up —
   in a precomputed ~1.08-billion-row table over
   `ror(SB[i]^SB[j],16) ^ (SB[k]^SB[l]) → (i,j,k,l)` — which S-box input pairs
   could have produced it. Most pairs produce no consistent entry and are thrown
   away immediately.
2. **Reconstruct.** For survivors, enumerate the few still-unknown middle bytes,
   keeping only assignments where the required cancellations actually hold.
3. **Vote.** Each consistent assignment yields all 8 key bytes by the XOR above.
   Cast a vote. Wrong pairs and wrong guesses scatter their votes; the ~3 right
   pairs all vote for the *same* key. Take the most common vote.

- **Signal-to-noise:** the ratio of right-pair votes for the true key to the
  background of wrong votes. Voting works whenever the true key's count sticks out
  of that background — which is why a handful of right pairs is enough even though
  the vast majority of pairs are noise.

This "guess a bit of key, check whether the difference behaves as predicted, keep
the guesses that survive" shape is the standard endgame of differential attacks;
you'll meet it as **last-round counting** in the literature.

---

## 9. Where differential stops here — and what beats it

Worth seeing, because it shows how to *think past* a technique you just learned.

Look again at the single most valuable thing we found: **a byte-6 perturbation
rides the entire first octet for free.** The differential attack spends that gift
on a *probabilistic* trail, and then pays `2^-16` for two lucky cancellations.

But that free ride is a fact about **byte 6**, not about *differences*. So it
applies just as well to a different technique — **saturation**:

- **Saturated byte:** instead of two texts, take a whole *set* of texts where one
  byte runs through all 256 values and everything else is fixed.
- **Balanced:** a byte position is balanced over a set if XOR-ing that byte across
  every text in the set gives 0. A saturated byte is balanced
  (`0⊕1⊕…⊕255 = 0`), and these permutation S-boxes preserve balance.

Saturating byte 6 makes the round-0..6 lookup bytes *constant* across the whole
set — the same seven free rounds, but now **deterministic**: no luck required.

**Experiment 7 — see it.**

```python
k = L.random_key(); base = L.random_block()
s1 = L.saturate(base, [6])          # 256 texts
for r in (9, 10, 11):
    print(r, L.balanced_bytes_after_round(s1, k, r))
# 9  [0, 1, 2, 3, 4, 5, 6, 7]
# 10 [4, 5, 6, 7]
# 11 []

s2 = L.saturate(base, [2, 6])       # 65536 texts
for r in (10, 11):
    print(r, L.balanced_bytes_after_round(s2, k, r))
# 10 [0, 1, 2, 3, 4, 5, 6, 7]
# 11 [4, 5, 6, 7]
```

With **256** texts, four bytes are still balanced after round 10 — a
*probability-1* property reaching as deep as the differential's `2^-16` trail. With
`256 × 256 = 65,536` texts it reaches a round deeper, and that is exactly enough
to run the key recovery. The result (see `SOLUTION.md` §4) is a full key recovery
from **65,536 chosen plaintexts in about 5 minutes** — 3× less data than the
differential attack, no billion-row table, and a unique answer rather than a vote.

The transferable lesson:

> When an attack depends on luck, ask what **structural** fact it is spending that
> luck on — and whether you can spend it deterministically instead.

That's not a knock on differential cryptanalysis. It's how the structural insight
was *found*: by working the differential attack until the free ride became
obvious.

---

## 10. Exercises

1. **By hand.** For a one-byte difference at state byte 6, name every round whose
   S-box is inactive, before running anything. Then check with
   `L.inactive_rounds(p1, p2, k)`.
2. **Why byte 6?** Which other single byte positions give free rounds, and how
   many? (Try all 8 with `L.first_active_round`.)
3. **Data volume.** How many pairs for ~10 right pairs on the (12,14) trail?
4. **Greedier trail.** Would requiring rounds 12, 13 **and** 14 inactive help?
5. **The impossible rounds.** Explain in one sentence why rounds 7–9 can never be
   inactive, and why round 10 can.
6. **DDT.** Is any input difference `δ` better than others for this S-box? Compare
   `max(L.ddt_row(d).values())` across all `d`.
7. **Break the free ride.** If `ROT` were `[8,8,8,8,8,8,8,8]`, would a byte-6
   difference still get 7 free rounds? Predict, then edit `L.ROT` and test.

### Solutions

1. Rounds **0–6** inactive, first active at **7**. Rounds 8–15 are then active
   unless a cancellation happens (~1/256 each from round 10).
2. Measured `first_active_round` for a difference at each byte position:

   | byte | 3 | 7 | 1 | 5 | 0 | 4 | 2 | 6 |
   |---|---|---|---|---|---|---|---|---|
   | first active round | 0 | 1 | 2 | 3 | 4 | 5 | 6 | **7** |

   Every position gives a *different* number of free rounds, 0 through 7 — the
   rotation schedule spreads them out perfectly. It is **not** simply "`hi` bytes
   are good": byte 2 (in `lo`) beats bytes 4, 5 and 7 (all in `hi`). Byte 6 is
   uniquely the best at 7 free rounds, and byte 2 is second at 6.

   This also answers something the integral attack found only by brute-force
   search: of all 28 two-byte choices, only `{2, 6}` reaches the deepest balance —
   because 6 and 2 are precisely the *two best* positions.
3. `10 × 64,655 ≈ 650,000` pairs.
4. It **hurts**. Each extra required cancellation costs another factor ~1/256, so
   the trail probability drops to ~`2^-24` and you'd need ~256× more data. You
   want the *fewest* constraints that still pin the key.
5. At rounds 7–9 the target byte's difference is still zero, so cancelling would
   need a zero S-box output-difference byte, which never occurs; by round 10 the
   difference has reached both halves, so you cancel against a nonzero byte, which
   happens with probability 1/256.
6. No. Every row has max count 2 — uniformly "boring", which is exactly what a
   well-built S-box looks like. The weakness in this cipher is *structural* (the
   free ride), not in the DDT.
7. **Byte 6 loses it, but the ride doesn't disappear — it moves.** With
   `ROT = [8]*8` the measured first-active rounds become

   | byte | 3 | 7 | 6 | 1 | 5 | 0 | 2 | 4 |
   |---|---|---|---|---|---|---|---|---|
   | first active round | 0 | 1 | 2 | 3 | 4 | 5 | 6 | **7** |

   Byte 6 drops from 7 free rounds to 3 — but byte **4** now has 7. So changing the
   schedule relabels which byte is the good one without removing the weakness. The
   real lesson is sharper than "this schedule has a hole": with one byte feeding
   the S-box and only rotations to move data, *some* input byte will always take
   the maximum number of rounds to arrive. The fix has to change the diffusion,
   not just the rotation amounts.

---

## 11. Where to go next

- **In this repo:** `SOLUTION.md` §2 for the intended differential attack in
  detail, §3–4 for the integral attack that beats it, `symtrace.py` for the
  symbolic tracer that derives the S-box chains, and `WRITEUP.md` for a gentler
  full walkthrough.
- **The classic:** Biham & Shamir, *Differential Cryptanalysis of the Data
  Encryption Standard* (1993) — the origin, and where "characteristic",
  "right pair" and the counting endgame come from. Their Khafre attack is the
  direct ancestor of the attack here.
- **The natural sequel:** *linear* cryptanalysis (Matsui) — same spirit, but
  tracking biased linear approximations instead of differences.
- **The technique that beat it here:** integral / "Square" attacks (Daemen,
  Knudsen, Rijmen) — differences replaced by structured *sets*, as in §9.

### A note on ethics and scope

This is a CTF challenge and a 1989 cipher, published for study, attacked here on
keys we generate ourselves. Cryptanalysis is how ciphers earn trust — Khafre is
interesting *because* it was analysed. Practise on targets you own or that are
published for the purpose.
