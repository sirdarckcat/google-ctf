# Is there a precomputable asset worth hosting?

Short answer: exactly one, and it buys a clean 1.94x on the full sweep for a 232 MB
download. It does nothing for the lucky button, and it cannot be used from the
hosted artifact at all.

## What in this attack is key-independent

Only things derived from the S-boxes, which are fixed and public:

| asset | size | cost to build locally | worth fetching? |
|---|---|---|---|
| the two S-boxes | 2 KB | instant | already inlined |
| `g5`, `g7` tables | 16 MB each | ~35 ms each | **no** — a 32 MB fetch to save 70 ms is far slower |
| **FWHT of the 16 `g5`/`g7` bit-planes** | 64 MB each as uint32 | ~0.3-1 s each, **every step** | **yes** |

Everything else — the parity histogram, the balance table, the candidates — depends
on the ciphertexts and therefore on the key. Nothing there can be precomputed.

## Why the transformed planes are the whole story

A step costs 33 transforms:

    1  forward transform of the histogram        depends on the data
    16 x  transform of a g bit-plane             key-independent, identical every step
    16 x  transform of the product               depends on the data

Those middle 16 are recomputed 256 times over for no reason. Precomputing them
takes a step from 33 transforms to 17 — a factor of **1.94**, which is exactly why
the native C solver holds them in RAM (1 GB) and reaches ~5 min where the browser
needs ~58.

    Pixel 9 Pro, 295 ms per transform:
      33 transforms/step  ->  42 min for the 256-step sweep
      17 transforms/step  ->  21 min

## Size, measured rather than assumed

A transformed bit-plane has rms 2896, so almost everything fits in 16 bits:

    fits int8   : 35.0%
    fits int16  : 99.998%     7729 exceptions across all 16 planes
    fits int24  : 100%        (one value per plane is 2^23, the DC term)

So store int16 plus a ~60 KB sidecar of exceptions, and gzip:

    per plane   32 MB int16  ->  14.6 MB gzipped   (7.0 bits per value)
    16 planes  512 MB int16  ->  232 MB gzipped

Sign-extending int16 to uint32 reproduces the value exactly mod 2^32 for the
99.998%, which is all the attack needs — it only reads bit 24 of the final result.

Download against 21 minutes saved:

    25 Mbps   74 s
    100 Mbps  19 s
    500 Mbps   4 s

## It degrades gracefully

Nothing forces all 16. Fetch *k* planes and a step costs `33 - k` transforms, so the
benefit is proportional to what you were willing to download. Eight planes is 116 MB
for 1.32x. That makes it a reasonable thing to gate behind a button.

## Three reasons it is not obviously worth building

1. **It does nothing for the lucky button.** One step is 3-10 s of compute against a
   19-74 s download, so precomputation makes the headline path *slower*. It only
   helps the 256-step sweep, which exists to show how expensive the real attack is.
2. **512 MB resident**, on top of ~192 MB of working arrays. Fine on a desktop,
   uncomfortable on a phone even with 16 GB.
3. **The hosted artifact cannot fetch it.** That page runs under a CSP that blocks
   every external host, so this only works in the self-hosted build.

## If it were built

Serve from GCS with `Content-Encoding: gzip` so the browser inflates transparently,
`Cache-Control: public, max-age=31536000, immutable` since the S-boxes never change,
and `Access-Control-Allow-Origin` for the cross-origin fetch. Fetch the planes in
parallel, keep them as int16 and widen during the pointwise multiply, and patch the
7729 exceptions from the sidecar before first use.

## What SharedArrayBuffer would change

Not what I first assumed. Parallel scaling is **not** the problem: measured with
startup excluded, independent 2^24 transforms scale 1.81x on two workers and 3.35x
on four, and the real sweep went 9.90 s/step on one worker to 2.93 s/step on four —
42 min down to 13 min. Workers already scale fine without SAB.

What SAB actually buys is that it makes precomputation **composable with**
parallelism. The 512 MB of transformed planes is read-only, so with SAB it is stored
once; without it, every worker needs its own copy and four workers would want 2 GB
of planes alone. That is the difference between the two optimisations multiplying
and being mutually exclusive:

    baseline, 1 worker                       42 min
    + 4 workers                              13 min   (3.38x, measured)
    + precomputed planes, no SAB             not possible: 4 x 512 MB
    + precomputed planes, with SAB          ~6.5 min  (a further 1.94x)

~6.5 min is roughly what the native C solver achieves, which is the point: the
native advantage *is* shared memory plus shared precomputed tables. SAB is what lets
a browser do the same thing.

Secondary benefits: the g5/g7 tables (32 MB per worker today) would also be shared,
and the kernel could use real WASM threads via `-matomics --shared-memory` instead of
one module instance per worker — tidier, though not faster on its own.

### The catch is hosting

SAB needs `crossOriginIsolated`, which needs two response headers:

    Cross-Origin-Opener-Policy: same-origin
    Cross-Origin-Embedder-Policy: require-corp

Measured `crossOriginIsolated: false` in every run so far. And:

* **GitHub Pages** cannot set custom headers, so SAB is impossible there.
* **Plain GCS static hosting** cannot either. You would need GCS behind Cloud CDN or
  a Load Balancer with a response-header policy, or Firebase Hosting, or Cloud Run.
* The hosted artifact is iframed and its CSP blocks external hosts, so neither the
  232 MB asset nor SAB is reachable from it.

Which makes the two answers converge: the same hosting move that lets you serve the
precomputed planes is the one that can set COOP/COEP — and the planes are only worth
serving if SAB exists to share them. Do both or neither.

## The shape of the answer

The precomputable objects are either too cheap to be worth a request (S-boxes,
`g5`/`g7`) or large enough that the download competes with the work saved. 232 MB
for 1.94x sits right at that boundary — a good trade on a desktop doing the full
sweep, a bad one everywhere else.
