# Service worker -> cross-origin isolation -> SharedArrayBuffer

A service worker can synthesise response headers the host never sent. That turns out
to be the enabling trick for the fastest browser version of this attack, and it works
on a static host with no configuration at all.

## Verified, not assumed

`serve.js` deliberately serves with **no** `Cross-Origin-Opener-Policy` and **no**
`Cross-Origin-Embedder-Policy`, standing in for GitHub Pages. `sw.js` intercepts each
fetch and re-emits the response with both headers set. Run it:

    node serve.js        # then open http://localhost:8099/

Measured result:

    crossOriginIsolated : true
    SharedArrayBuffer   : true
    controlled by SW    : true
    worker wrote through the shared buffer: true
      view[0] = 0xc0ffee   Atomics.load(view,1) = 42

So a page can be cross-origin isolated, and use `SharedArrayBuffer` and `Atomics`
across workers, on a host that cannot set a single header.

## Why that matters here

The sweep spends 16 of its 33 transforms per step re-transforming the `g5`/`g7`
bit-planes, which are key-independent and identical for all 256 steps. Keeping them
costs 512 MB. Without shared memory that is 512 MB *per worker*, so retaining them
and using several workers are mutually exclusive. With `SharedArrayBuffer` it is one
copy.

    baseline, 1 worker                  42 min
    + 4 workers                         13 min    3.38x, measured
    + retained planes, no SAB           not possible: 4 x 512 MB
    + retained planes, with SAB        ~6.5 min   a further 1.94x

~6.5 min is about what the native C solver achieves, which is the point: the native
advantage *is* shared memory plus retained tables.

## And it kills the case for hosting a precomputed asset

Building all sixteen transformed planes from scratch takes **3.59 s**
(`../gpu/buildplanes.c`), against 4-74 s to download 232 MB of them depending on the
link. Computing locally wins outright.

An earlier version of `../gpu/PRECOMPUTE.md` argued for the download by comparing it
against *re-transforming every step*. That was the wrong comparison. The right one is
against *computing once and keeping them*, and then the download never pays. The
bottleneck was never the arithmetic — 221 ms per plane — it was having somewhere to
put 512 MB. Shared memory is the answer, not a CDN.

## Wired into the lab, and measured

`../index.html` + `../sw.js` are the deployable pair; drop both in one directory on any
static host. Measured on the same machine, one sweep worker, lucky button:

    not isolated   33 transforms/step   ~14 s per step
    isolated       17 transforms/step    ~7 s per step   + 9 s one-off to build the planes

Verified against a server sending **no** isolation headers, i.e. the GitHub Pages case:
one automatic reload, then `crossOriginIsolated: true`, `SharedArrayBuffer: true`, and
the panel reports "cross-origin isolated — shared transform planes on". Full attack
under isolation completed in 11 s against 21-32 s without, key recovered and target
decrypted both ways.

Projected for the full 256-step sweep, from two separately measured factors — 3.38x
across four workers and 1.94x from retained planes:

    1 worker,  no planes    42 min
    4 workers, no planes    13 min   (measured)
    4 workers, planes      ~6.4 min  (projected)

The planes are held as int16 in one `SharedArrayBuffer` (512 MB) plus a 75 KB sidecar
for the 7729 values that do not fit; sign extension reproduces the rest exactly mod
2^32, which is all the attack reads. The pointwise multiply happens in JS straight
from the shared buffer into the worker's wasm memory, which avoids needing wasm shared
memory at all — and replaces a 24-pass transform with a single pass.

## Caveats

* The first load is not isolated; the page must register the worker and reload once
  before `crossOriginIsolated` becomes true. Handle both states rather than assuming.
* `COEP: require-corp` requires every subresource to opt in. Harmless here because the
  lab is a single file with no external references, but it would break a page that
  pulls in third-party assets.
* Needs a secure context, so https or localhost.
* Not usable from the hosted artifact, which is iframed and under a CSP that blocks
  external hosts. This is for the self-hosted build.
* A service worker is the wrong place to *run* the attack. It is there to rewrite
  headers, and browsers are free to terminate idle workers.
