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
