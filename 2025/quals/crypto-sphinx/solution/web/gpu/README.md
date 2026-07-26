# WebGPU feasibility probe

Two builds of the same probe, both self-contained (no network, no dependencies):

* `webgpu-bench.html` — a complete standalone document: doctype, viewport, wasm
  inlined as base64, no external references at all. Suitable for opening from disk
  **or dropping straight into a GitHub Pages repo**, which is the best option: a
  top-level HTTPS page rules out both of the context problems below in one move.
* `gpu-bench-artifact.html` — the same page with the document wrapper stripped, for
  publishing as a hosted artifact. Deployed at
  <https://claude.ai/code/artifact/7af5cd78-5f92-489f-b151-771e4f9bddf2>, which is
  the easier route on a phone: a URL opens in Chrome proper, whereas a downloaded
  file tends to land in an in-app WebView where neither WebGPU nor wasm is
  available.

Open either, let it run, press **Copy all output**.

## What it measures

The attack's inner loop is a **2^24-point uint32 Walsh–Hadamard transform**, and that
transform is almost pure memory traffic — one add and one subtract per two words, so
roughly 0.25 arithmetic ops per byte. That profile is why the GPU is worth probing.

It runs, on the same machine:

1. **CPU baseline** — the identical transform compiled to `wasm32 -msimd128`
   (`fwbench.c`, inlined as base64), single-threaded.
2. **GPU naive** — one dispatch per butterfly stage: 24 global passes.
3. **GPU blocked (WebGPU)** — eight stages per dispatch held in workgroup memory, so
   24 global passes collapse to 3. This is where the biggest win should come from:
   traffic drops ~8x *before* raw bandwidth even enters.
3b. **WebGL2** — the fallback that actually runs almost everywhere. No compute
   shaders and no shared memory, so the transform becomes one fragment pass per
   butterfly stage, ping-ponging two `RGBA32UI` textures. Each texel holds four
   consecutive elements, which lets stages 0 and 1 happen inside the texel. GLSL ES
   3.00 guarantees `uint` is 32 bits and wraps mod 2^32, so the arithmetic is exact
   — confirmed by the checksum matching the CPU. It cannot do the 8-stage blocking,
   so it leaves roughly 8x on the table versus a good WebGPU implementation, but on
   a device where WebGPU has no adapter it is the only option that produces a
   number.
4. **GPU linear pass** — a plain pointwise kernel, to price the non-transform work.

Then it projects one attack step (~33 transforms + ~50 linear passes) and the full
256-step sweep.

## Why the timing needed fixing

The first WebGL2 run reported 0.4 ms and "8053 GB/s" on a *software* rasteriser,
which is impossible. `gl.finish()` returns once Chrome's command buffer is flushed,
not once the GPU has finished, so the work was deferring past the timer and only
completing at the later readback. Timing is now taken to a synchronous 1x1
`readPixels`, which forces the pipeline to drain. The same run then reported 1326 ms
— slower than the CPU, which is exactly what a software rasteriser should be, and
therefore believable.

A fast wrong *timing* is as useless as a fast wrong answer, and is harder to notice
because the checksum still passes.

## Why the checksum matters

Both GPU variants are checked against the CPU checksum and reported as
`MATCHES CPU` / `DOES NOT MATCH CPU`. A fast wrong answer is worthless, and the
blocked variant's index arithmetic is fiddly enough to be worth verifying rather
than trusting. The checksum deliberately folds high bits down: FWHT outputs
accumulate factors of two, so the low bits go to zero and a naive hash would be
insensitive to exactly the bits the attack reads (bit 24).

## Where it will NOT work (learned the hard way)

- **Android WebView / in-app browsers.** `navigator.gpu` is undefined there, and the
  host app's CSP is typically `script-src 'unsafe-inline'` with no
  `wasm-unsafe-eval`, which also blocks `WebAssembly.instantiate`. A real run from a
  Pixel 9 Pro WebView produced no GPU data and no wasm baseline. The page now
  detects the WebView user-agent and says so with instructions instead of just
  reporting two blank sections.
- **Fallback:** when wasm is blocked the CPU baseline runs as plain JavaScript over
  a `Uint32Array` instead. Verified bit-identical to the wasm path (same checksum
  `0x6d2635fe`), about 2.1x slower here (531 ms vs 248 ms), so a GPU speedup
  measured against it is a *lower bound*. Force this path with `?nowasm=1` to test
  it.
- **Undersized devices:** if the adapter reports `maxStorageBufferBindingSize` or
  `maxBufferSize` below 64 MiB the page stops and prints both numbers rather than
  running scaled index arithmetic that has never been tested. Send those two
  numbers and a correctly sized variant can be built.

Use Chrome/Edge proper, ideally on desktop — that is where the 58-minute sweep
would actually run.

## Caveats it will surface for you

- `maxStorageBufferBindingSize` baseline is 128 MiB and `maxBufferSize` 256 MiB. The
  buffer here is 64 MiB, so it fits — but the page prints the real limits and asks
  for raised ones if needed, reporting any refusal.
- `navigator.gpu` absent, or `requestAdapter()` returning null, is reported plainly
  rather than thrown. Confirmed working: in the sandbox this repo was built in,
  `navigator.gpu` exists but there is no adapter, and the page says so and still
  reports the CPU baseline.
- Validation errors are captured three ways: an `uncapturederror` listener,
  `pushErrorScope`/`popErrorScope` around pipeline creation and each submit, and
  `window.onerror` / `unhandledrejection`. Shader compilation messages are printed.

## Reference numbers from the build sandbox (CPU only, 4 cores, no GPU)

    isolated 2^24 transform      ~197 ms   (~16 GB/s effective)
    inside the full kernel       ~410 ms   (H and T compete for cache)
    one attack step              13.7 s
    full 256-step sweep          58 min, 1 core

If the blocked GPU variant lands in the single-digit-milliseconds range and matches
the CPU checksum, the sweep moves from tens of minutes to well under a minute.
