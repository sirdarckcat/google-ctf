/* Synthesise the two headers a static host cannot set, so the document becomes
   cross-origin isolated and SharedArrayBuffer becomes available. */
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", event => {
  if (event.request.cache === "only-if-cached" && event.request.mode !== "same-origin") return;
  event.respondWith(fetch(event.request).then(r => {
    if (r.status === 0) return r;
    const h = new Headers(r.headers);
    h.set("Cross-Origin-Embedder-Policy", "require-corp");
    h.set("Cross-Origin-Opener-Policy", "same-origin");
    return new Response(r.body, {status: r.status, statusText: r.statusText, headers: h});
  }).catch(e => { console.error(e); throw e; }));
});
