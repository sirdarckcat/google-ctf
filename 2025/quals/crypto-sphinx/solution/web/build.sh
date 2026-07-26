#!/bin/sh
# Build the WebAssembly lab and inline it into index.html.
# Needs clang >= 15 with the wasm32 target and wasm-ld (no emscripten required).
set -e
cd "$(dirname "$0")"

# bake the key-independent S-boxes into the module so the page is one blob
python3 - <<'PY'
import re
t = open('../sboxes.h').read()
out = ['/* baked-in key-independent Khafre S-boxes */']
for i in (0, 1):
    m = re.search(r'SB%d\[256\]\s*=\s*\{(.*?)\}' % i, t, re.S)
    vals = [v.strip() for v in m.group(1).split(',')]
    out.append('static u32 SB%d[256]={%s};' % (i, ','.join(vals)))
open('sbox_data.h', 'w').write('\n'.join(out) + '\n')
PY

clang --target=wasm32 -O3 -msimd128 -nostdlib -ffreestanding \
      -Wl,--no-entry -Wl,--export-dynamic \
      -Wl,--initial-memory=33554432 -Wl,--allow-undefined \
      -o lab.wasm lab.c

python3 - <<'PY'
import base64, re
w = base64.b64encode(open('lab.wasm','rb').read()).decode()
s = open('index.html', encoding='utf-8').read()
s = re.sub(r'const WASM_B64="[^"]*"', 'const WASM_B64="%s"' % w, s, count=1)
open('index.html','w',encoding='utf-8').write(s)
print('inlined %d bytes of wasm -> index.html (%.1f KB)' % (len(w), len(s.encode())/1024))
PY
