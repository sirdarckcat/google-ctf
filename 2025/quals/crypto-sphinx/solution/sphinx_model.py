"""Clean reimplementation of the sphinx (Khafre) cipher + offline R0/R1 helpers."""
import struct, importlib.util, sys, os

MASK = 0xFFFFFFFF
ROT = [16, 16, 8, 8, 16, 16, 24, 24]

def rol(x, r): return ((x << r) & MASK) | (x >> (32 - r)) if r else x & MASK
def ror(x, r): return ((x >> r) | (x << (32 - r))) & MASK if r else x & MASK

# ---- load the original obfuscated module to steal the (fixed) sboxes ----
def load_orig():
    spec = importlib.util.spec_from_file_location("sphinx_core", "/tmp/sphinx/sphinx_core.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

_ORIG = load_orig()
# find the two classes
_classes = [v for v in vars(_ORIG).values() if isinstance(v, type)]
def _find_cipher():
    for c in _classes:
        try:
            inst = c(b"\x00"*8)
            return c
        except TypeError:
            continue
    raise RuntimeError("cipher class not found")
CipherOrig = _find_cipher()

def _orig_methods():
    # encrypt: 3 positional params beyond self ; decrypt: 1
    enc = dec = None
    for name, fn in vars(CipherOrig).items():
        if not callable(fn): continue
        try:
            n = fn.__code__.co_argcount
        except AttributeError:
            continue
        if n == 4 and enc is None: enc = name
        elif n == 2 and dec is None: dec = name
    return enc, dec
ENC_NAME, DEC_NAME = _orig_methods()

# Steal fixed sboxes from an instance
_inst0 = CipherOrig(b"\x00"*8)
SBOXES = _inst0.__dict__[[k for k in _inst0.__dict__ if isinstance(_inst0.__dict__[k], list) and len(_inst0.__dict__[k])==8][0]]
# SBOXES is list of 8 sboxes, each 256 ints. Only [0] and [1] used for rounds=16.

def bits_to_int(b): return list(struct.unpack(">%dI" % (len(b)//4), b))
def int_to_bits(l): return struct.pack(">%dI" % len(l), *l)

def R_forward(lo, hi, sbox):
    # NOTE: the obfuscated encrypt uses ROR here (homoglyph trap), not ROL.
    for r in range(8):
        hi = (hi ^ sbox[lo & 0xff]) & MASK
        lo = ror(lo, ROT[r])
        lo, hi = hi, lo
    return lo, hi

def R_inverse(lo, hi, sbox):
    for r in reversed(range(8)):
        lo, hi = hi, lo
        lo = rol(lo, ROT[r])
        hi = (hi ^ sbox[lo & 0xff]) & MASK
    return lo, hi

def enc_block(block, k0, k1):
    lo, hi = bits_to_int(block)
    # W0
    lo ^= k0; hi ^= k1
    lo, hi = R_forward(lo, hi, SBOXES[0])
    # W1
    lo ^= ror(k0,1); hi ^= ror(k1,1)
    lo, hi = R_forward(lo, hi, SBOXES[1])
    # W2
    lo ^= ror(k0,2); hi ^= ror(k1,2)
    return int_to_bits([lo & MASK, hi & MASK])

def dec_block(block, k0, k1):
    lo, hi = bits_to_int(block)
    lo ^= ror(k0,2); hi ^= ror(k1,2)
    lo, hi = R_inverse(lo, hi, SBOXES[1])
    lo ^= ror(k0,1); hi ^= ror(k1,1)
    lo, hi = R_inverse(lo, hi, SBOXES[0])
    lo ^= k0; hi ^= k1
    return int_to_bits([lo & MASK, hi & MASK])

if __name__ == "__main__":
    import random
    print("ENC_NAME=", ENC_NAME, "DEC_NAME=", DEC_NAME)
    enc = getattr(CipherOrig, ENC_NAME)
    dec = getattr(CipherOrig, DEC_NAME)
    ok = True
    for _ in range(2000):
        key = os.urandom(8)
        k0, k1 = bits_to_int(key)
        inst = CipherOrig(key)
        pt = os.urandom(8)
        c_orig = enc(inst, pt)
        c_mine = enc_block(pt, k0, k1)
        if c_orig != c_mine:
            print("ENC MISMATCH", pt.hex(), key.hex(), c_orig.hex(), c_mine.hex()); ok=False; break
        # decrypt check
        d_orig = dec(inst, c_orig)
        d_mine = dec_block(c_orig, k0, k1)
        if d_orig != pt or d_mine != pt:
            print("DEC MISMATCH", d_orig.hex(), d_mine.hex(), pt.hex()); ok=False; break
    print("ALL OK" if ok else "FAILED")
