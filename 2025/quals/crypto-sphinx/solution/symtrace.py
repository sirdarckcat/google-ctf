# symbolic byte-level tracer for the inverse of the last rounds of R1
ROT=[16,16,8,8,16,16,24,24]
def X(*sets):           # xor of byte-expressions (frozensets of atoms)
    acc=frozenset()
    for s in sets: acc=acc ^ s
    return acc
def atom(a): return frozenset([a])
def show(e):
    if not e: return "0"
    return " ^ ".join(sorted(fmt(a) for a in e))
def fmt(a):
    if a[0]=='c': return "%s%d"%(a[1],a[2])
    return "S%d[%s]"%(a[1], show(a[2]))
# input state bytes after de-whitening: lo_j = C_lo j ^ W2_lo j  (call Lj), hi_j = Hj
L=[atom(('c','L',j)) for j in range(4)]
H=[atom(('c','H',j)) for j in range(4)]
for n in range(1,6):
    r=7-(n-1)
    L,H = H,L                                   # swap
    rot=ROT[r]; sh=rot//8
    L=[L[(j+sh)%4] for j in range(4)]            # rol by sh bytes: new[j]=old[(j+sh)%4]
    idx=L[3]                                    # lo & 0xff
    H=[X(H[j], atom(('S',j,idx))) for j in range(4)]
    print("=== after %d inversion(s)  (labeled round %d) ==="%(n,16-n))
    for j in range(4): print("   state byte %d (lo%d) = %s"%(j,j,show(L[j])))
    for j in range(4): print("   state byte %d (hi%d) = %s"%(4+j,j,show(H[j])))
    print()
