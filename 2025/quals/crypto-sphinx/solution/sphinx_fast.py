import numpy as np, os
import sphinx_model as clean
SB=[np.array(clean.SBOXES[i],dtype=np.uint32) for i in range(8)]
ROT=clean.ROT
M=np.uint32(0xFFFFFFFF)
def rol(x,r):
    if r==0: return x
    return ((x<<np.uint32(r))|(x>>np.uint32(32-r)))
def ror(x,r):
    if r==0: return x
    return ((x>>np.uint32(r))|(x<<np.uint32(32-r)))

def enc_vec(lo,hi,k0,k1):
    """lo,hi: uint32 arrays. k0,k1 python ints. returns (clo,chi)."""
    lo=lo.copy()^np.uint32(k0); hi=hi.copy()^np.uint32(k1)
    for r in range(8):
        hi=hi^SB[0][(lo&np.uint32(0xff))]
        lo=ror(lo,ROT[r]); lo,hi=hi,lo
    lo=lo^np.uint32(clean.ror(k0,1)); hi=hi^np.uint32(clean.ror(k1,1))
    for r in range(8):
        hi=hi^SB[1][(lo&np.uint32(0xff))]
        lo=ror(lo,ROT[r]); lo,hi=hi,lo
    lo=lo^np.uint32(clean.ror(k0,2)); hi=hi^np.uint32(clean.ror(k1,2))
    return lo,hi

# trail templates for dP=hi byte2: from buildtrail, cipher zeros at indices [0,1,3,6]
# i.e. clo bytes: b0(idx0)=0,b1(idx1)=0,b2(idx2)=X,b3(idx3)=0 ; chi: b4(idx4)=X,b5(idx5)=X,b6(idx6)=0,b7(idx7)=X
# So filter: dC has clo&0xFF00FFFF... let's define mask of zero bytes.
ZERO_BYTES=[0,1,3,6]  # state byte indices that must be zero in ciphertext XOR

def main():
    K0,K1=clean.bits_to_int(os.urandom(8))
    rng=np.random.default_rng(0)
    NS=200000   # structures
    found=[]
    # zero-byte mask for lo and hi
    # lo bytes idx0..3 -> shifts 24,16,8,0 ; hi idx4..7 -> shifts 24,16,8,0
    lozero=[b for b in ZERO_BYTES if b<4]; hizero=[b-4 for b in ZERO_BYTES if b>=4]
    lomask=0
    for b in lozero: lomask|=0xff<<(8*(3-b))
    himask=0
    for b in hizero: himask|=0xff<<(8*(3-b))
    import time; t=time.time()
    total=0
    for s in range(NS):
        # structure: fix 7 bytes random, vary b6 (hi byte2 -> hi bits 8-15) over 0..255
        base_lo=int(rng.integers(0,2**32)); base_hi=int(rng.integers(0,2**32)) & ~0x0000ff00
        vals=np.arange(256,dtype=np.uint32)
        lo=np.full(256,base_lo,dtype=np.uint32)
        hi=(np.uint32(base_hi)|(vals<<np.uint32(8)))
        clo,chi=enc_vec(lo,hi,K0,K1)
        # find pairs colliding on zero bytes: same (clo&lomask, chi&himask)
        key=( (clo&np.uint32(lomask)).astype(np.uint64)<<np.uint64(32))|(chi&np.uint32(himask)).astype(np.uint64)
        order=np.argsort(key,kind='stable')
        ks=key[order]
        # find groups
        i=0
        while i<256:
            j=i
            while j+1<256 and ks[j+1]==ks[i]: j+=1
            if j>i:
                grp=order[i:j+1]
                for a in range(len(grp)):
                    for b in range(a+1,len(grp)):
                        found.append((int(lo[grp[a]]),int(hi[grp[a]]),int(lo[grp[b]]),int(hi[grp[b]]),
                                      int(clo[grp[a]]),int(chi[grp[a]]),int(clo[grp[b]]),int(chi[grp[b]])))
            i=j+1
        total+=256
        if s%50000==0 and s: print(f'  {s} structs, {total} enc, {len(found)} candidate pairs, {time.time()-t:.0f}s')
    print(f'TOTAL: {NS} structures, {total} encryptions, {len(found)} candidate pairs in {time.time()-t:.0f}s')
    # white-box: verify which candidates are RIGHT pairs (internal trail: rounds 8-13,15 inactive)
    right=verify_right(found,K0,K1)
    print(f'RIGHT pairs among candidates: {len(right)}')
    return found,right,(K0,K1)

def enc_snap(lo,hi,K0,K1):
    lo=lo^K0; hi=hi^K1; snap=[]
    for r in range(8):
        snap.append((lo,hi)); hi=(hi^clean.SBOXES[0][lo&0xff])&clean.MASK; lo=clean.ror(lo,ROT[r]); lo,hi=hi,lo
    lo^=clean.ror(K0,1); hi^=clean.ror(K1,1)
    for r in range(8):
        snap.append((lo,hi)); hi=(hi^clean.SBOXES[1][lo&0xff])&clean.MASK; lo=clean.ror(lo,ROT[r]); lo,hi=hi,lo
    snap.append((lo,hi)); return snap

def verify_right(found,K0,K1):
    right=[]
    for (lo1,hi1,lo2,hi2,*_) in found:
        s1=enc_snap(lo1,hi1,K0,K1); s2=enc_snap(lo2,hi2,K0,K1)
        # active rounds = where lo low byte differs at input of round
        acts=[r for r in range(16) if ((s1[r][0]^s2[r][0])&0xff)!=0]
        if acts==[7,14]:
            right.append((lo1,hi1,lo2,hi2))
    return right

if __name__=='__main__':
    main()
