/* Interactive lab kernel: cipher, difference tracing, DDT, measurement,
   integral label measurement, reduced-round key recovery. Freestanding WASM. */
typedef unsigned char u8; typedef unsigned int u32;
#define EXPORT __attribute__((visibility("default"),used))
static const int ROT[8]={16,16,8,8,16,16,24,24};
#include "sbox_data.h"
static inline u32 ror(u32 x,int r){return r?(x>>r)|(x<<(32-r)):x;}
static inline u32 rol(u32 x,int r){return r?(x<<r)|(x>>(32-r)):x;}
static inline u32 B(u32 x,int i){return (x>>(8*(3-i)))&0xff;}

static u32 OUT[64];          /* generic small return buffer */
static u32 TRACE[16*4];      /* per round: in1,in2,dlo,dhi */
static u32 CNT[20];          /* inactivity counts per round + joint */
static u32 DDT[256];
static u8  LBL[17*8];        /* measured integral labels */
static u32 SURV[4096]; static u32 nsurv;
static u32 CTLO[65536], CTHI[65536];
static u32 VCNT[17*8*256];   /* value histograms for integral labelling */
static u32 VXOR[17*8];

EXPORT u32* sb0_ptr(void){return SB0;}
EXPORT u32* sb1_ptr(void){return SB1;}
EXPORT u32* out_ptr(void){return OUT;}
EXPORT u32* trace_ptr(void){return TRACE;}
EXPORT u32* cnt_ptr(void){return CNT;}
EXPORT u32* ddt_ptr(void){return DDT;}
EXPORT u8*  lbl_ptr(void){return LBL;}
EXPORT u32* surv_ptr(void){return SURV;}

static void encrypt(u32 lo,u32 hi,u32 k0,u32 k1,u32*ol,u32*oh){
    lo^=k0; hi^=k1;
    for(int r=0;r<8;r++){hi^=SB0[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo;lo=hi;hi=t;}
    lo^=ror(k0,1); hi^=ror(k1,1);
    for(int r=0;r<8;r++){hi^=SB1[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo;lo=hi;hi=t;}
    *ol=lo^ror(k0,2); *oh=hi^ror(k1,2);
}
EXPORT void enc1(u32 lo,u32 hi,u32 k0,u32 k1){ encrypt(lo,hi,k0,k1,&OUT[0],&OUT[1]); }

/* record the S-box input byte and state at every round */
static void trace16(u32 lo,u32 hi,u32 k0,u32 k1,u32*ins,u32*slo,u32*shi){
    lo^=k0; hi^=k1;
    for(int oc=0;oc<2;oc++){
        if(oc){ lo^=ror(k0,1); hi^=ror(k1,1); }
        for(int r=0;r<8;r++){
            int idx=oc*8+r; ins[idx]=lo&0xff; slo[idx]=lo; shi[idx]=hi;
            hi ^= (oc? SB1[lo&0xff] : SB0[lo&0xff]);
            lo=ror(lo,ROT[r]); u32 t=lo;lo=hi;hi=t;
        }
    }
}
EXPORT void trace_pair(u32 lo,u32 hi,u32 lo2,u32 hi2,u32 k0,u32 k1){
    u32 i1[16],i2[16],a1[16],b1[16],a2[16],b2[16];
    trace16(lo,hi,k0,k1,i1,a1,b1);
    trace16(lo2,hi2,k0,k1,i2,a2,b2);
    for(int r=0;r<16;r++){
        TRACE[r*4+0]=i1[r]; TRACE[r*4+1]=i2[r];
        TRACE[r*4+2]=a1[r]^a2[r]; TRACE[r*4+3]=b1[r]^b2[r];
    }
}

/* xorshift32 PRNG so measurements are reproducible from a seed */
static u32 RS;
static inline u32 rnd(void){ RS^=RS<<13; RS^=RS>>17; RS^=RS<<5; return RS; }

/* P(S-box inactive) per round for a one-byte difference at plaintext byte bp */
EXPORT void measure_inactive(u32 bp,u32 trials,u32 k0,u32 k1,u32 seed){
    RS = seed?seed:0x2545F491u;
    for(int i=0;i<20;i++) CNT[i]=0;
    u32 i1[16],i2[16],a[16],b[16];
    for(u32 t=0;t<trials;t++){
        u32 lo=rnd(), hi=rnd(); u32 d=rnd()&0xff; if(!d) d=1;
        u32 lo2=lo, hi2=hi; u32 sh=8*(3-(bp&3));
        if(bp<4) lo2 ^= d<<sh; else hi2 ^= d<<sh;
        trace16(lo,hi,k0,k1,i1,a,b);
        trace16(lo2,hi2,k0,k1,i2,a,b);
        for(int r=0;r<16;r++) if(i1[r]==i2[r]) CNT[r]++;
        if(i1[12]==i2[12] && i1[14]==i2[14]) CNT[16]++;
    }
    CNT[17]=trials;
}

/* one DDT row: output differences for input difference delta */
EXPORT void ddt_row(u32 delta,u32 which){
    const u32* sb = which? SB1 : SB0;
    for(u32 x=0;x<256;x++) DDT[x]= sb[x]^sb[(x^delta)&0xff];
}

/* exhaustive check: does the S-box ever emit a zero output-difference byte? */
EXPORT u32 zero_diff_bytes(u32 which){
    const u32* sb = which? SB1 : SB0; u32 hits=0;
    for(u32 d=1;d<256;d++) for(u32 x=0;x<256;x++){
        u32 v=sb[x]^sb[x^d];
        if(!B(v,0)||!B(v,1)||!B(v,2)||!B(v,3)) hits++;
    }
    return hits;
}

/* measured integral labels. sat2=255 means a first-order set. */
EXPORT u32 integral_measure(u32 sat1,u32 sat2,u32 baselo,u32 basehi,u32 k0,u32 k1){
    u32 n = (sat2>7)? 256u : 65536u;
    for(u32 i=0;i<17u*8u;i++) VXOR[i]=0;
    for(u32 i=0;i<17u*8u*256u;i++) VCNT[i]=0;
    u32 ins[16],slo[16],shi[16];
    for(u32 v=0; v<n; v++){
        u32 lo=baselo, hi=basehi;
        u32 d1=v&0xff, sh1=8*(3-(sat1&3));
        if(sat1<4) lo=(lo&~(0xffu<<sh1))|(d1<<sh1); else hi=(hi&~(0xffu<<sh1))|(d1<<sh1);
        if(sat2<8){ u32 d2=(v>>8)&0xff, sh2=8*(3-(sat2&3));
            if(sat2<4) lo=(lo&~(0xffu<<sh2))|(d2<<sh2); else hi=(hi&~(0xffu<<sh2))|(d2<<sh2); }
        trace16(lo,hi,k0,k1,ins,slo,shi);
        for(int r=0;r<16;r++) for(int i=0;i<8;i++){
            u32 val = B(i<4? slo[r]:shi[r], i&3);
            VXOR[r*8+i]^=val; VCNT[(r*8+i)*256+val]++;
        }
        u32 cl,ch; encrypt(lo,hi,k0,k1,&cl,&ch);
        cl^=ror(k0,2); ch^=ror(k1,2);
        for(int i=0;i<8;i++){ u32 val=B(i<4?cl:ch, i&3);
            VXOR[16*8+i]^=val; VCNT[(16*8+i)*256+val]++; }
    }
    for(u32 r=0;r<17;r++) for(u32 i=0;i<8;i++){
        u32 idx=r*8+i, distinct=0, uniform=1, per=n/256u;
        for(u32 v=0;v<256;v++){ u32 c=VCNT[idx*256+v]; if(c){distinct++; if(c!=per) uniform=0;} }
        LBL[idx] = (distinct==1)?'C' : (distinct==256&&uniform)?'A' : (VXOR[idx]==0)?'B' : '?';
    }
    return n;
}


/* ---- sub-step trace: what each round does, one operation at a time ---- */
static u32 SUB[16*10];
EXPORT u32* sub_ptr(void){return SUB;}
EXPORT void substep_trace(u32 lo,u32 hi,u32 k0,u32 k1){
    OUT[0]=lo; OUT[1]=hi;                 /* plaintext */
    lo^=k0; hi^=k1;
    OUT[2]=lo; OUT[3]=hi;                 /* after the input whitening */
    for(int oc=0;oc<2;oc++){
        if(oc){ lo^=ror(k0,1); hi^=ror(k1,1); }
        for(int r=0;r<8;r++){
            int idx=oc*8+r; u32*S=&SUB[idx*10];
            S[0]=lo; S[1]=hi;                       /* 0: start of round   */
            u32 b=lo&0xff, so=(oc?SB1[b]:SB0[b]);
            S[2]=b; S[3]=so;                        /*    S-box in / out   */
            u32 h2=hi^so;  S[4]=lo; S[5]=h2;        /* 1: after the XOR    */
            u32 l2=ror(lo,ROT[r]); S[6]=l2; S[7]=h2;/* 2: after the rotate */
            S[8]=h2; S[9]=l2;                       /* 3: after the swap   */
            lo=h2; hi=l2;
        }
    }
    OUT[4]=lo^ror(k0,2); OUT[5]=hi^ror(k1,2);       /* ciphertext */
    OUT[6]=lo; OUT[7]=hi;                           /* before final whitening */
}

/* ---- sweep every one-byte difference, looking for a cancellation ---- */
static u32 SWEEP[256];
EXPORT u32* sweep_ptr(void){return SWEEP;}
EXPORT void sweep_delta(u32 lo,u32 hi,u32 k0,u32 k1,u32 bp){
    u32 i1[16],i2[16],a[16],b[16];
    trace16(lo,hi,k0,k1,i1,a,b);
    u32 sh=8*(3-(bp&3));
    SWEEP[0]=0;
    for(u32 d=1;d<256;d++){
        u32 l2=lo,h2=hi;
        if(bp<4) l2^=d<<sh; else h2^=d<<sh;
        trace16(l2,h2,k0,k1,i2,a,b);
        u32 m=0;
        for(int r=0;r<16;r++) if(i1[r]==i2[r]) m|=(1u<<r);
        SWEEP[d]=m;                 /* bit r set = round r inactive for this delta */
    }
}

/* ---- avalanche: flip one input bit, watch the damage spread ---- */
static u32 AVA[17*3];
EXPORT u32* ava_ptr(void){return AVA;}
EXPORT void avalanche(u32 lo,u32 hi,u32 k0,u32 k1,u32 bit){
    u32 lo2=lo,hi2=hi;
    if(bit<32) lo2^=1u<<(31-bit); else hi2^=1u<<(63-bit);
    u32 i1[16],a1[16],b1[16],i2[16],a2[16],b2[16];
    trace16(lo,hi,k0,k1,i1,a1,b1);
    trace16(lo2,hi2,k0,k1,i2,a2,b2);
    for(int r=0;r<16;r++){
        AVA[r*3+0]=a1[r]^a2[r]; AVA[r*3+1]=b1[r]^b2[r];
        AVA[r*3+2]=__builtin_popcount(a1[r]^a2[r])+__builtin_popcount(b1[r]^b2[r]);
    }
    u32 c1l,c1h,c2l,c2h;
    encrypt(lo,hi,k0,k1,&c1l,&c1h); encrypt(lo2,hi2,k0,k1,&c2l,&c2h);
    AVA[48]=c1l^c2l; AVA[49]=c1h^c2h;
    AVA[50]=__builtin_popcount(c1l^c2l)+__builtin_popcount(c1h^c2h);
}

/* ---- reduced-round cipher + integral key recovery ---- */
static void enc_reduced(u32 lo,u32 hi,u32 k0,u32 k1,u32 r1,u32*ol,u32*oh){
    lo^=k0; hi^=k1;
    for(int r=0;r<8;r++){hi^=SB0[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo;lo=hi;hi=t;}
    lo^=ror(k0,1); hi^=ror(k1,1);
    for(u32 r=0;r<r1;r++){hi^=SB1[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo;lo=hi;hi=t;}
    *ol=lo^ror(k0,2); *oh=hi^ror(k1,2);
}
static inline void invn(u32 cl,u32 ch,u32 wlo,u32 whi,u32 n,u32 r1,u32*ol,u32*oh){
    u32 lo=cl^wlo, hi=ch^whi;
    for(u32 i=0;i<n;i++){ u32 r=r1-1-i; u32 t=lo;lo=hi;hi=t; lo=rol(lo,ROT[r]); hi^=SB1[lo&0xff]; }
    *ol=lo; *oh=hi;
}
static u32 SETN; 
static void build_reduced_set(u32 sat,u32 baselo,u32 basehi,u32 k0,u32 k1,u32 r1){
    SETN=256;
    for(u32 v=0;v<256;v++){
        u32 lo=baselo, hi=basehi, sh=8*(3-(sat&3));
        if(sat<4) lo=(lo&~(0xffu<<sh))|(v<<sh); else hi=(hi&~(0xffu<<sh))|(v<<sh);
        enc_reduced(lo,hi,k0,k1,r1,&CTLO[v],&CTHI[v]);
    }
}
/* which W2 bytes affect the balance of state bytes 4..7 after n inversions */
EXPORT u32 which_matter(u32 r1,u32 n,u32 sat,u32 baselo,u32 basehi,u32 k0,u32 k1){
    build_reduced_set(sat,baselo,basehi,k0,k1,r1);
    u32 wlo=ror(k0,2), whi=ror(k1,2), mask=0;
    u32 bl=0,bh=0;
    for(u32 v=0;v<SETN;v++){u32 a,b; invn(CTLO[v],CTHI[v],wlo,whi,n,r1,&a,&b); bl^=a; bh^=b;}
    for(u32 bi=0;bi<8;bi++){
        u32 dl=0,dh=0, sh=8*(3-(bi&3));
        if(bi<4) dl=0x5Au<<sh; else dh=0x5Au<<sh;
        u32 cl2=0,ch2=0;
        for(u32 v=0;v<SETN;v++){u32 a,b; invn(CTLO[v],CTHI[v],wlo^dl,whi^dh,n,r1,&a,&b); cl2^=a; ch2^=b;}
        if(ch2!=bh) mask|=(1u<<bi);
    }
    OUT[0]=bl; OUT[1]=bh;
    return mask;
}
/* enumerate the masked W2 bytes, keep guesses where bytes 4..7 are balanced */
EXPORT u32 recover(u32 r1,u32 n,u32 mask,u32 sat,u32 baselo,u32 basehi,u32 k0,u32 k1){
    build_reduced_set(sat,baselo,basehi,k0,k1,r1);
    u32 pos[8],np=0;
    for(u32 i=0;i<8;i++) if(mask&(1u<<i)) pos[np++]=i;
    nsurv=0;
    u32 total=1; for(u32 i=0;i<np;i++) total*=256u;
    for(u32 g=0; g<total; g++){
        u32 wlo=0,whi=0,gg=g;
        for(u32 i=0;i<np;i++){ u32 v=gg&0xff; gg>>=8; u32 sh=8*(3-(pos[i]&3));
            if(pos[i]<4) wlo|=v<<sh; else whi|=v<<sh; }
        u32 bl=0,bh=0;
        for(u32 v=0;v<SETN;v++){u32 a,b; invn(CTLO[v],CTHI[v],wlo,whi,n,r1,&a,&b); bl^=a; bh^=b;}
        if(bh==0 && nsurv<4096) SURV[nsurv++]=g;
    }
    /* report the true packed guess for comparison */
    u32 wlo=ror(k0,2), whi=ror(k1,2), truth=0;
    for(u32 i=0;i<np;i++){ u32 sh=8*(3-(pos[i]&3));
        u32 v = (pos[i]<4? wlo:whi)>>sh & 0xff; truth |= v<<(8*i); }
    OUT[0]=truth; OUT[1]=np; OUT[2]=total;
    return nsurv;
}
