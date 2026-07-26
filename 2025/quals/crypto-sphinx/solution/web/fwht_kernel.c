/* Freestanding WASM kernel for the sphinx integral attack.
   No libc. Exports are called from JS. */
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32; typedef unsigned long long u64;
#define N24 (1u<<24)
#define EXPORT __attribute__((visibility("default"),used))

static u32 SB0[256], SB1[256];
static u8  g5[N24];
static u32 H[N24];
static u32 T[N24];
static u32 CT_LO[65536], CT_HI[65536];
static u32 CAND[1<<20]; static u32 ncand;

static const int ROT[8] = {16,16,8,8,16,16,24,24};
static inline u32 ror(u32 x,int r){return r?(x>>r)|(x<<(32-r)):x;}
static inline u32 rol(u32 x,int r){return r?(x<<r)|(x>>(32-r)):x;}
static inline u32 B(u32 x,int i){return (x>>(8*(3-i)))&0xff;}

EXPORT u32* sb0_ptr(void){return SB0;}
EXPORT u32* sb1_ptr(void){return SB1;}
EXPORT u32* ctlo_ptr(void){return CT_LO;}
EXPORT u32* cthi_ptr(void){return CT_HI;}
EXPORT u32* cand_ptr(void){return CAND;}

static void encrypt_fwd(u32 lo,u32 hi,u32 k0,u32 k1,u32*ol,u32*oh){
    lo^=k0; hi^=k1;
    for(int r=0;r<8;r++){hi^=SB0[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo; lo=hi; hi=t;}
    lo^=ror(k0,1); hi^=ror(k1,1);
    for(int r=0;r<8;r++){hi^=SB1[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo; lo=hi; hi=t;}
    *ol=lo^ror(k0,2); *oh=hi^ror(k1,2);
}
EXPORT void enc1(u32 lo,u32 hi,u32 k0,u32 k1,u32* out){ encrypt_fwd(lo,hi,k0,k1,out,out+1); }

/* build the order-2 integral set (saturate state bytes 2 and 6) and encrypt it */
EXPORT void build_set(u32 baselo,u32 basehi,u32 k0,u32 k1){
    for(u32 v=0; v<65536u; v++){
        u32 lo=(baselo&0xffff00ffu)|((v&0xff)<<8);
        u32 hi=(basehi&0xffff00ffu)|(((v>>8)&0xff)<<8);
        encrypt_fwd(lo,hi,k0,k1,&CT_LO[v],&CT_HI[v]);
    }
}

/* g5(A,B,D) = byte3(SB1[A]) ^ byte1(SB1[M]),  M = D ^ byte1(SB1[B ^ byte1(SB1[A])]) */
EXPORT void build_g5(void){
    for(u32 A=0;A<256;A++){
        u32 s1A=B(SB1[A],1), s3A=B(SB1[A],3);
        for(u32 Bb=0;Bb<256;Bb++){
            u32 inner=B(SB1[Bb^s1A],1);
            u32 base=(A<<16)|(Bb<<8);
            for(u32 D=0;D<256;D++) g5[base|D]=(u8)(s3A ^ B(SB1[D^inner],1));
        }
    }
}

/* uint32 FWHT with natural wraparound (mod 2^32) */
static void fwht(u32* a){
    for(u32 h=1; h<N24; h<<=1)
        for(u32 i=0;i<N24;i+=h<<1)
            for(u32 j=i;j<i+h;j++){u32 x=a[j],y=a[j+h]; a[j]=x+y; a[j+h]=x-y;}
}
EXPORT void fwht_bench(void){ fwht(H); }

/* g7(A,B,D) = byte1(SB1[A]) ^ byte3(SB1[M]) -- the second balanced byte (state byte 7) */
static u8 g7[N24];
EXPORT void build_g7(void){
    for(u32 A=0;A<256;A++){
        u32 s1A=B(SB1[A],1);
        for(u32 Bb=0;Bb<256;Bb++){
            u32 inner=B(SB1[Bb^s1A],1);
            u32 base=(A<<16)|(Bb<<8);
            for(u32 D=0;D<256;D++) g7[base|D]=(u8)(s1A ^ B(SB1[D^inner],3));
        }
    }
}
static inline u32 rol_(u32 x,int r){return r?(x<<r)|(x>>(32-r)):x;}
/* real 4-round inversion over the whole set: are state bytes 4..7 all balanced?
   the other four W2 bytes enter only linearly and cancel over an even-sized set. */
static u32 verify4(u32 whi2,u32 wlo2,u32 whi0,u32 wlo0){
    u32 W2lo=(wlo0<<24)|(wlo2<<8), W2hi=(whi0<<24)|(whi2<<8), axh=0;
    for(u32 v=0;v<65536u;v++){
        u32 lo=CT_LO[v]^W2lo, hi=CT_HI[v]^W2hi;
        for(int i=0;i<4;i++){int r=7-i;u32 t=lo;lo=hi;hi=t;lo=rol_(lo,ROT[r]);hi^=SB1[lo&0xff];}
        axh^=hi;
    }
    return axh==0;
}

/* one pass of the real attack for a given W2_hi2; returns candidate count */

/* --- the pass, split into resumable chunks so a browser can yield between them --- */
static u16 BAL[N24];
static u32 PC5,PC7,PWHI2;

/* --- retained-plane path ---------------------------------------------------
   The 16 transformed g5/g7 bit-planes are key-independent and identical for all
   256 steps, so re-transforming them every step is pure waste. When they are held
   in a SharedArrayBuffer, JS multiplies H by a plane straight into T and the
   plane's own transform is skipped: 33 transforms per step becomes 17. */
EXPORT u32* h_ptr(void){return H;}
EXPORT u32* t_ptr(void){return T;}
EXPORT void fwht_t(void){ fwht(T); }
EXPORT void extract_t(u32 which,u32 bit){
    u32 sh = bit + (which?8:0);
    for(u32 i=0;i<N24;i++) if((T[i]>>24)&1u) BAL[i]|=(u16)(1u<<sh);
}
/* build one transformed plane into T so JS can copy it out (once, at startup) */
EXPORT void build_plane_into_t(u32 which,u32 bit){
    const u8* g = which? g7 : g5;
    for(u32 i=0;i<N24;i++) T[i]=(g[i]>>bit)&1u;
    fwht(T);
}

EXPORT void pass_begin(u32 whi2){
    PWHI2=whi2; PC5=0; PC7=0;
    for(u32 i=0;i<N24;i++) H[i]=0;
    for(u32 v=0;v<65536u;v++){
        u32 cl=CT_LO[v], ch=CT_HI[v];
        u32 X6=B(ch,2)^whi2, s=SB1[X6];
        u32 A0=B(cl,2)^B(s,2), D0=B(cl,0)^B(s,0), B0=B(ch,0);
        H[(A0<<16)|(B0<<8)|D0]^=1u;
        PC5^=B(ch,2);            /* linear term of balanced byte 5 */
        PC7^=B(ch,0);            /* linear term of balanced byte 7 */
    }
    fwht(H);                     /* one forward transform serves every bit-plane */
    for(u32 i=0;i<N24;i++) BAL[i]=0;
}
/* which=0 -> byte 5 (g5), which=1 -> byte 7 (g7); bit = 0..7 */
EXPORT void pass_plane(u32 which,u32 bit){
    const u8* g = which? g7 : g5;
    for(u32 i=0;i<N24;i++) T[i]=(g[i]>>bit)&1u;
    fwht(T);
    for(u32 i=0;i<N24;i++) T[i]=H[i]*T[i];
    fwht(T);
    u32 sh = bit + (which?8:0);
    for(u32 i=0;i<N24;i++) if((T[i]>>24)&1u) BAL[i]|=(u16)(1u<<sh);
}
EXPORT u32 pass_finish(void){
    u16 want=(u16)((PC5&0xff)|((PC7&0xff)<<8));
    ncand=0;
    for(u32 w=0;w<N24;w++) if(BAL[w]==want){
        /* 16 bits of filter leaves ~2^8 here; confirm all four bytes with a real inversion */
        if(verify4(PWHI2,(w>>16)&0xff,(w>>8)&0xff,w&0xff) && ncand<1024u)
            CAND[ncand++]=(PWHI2<<24)|w;
    }
    return ncand;
}
/* convenience: the whole pass in one call (used by the node benchmarks) */
EXPORT u32 attack_pass(u32 whi2){
    pass_begin(whi2);
    for(u32 w=0;w<2;w++) for(u32 b=0;b<8;b++) pass_plane(w,b);
    return pass_finish();
}

/* ---- throughput probe + sharded brute force over the remaining 4 W2 bytes ---- */
EXPORT u32 enc_bench(u32 n){
    u32 lo=0x12345678u,hi=0x9abcdef0u,a,b,acc=0;
    for(u32 i=0;i<n;i++){ encrypt_fwd(lo^i,hi,0xcafebabeu,0xdeadbeefu,&a,&b); acc^=a; }
    return acc;
}
/* known-plaintext filter: try `count` values of the 4 unknown W2 bytes starting at `start`.
   base_lo/base_hi carry the 4 bytes already recovered. Returns 1 and stores the key if found. */
EXPORT u32 brute_range(u32 base_lo,u32 base_hi,u32 plo,u32 phi,u32 kcl,u32 kch,
                       u32 start,u32 count,u32*out){
    for(u32 i=0;i<count;i++){
        u32 g=start+i;
        u32 w2lo=base_lo|((g>>24)&0xff)<<16|((g>>16)&0xff);
        u32 w2hi=base_hi|((g>>8)&0xff)<<16|(g&0xff);
        u32 k0=rol(w2lo,2),k1=rol(w2hi,2),cl,ch;
        encrypt_fwd(plo,phi,k0,k1,&cl,&ch);
        if(cl==kcl&&ch==kch){ out[0]=k0; out[1]=k1; return 1; }
    }
    return 0;
}
