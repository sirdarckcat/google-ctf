/* Freestanding WASM kernel for the sphinx integral attack.
   No libc. Exports are called from JS. */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
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

static void encrypt(u32 lo,u32 hi,u32 k0,u32 k1,u32*ol,u32*oh){
    lo^=k0; hi^=k1;
    for(int r=0;r<8;r++){hi^=SB0[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo; lo=hi; hi=t;}
    lo^=ror(k0,1); hi^=ror(k1,1);
    for(int r=0;r<8;r++){hi^=SB1[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo; lo=hi; hi=t;}
    *ol=lo^ror(k0,2); *oh=hi^ror(k1,2);
}
EXPORT void enc1(u32 lo,u32 hi,u32 k0,u32 k1,u32* out){ encrypt(lo,hi,k0,k1,out,out+1); }

/* build the order-2 integral set (saturate state bytes 2 and 6) and encrypt it */
EXPORT void build_set(u32 baselo,u32 basehi,u32 k0,u32 k1){
    for(u32 v=0; v<65536u; v++){
        u32 lo=(baselo&0xffff00ffu)|((v&0xff)<<8);
        u32 hi=(basehi&0xffff00ffu)|(((v>>8)&0xff)<<8);
        encrypt(lo,hi,k0,k1,&CT_LO[v],&CT_HI[v]);
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

/* one pass of the real attack for a given W2_hi2; returns candidate count */
EXPORT u32 attack_pass(u32 whi2){
    for(u32 i=0;i<N24;i++) H[i]=0;
    u32 C5=0;
    for(u32 v=0;v<65536u;v++){
        u32 cl=CT_LO[v], ch=CT_HI[v];
        u32 X6=B(ch,2)^whi2, s=SB1[X6];
        u32 A0=B(cl,2)^B(s,2), D0=B(cl,0)^B(s,0), B0=B(ch,0);
        H[(A0<<16)|(B0<<8)|D0]^=1u;
        C5^=B(ch,2);
    }
    fwht(H);
    /* accumulate the 8 bit-planes of the balance byte into T (reused as bytes) */
    static u8 bal[N24];
    for(u32 i=0;i<N24;i++) bal[i]=0;
    for(int bit=0; bit<8; bit++){
        for(u32 i=0;i<N24;i++) T[i]=(g5[i]>>bit)&1u;
        fwht(T);
        for(u32 i=0;i<N24;i++) T[i]=H[i]*T[i];
        fwht(T);
        for(u32 i=0;i<N24;i++) if((T[i]>>24)&1u) bal[i]|=(1u<<bit);
    }
    ncand=0;
    for(u32 w=0;w<N24;w++) if(bal[w]==(u8)C5){ if(ncand<(1u<<20)) CAND[ncand++]=w; }
    return ncand;
}
