/* Tiny kernel for the final known-plaintext search over the four remaining W2
   bytes. Deliberately separate from fwht_kernel.c: that one reserves ~200 MB of
   tables, which a brute-force shard has no use for. */
typedef unsigned char u8; typedef unsigned int u32;
#define EXPORT __attribute__((visibility("default"),used))
#include "sbox_data.h"
static const int ROT[8]={16,16,8,8,16,16,24,24};
static inline u32 ror(u32 x,int r){return r?(x>>r)|(x<<(32-r)):x;}
static inline u32 rol(u32 x,int r){return r?(x<<r)|(x>>(32-r)):x;}
static u32 OUT[8];
EXPORT u32* out_ptr(void){return OUT;}

static void enc(u32 lo,u32 hi,u32 k0,u32 k1,u32*ol,u32*oh){
    lo^=k0; hi^=k1;
    for(int r=0;r<8;r++){hi^=SB0[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo;lo=hi;hi=t;}
    lo^=ror(k0,1); hi^=ror(k1,1);
    for(int r=0;r<8;r++){hi^=SB1[lo&0xff]; lo=ror(lo,ROT[r]); u32 t=lo;lo=hi;hi=t;}
    *ol=lo^ror(k0,2); *oh=hi^ror(k1,2);
}
EXPORT void enc1(u32 lo,u32 hi,u32 k0,u32 k1){ enc(lo,hi,k0,k1,&OUT[0],&OUT[1]); }
EXPORT void dec1(u32 cl,u32 ch,u32 k0,u32 k1){
    u32 lo=cl^ror(k0,2),hi=ch^ror(k1,2);
    for(int r=7;r>=0;r--){u32 t=lo;lo=hi;hi=t;lo=rol(lo,ROT[r]);hi^=SB1[lo&0xff];}
    lo^=ror(k0,1); hi^=ror(k1,1);
    for(int r=7;r>=0;r--){u32 t=lo;lo=hi;hi=t;lo=rol(lo,ROT[r]);hi^=SB0[lo&0xff];}
    OUT[0]=lo^k0; OUT[1]=hi^k1;
}
/* The order-2 integral set: saturate state bytes 2 and 6 -> 2^16 chosen plaintexts.
   Built here on the main thread, which is the side legitimately playing the oracle;
   the attack workers receive only the ciphertexts. */
static u32 SLO[65536], SHI[65536];
EXPORT u32* slo_ptr(void){return SLO;}
EXPORT u32* shi_ptr(void){return SHI;}
EXPORT void build_set16(u32 baselo,u32 basehi,u32 k0,u32 k1){
    for(u32 v=0;v<65536u;v++){
        u32 lo=(baselo&0xffff00ffu)|((v&0xff)<<8);
        u32 hi=(basehi&0xffff00ffu)|(((v>>8)&0xff)<<8);
        enc(lo,hi,k0,k1,&SLO[v],&SHI[v]);
    }
}

/* base_lo/base_hi carry the four W2 bytes the integral already recovered.
   Sweeps `count` values of the other four starting at `start`.
   Returns 1 and leaves (k0,k1) in OUT when the known pair verifies. */
EXPORT u32 brute_range(u32 base_lo,u32 base_hi,u32 plo,u32 phi,u32 kcl,u32 kch,
                       u32 start,u32 count){
    for(u32 i=0;i<count;i++){
        u32 g=start+i;
        u32 w2lo=base_lo|(((g>>24)&0xff)<<16)|((g>>16)&0xff);
        u32 w2hi=base_hi|(((g>>8)&0xff)<<16)|(g&0xff);
        u32 k0=rol(w2lo,2),k1=rol(w2hi,2),cl,ch;
        enc(plo,phi,k0,k1,&cl,&ch);
        if(cl==kcl&&ch==kch){ OUT[0]=k0; OUT[1]=k1; OUT[2]=g; return 1; }
    }
    return 0;
}
