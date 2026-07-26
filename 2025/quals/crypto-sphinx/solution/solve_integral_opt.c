/* sphinx / Khafre-16 key recovery -- cost-optimal version
 * ONE order-2 integral set: saturate state bytes 2 and 6  => 2^16 = 65536 chosen plaintexts.
 * Round-12 upper half is balanced; all 4 balanced bytes depend on the same 4 key bytes
 * {W2_lo0,W2_lo2,W2_hi0,W2_hi2}.  Peel W2_hi2 into a 256-way outer loop; the rest is a
 * clean 3-byte XOR-correlation solved by a 2^24 FWHT in pure uint32 (natural wraparound,
 * no modular reduction).  Filter on 2 balanced bytes (16 bits) by FWHT, then verify
 * survivors directly with a real 4-round inversion.  Finally brute the other 4 W2 bytes.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>
#include "sboxes.h"
static const int ROT[8]={16,16,8,8,16,16,24,24};
static inline uint32_t ror(uint32_t x,int r){return r?(x>>r)|(x<<(32-r)):x;}
static inline uint32_t rol(uint32_t x,int r){return r?(x<<r)|(x>>(32-r)):x;}
static inline int B(uint32_t x,int i){return (x>>(8*(3-i)))&0xff;}
static void enc(uint32_t lo,uint32_t hi,uint32_t k0,uint32_t k1,uint32_t*ol,uint32_t*oh){
    lo^=k0;hi^=k1;for(int r=0;r<8;r++){hi^=SB0[lo&0xff];lo=ror(lo,ROT[r]);uint32_t t=lo;lo=hi;hi=t;}
    lo^=ror(k0,1);hi^=ror(k1,1);for(int r=0;r<8;r++){hi^=SB1[lo&0xff];lo=ror(lo,ROT[r]);uint32_t t=lo;lo=hi;hi=t;}
    *ol=lo^ror(k0,2);*oh=hi^ror(k1,2);}
static void dec(uint32_t cl,uint32_t ch,uint32_t k0,uint32_t k1,uint32_t*ol,uint32_t*oh){
    uint32_t lo=cl^ror(k0,2),hi=ch^ror(k1,2);
    for(int r=7;r>=0;r--){uint32_t t=lo;lo=hi;hi=t;lo=rol(lo,ROT[r]);hi^=SB1[lo&0xff];}
    lo^=ror(k0,1);hi^=ror(k1,1);
    for(int r=7;r>=0;r--){uint32_t t=lo;lo=hi;hi=t;lo=rol(lo,ROT[r]);hi^=SB0[lo&0xff];}
    *ol=lo^k0;*oh=hi^k1;}

#define N24 (1<<24)
#define NSET 65536
static void fwht(uint32_t*a){
    for(long h=1;h<N24;h<<=1)
      for(long i=0;i<N24;i+=h<<1)
        for(long j=i;j<i+h;j++){uint32_t x=a[j],y=a[j+h];a[j]=x+y;a[j+h]=x-y;}
}
static uint32_t *Wg5,*Wg7;                 /* FWHT of g5,g7 bit-planes (key independent) */
static uint32_t setcl[NSET],setch[NSET];   /* the one integral set's ciphertexts */

/* direct verification: 4 inversions over the whole set, other 4 W2 bytes = 0
   (they enter only linearly and cancel over an even-sized set). */
static int verify4(int whi2,int wlo2,int whi0,int wlo0){
    uint32_t W2lo=((uint32_t)wlo0<<24)|((uint32_t)wlo2<<8);
    uint32_t W2hi=((uint32_t)whi0<<24)|((uint32_t)whi2<<8);
    uint32_t axl=0,axh=0;
    for(long v=0;v<NSET;v++){
        uint32_t lo=setcl[v]^W2lo, hi=setch[v]^W2hi;
        for(int i=0;i<4;i++){int r=7-i;uint32_t t=lo;lo=hi;hi=t;lo=rol(lo,ROT[r]);hi^=SB1[lo&0xff];}
        axl^=lo; axh^=hi;
    }
    return (axh==0);            /* upper half (state bytes 4..7) fully balanced */
}

int main(void){
    srand(20250611);
    uint32_t k0=((uint32_t)rand()<<16)^rand(),k1=((uint32_t)rand()<<16)^rand();
    uint8_t flag[8]; for(int i=0;i<8;i++) flag[i]=rand()&0xff;
    uint32_t flo=(flag[0]<<24)|(flag[1]<<16)|(flag[2]<<8)|flag[3];
    uint32_t fhi=(flag[4]<<24)|(flag[5]<<16)|(flag[6]<<8)|flag[7];
    uint32_t tlo,thi; enc(flo,fhi,k0,k1,&tlo,&thi);
    uint32_t plo,phi,kcl,kch;   /* filled in from the integral set below: no extra query */
    uint32_t W2lo=ror(k0,2),W2hi=ror(k1,2);
    fprintf(stderr,"[*] secret k0=%08x k1=%08x   true4: whi2=%02x wlo2=%02x whi0=%02x wlo0=%02x\n",
            k0,k1,B(W2hi,2),B(W2lo,2),B(W2hi,0),B(W2lo,0));

    /* g5,g7 over (A,B,D):  M = D ^ S1[B ^ S1[A]] ; g5=S3[A]^S1[M] ; g7=S1[A]^S3[M] */
    static uint8_t g5[N24],g7[N24];
    for(int A=0;A<256;A++){int s1A=B(SB1[A],1),s3A=B(SB1[A],3);
      for(int Bb=0;Bb<256;Bb++){int inner=B(SB1[Bb^s1A],1);
        for(int D=0;D<256;D++){int M=D^inner; long i=((long)A<<16)|(Bb<<8)|D;
          g5[i]=s3A^B(SB1[M],1); g7[i]=s1A^B(SB1[M],3);}}}
    double t0=omp_get_wtime();
    Wg5=malloc(8L*N24*sizeof(uint32_t)); Wg7=malloc(8L*N24*sizeof(uint32_t));
    { uint32_t*buf=malloc((long)N24*sizeof(uint32_t));
      for(int b=0;b<8;b++){for(long i=0;i<N24;i++) buf[i]=(g5[i]>>b)&1; fwht(buf);
        memcpy(Wg5+(long)b*N24,buf,(long)N24*sizeof(uint32_t));}
      for(int b=0;b<8;b++){for(long i=0;i<N24;i++) buf[i]=(g7[i]>>b)&1; fwht(buf);
        memcpy(Wg7+(long)b*N24,buf,(long)N24*sizeof(uint32_t));} free(buf);}
    fprintf(stderr,"[*] precomputed FWHT(g5),FWHT(g7) in %.1fs\n",omp_get_wtime()-t0);

    /* --- the ONE integral set: saturate state byte 2 (lo byte2) and byte 6 (hi byte2) --- */
    uint32_t bl=0x1234abcd, bh=0x5678ef01;
    uint8_t c0[NSET],c2[NSET],h0[NSET],h2[NSET]; int C5=0,C7=0;
    for(long v=0;v<NSET;v++){
        uint32_t lo=(bl&0xffff00ffu)|((uint32_t)(v&0xff)<<8);
        uint32_t hi=(bh&0xffff00ffu)|((uint32_t)((v>>8)&0xff)<<8);
        uint32_t cl,ch; enc(lo,hi,k0,k1,&cl,&ch);
        setcl[v]=cl; setch[v]=ch;
        if(v==0){plo=lo;phi=hi;kcl=cl;kch=ch;}   /* known PC pair, reused from the set */
        c0[v]=B(cl,0);c2[v]=B(cl,2);h0[v]=B(ch,0);h2[v]=B(ch,2);
        C5^=B(ch,2);          /* linear term of balanced byte 5 */
        C7^=B(ch,0);          /* linear term of balanced byte 7 */
    }
    fprintf(stderr,"[*] one integral set built: %d chosen plaintexts (sat bytes 2,6)\n",NSET);

    /* --- recover: 256-way outer loop on W2_hi2, 2^24 FWHT correlation inside --- */
    long *cand=malloc(sizeof(long)*(1L<<22)); long ncand=0;
    t0=omp_get_wtime();
    #pragma omp parallel
    {
      uint32_t*H=malloc((long)N24*sizeof(uint32_t));
      uint32_t*buf=malloc((long)N24*sizeof(uint32_t));
      uint8_t *b5=malloc(N24),*b7=malloc(N24);
      #pragma omp for schedule(dynamic)
      for(int whi2=0; whi2<256; whi2++){
        memset(H,0,(long)N24*sizeof(uint32_t));
        for(long v=0;v<NSET;v++){int X6=h2[v]^whi2; uint32_t sb=SB1[X6];
          int A0=c2[v]^B(sb,2), D0=c0[v]^B(sb,0);
          H[((long)A0<<16)|((long)h0[v]<<8)|D0]^=1;}
        fwht(H);                                   /* one forward FWHT serves every bit-plane */
        memset(b5,0,N24); memset(b7,0,N24);
        for(int b=0;b<8;b++){ uint32_t*w=Wg5+(long)b*N24;
          for(long i=0;i<N24;i++) buf[i]=H[i]*w[i]; fwht(buf);
          for(long i=0;i<N24;i++) if((buf[i]>>24)&1) b5[i]|=(1<<b);}
        for(int b=0;b<8;b++){ uint32_t*w=Wg7+(long)b*N24;
          for(long i=0;i<N24;i++) buf[i]=H[i]*w[i]; fwht(buf);
          for(long i=0;i<N24;i++) if((buf[i]>>24)&1) b7[i]|=(1<<b);}
        for(long w=0;w<N24;w++) if(b5[w]==(C5&0xff) && b7[w]==(C7&0xff)){
            long idx=((long)whi2<<24)|w;
            #pragma omp critical
            { if(ncand<(1L<<22)) cand[ncand++]=idx; }
        }
      }
      free(H);free(buf);free(b5);free(b7);
    }
    fprintf(stderr,"[*] FWHT stage %.0fs -> %ld candidates after 16-bit filter\n",omp_get_wtime()-t0,ncand);

    /* --- verify survivors with a real inversion (all 4 balanced bytes) --- */
    t0=omp_get_wtime();
    long nfinal=0; long finals[64];
    #pragma omp parallel for schedule(dynamic)
    for(long i=0;i<ncand;i++){
        long idx=cand[i];
        if(verify4((idx>>24)&0xff,(idx>>16)&0xff,(idx>>8)&0xff,idx&0xff)){
            #pragma omp critical
            { if(nfinal<64) finals[nfinal++]=idx; }
        }
    }
    fprintf(stderr,"[*] verify %.0fs -> %ld survivor(s)\n",omp_get_wtime()-t0,nfinal);

    for(long i=0;i<nfinal;i++){
        long idx=finals[i];
        int whi2=(idx>>24)&0xff,wlo2=(idx>>16)&0xff,whi0=(idx>>8)&0xff,wlo0=idx&0xff;
        fprintf(stderr,"[+] survivor whi2=%02x wlo2=%02x whi0=%02x wlo0=%02x\n",whi2,wlo2,whi0,wlo0);
        uint32_t base_lo=((uint32_t)wlo0<<24)|(wlo2<<8), base_hi=((uint32_t)whi0<<24)|(whi2<<8);
        #pragma omp parallel for collapse(2) schedule(dynamic)
        for(int a=0;a<256;a++) for(int b=0;b<256;b++) for(int c=0;c<256;c++) for(int d=0;d<256;d++){
            uint32_t w2lo=base_lo|(a<<16)|b, w2hi=base_hi|(c<<16)|d;
            uint32_t kk0=rol(w2lo,2),kk1=rol(w2hi,2),cl,ch; enc(plo,phi,kk0,kk1,&cl,&ch);
            if(cl==kcl&&ch==kch){uint32_t dl,dh; dec(tlo,thi,kk0,kk1,&dl,&dh);
              #pragma omp critical
              printf("RECOVERED=%08x%08x TRUE=%08x%08x %s  (queries=%d)\n",dl,dh,flo,fhi,
                     (dl==flo&&dh==fhi)?"SUCCESS-FLAG-MATCH":"MISMATCH",NSET);}
        }
    }
    return 0;
}
