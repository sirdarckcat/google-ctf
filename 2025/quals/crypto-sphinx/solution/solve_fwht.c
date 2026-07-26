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
#define P 2147483647LL
static inline int64_t mod(int64_t x){x=(x&P)+(x>>31); return x>=P?x-P:x;}
static void fwht(int64_t*a){
    for(long h=1;h<N24;h<<=1) for(long i=0;i<N24;i+=h<<1) for(long j=i;j<i+h;j++){
        int64_t x=a[j],y=a[j+h]; a[j]=mod(x+y); a[j+h]=mod(x-y+P);}
}
#define NS 4
static uint8_t *c0[NS],*c2[NS],*h0[NS],*h2[NS]; static int C6[NS];
static int64_t *Wg;          // 8 * N24
static int64_t invN;
static uint8_t *bm;          // survivor bitmap over 2^32 (AND across sets), 512MB

int main(){
    srand(20250611);
    uint32_t k0=((uint32_t)rand()<<16)^rand(),k1=((uint32_t)rand()<<16)^rand();
    uint8_t flag[8]; for(int i=0;i<8;i++) flag[i]=rand()&0xff;
    uint32_t flo=(flag[0]<<24)|(flag[1]<<16)|(flag[2]<<8)|flag[3];
    uint32_t fhi=(flag[4]<<24)|(flag[5]<<16)|(flag[6]<<8)|flag[7];
    uint32_t tlo,thi; enc(flo,fhi,k0,k1,&tlo,&thi);
    uint32_t plo=0x0f1e2d3c,phi=0x4b5a6978,kcl,kch; enc(plo,phi,k0,k1,&kcl,&kch);
    uint32_t W2lo=ror(k0,2),W2hi=ror(k1,2);
    fprintf(stderr,"[*] secret k0=%08x k1=%08x  true4(whi2=%02x wlo2=%02x whi0=%02x wlo0=%02x)\n",
            k0,k1,B(W2hi,2),B(W2lo,2),B(W2hi,0),B(W2lo,0));
    // g5 table + FWHT precompute
    static uint8_t g5[N24];
    for(int A=0;A<256;A++){int t1A=B(SB1[A],1),t3A=B(SB1[A],3);
      for(int Bb=0;Bb<256;Bb++){int u=B(SB1[Bb^t1A],1);
        for(int D=0;D<256;D++) g5[(A<<16)|(Bb<<8)|D]=t3A^B(SB1[D^u],1);}}
    Wg=malloc(8L*N24*sizeof(int64_t));
    { int64_t*buf=malloc((long)N24*sizeof(int64_t));
      for(int b=0;b<8;b++){for(long i=0;i<N24;i++) buf[i]=(g5[i]>>b)&1; fwht(buf); memcpy(Wg+(long)b*N24,buf,(long)N24*sizeof(int64_t));}
      free(buf);}
    { long e=P-2,base=N24%P,r=1; while(e){if(e&1)r=r*base%P; base=base*base%P; e>>=1;} invN=r;}
    // generate 4 integral sets
    for(int s=0;s<NS;s++){
        c0[s]=malloc(N24);c2[s]=malloc(N24);h0[s]=malloc(N24);h2[s]=malloc(N24);
        uint32_t bl=((uint32_t)rand()<<16)^rand(), bh=((uint32_t)rand()<<16)^rand(); int c6=0;
        #pragma omp parallel for reduction(^:c6)
        for(long v=0;v<N24;v++){int b3=v&0xff,b2=(v>>8)&0xff,b6=(v>>16)&0xff;
          uint32_t lo=(bl&0xffff0000u)|(b2<<8)|b3, hi=(bh&0xffff0000u)|(b6<<8)|(bh&0xff);
          uint32_t cl,ch;enc(lo,hi,k0,k1,&cl,&ch);
          c0[s][v]=B(cl,0);c2[s][v]=B(cl,2);h0[s][v]=B(ch,0);h2[s][v]=B(ch,2);c6^=B(ch,2);}
        C6[s]=c6;
    }
    fprintf(stderr,"[*] sets built, precompute done; starting FWHT recovery\n");
    bm=calloc(1L<<29,1); // 2^32 bits
    for(int s=0;s<NS;s++){
        uint8_t *setbm = (s==0)? bm : calloc(1L<<29,1);
        double t0=omp_get_wtime();
        #pragma omp parallel
        {
          int64_t*H3=malloc((long)N24*sizeof(int64_t));
          int64_t*buf=malloc((long)N24*sizeof(int64_t));
          uint8_t*bal=malloc(N24);
          #pragma omp for schedule(dynamic)
          for(int whi2=0; whi2<256; whi2++){
            memset(H3,0,(long)N24*sizeof(int64_t));
            uint8_t*C0=c0[s],*C2=c2[s],*H0=h0[s],*H2=h2[s];
            for(long v=0;v<N24;v++){int X6=H2[v]^whi2; uint32_t sb=SB1[X6];
              int u2=C2[v]^B(sb,2), u0=C0[v]^B(sb,0);
              H3[((long)u2<<16)|(H0[v]<<8)|u0]^=1;}
            fwht(H3);
            memset(bal,0,N24);
            for(int b=0;b<8;b++){ int64_t*wg=Wg+(long)b*N24;
              for(long i=0;i<N24;i++) buf[i]=mod(H3[i]*wg[i]);
              fwht(buf);
              for(long i=0;i<N24;i++){ int64_t cnt=mod(buf[i]*invN); if(cnt&1) bal[i]|=(1<<b);}}
            int c6=C6[s]&0xff;
            for(long w=0;w<N24;w++) if(bal[w]==c6){ long idx=((long)whi2<<24)|w; setbm[idx>>3]|=(1<<(idx&7));}
          }
          free(H3);free(buf);free(bal);
        }
        fprintf(stderr,"[*] set %d FWHT done %.0fs\n",s,omp_get_wtime()-t0);
        if(s>0){ // AND into bm
          #pragma omp parallel for
          for(long i=0;i<(1L<<29);i++) bm[i]&=setbm[i];
          free(setbm);
        }
    }
    // survivors -> brute other 4 W2 bytes
    long surv=0;
    for(long idx=0; idx<(1L<<32); idx++){
        if(!(bm[idx>>3]&(1<<(idx&7)))) continue;
        surv++;
        int whi2=(idx>>24)&0xff, wlo2=(idx>>16)&0xff, whi0=(idx>>8)&0xff, wlo0=idx&0xff;
        fprintf(stderr,"[+] survivor whi2=%02x wlo2=%02x whi0=%02x wlo0=%02x\n",whi2,wlo2,whi0,wlo0);
        uint32_t base_lo=((uint32_t)wlo0<<24)|(wlo2<<8), base_hi=((uint32_t)whi0<<24)|(whi2<<8);
        #pragma omp parallel for collapse(2) schedule(dynamic)
        for(int a=0;a<256;a++) for(int b=0;b<256;b++) for(int c=0;c<256;c++) for(int d=0;d<256;d++){
            uint32_t w2lo=base_lo|(a<<16)|b, w2hi=base_hi|(c<<16)|d;
            uint32_t kk0=rol(w2lo,2),kk1=rol(w2hi,2),cl,ch; enc(plo,phi,kk0,kk1,&cl,&ch);
            if(cl==kcl&&ch==kch){uint32_t dl,dh; dec(tlo,thi,kk0,kk1,&dl,&dh);
              #pragma omp critical
              printf("RECOVERED=%08x%08x TRUE=%08x%08x %s\n",dl,dh,flo,fhi,(dl==flo&&dh==fhi)?"SUCCESS-FLAG-MATCH":"MISMATCH");}
        }
    }
    fprintf(stderr,"[*] survivors=%ld\n",surv);
    return 0;
}
