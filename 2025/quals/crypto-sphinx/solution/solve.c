#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

#define NSET (1<<24)
#define NS 4               // 3 sets for partial-sums, set 3 for filtering
static uint8_t *C0[NS],*C2[NS],*H0[NS],*H2[NS]; static int C6[NS];
static uint8_t g1[256],g3[256],g0[256],g2[256];

// direct balance(b5) over a set for full 4-byte key
static int balance_set(int s,int whi2,int wlo2,int whi0,int wlo0){
    int bal=0; uint8_t*c0=C0[s],*c2=C2[s],*h0=H0[s],*h2=H2[s];
    for(long long v=0;v<NSET;v++){
        int X6=h2[v]^whi2; uint32_t sb=SB1[X6]; int s2=B(sb,2),s0=B(sb,0);
        int m1=(c2[v]^wlo2)^s2; uint32_t sm1=SB1[m1];
        int m2=(h0[v]^whi0)^B(sm1,1); int m3=(c0[v]^wlo0)^s0^B(SB1[m2],1);
        bal^=X6^B(sm1,3)^B(SB1[m3],1);
    }
    return bal;
}

// candidate storage
#define MAXC 100000
static int CW2[4][MAXC]; static volatile long NC=0;

int main(){
    srand(424242);
    uint32_t k0=((uint32_t)rand()<<16)^rand(), k1=((uint32_t)rand()<<16)^rand();
    uint8_t flag[8]; for(int i=0;i<8;i++) flag[i]=rand()&0xff;
    uint32_t flo=(flag[0]<<24)|(flag[1]<<16)|(flag[2]<<8)|flag[3];
    uint32_t fhi=(flag[4]<<24)|(flag[5]<<16)|(flag[6]<<8)|flag[7];
    uint32_t tlo,thi; enc(flo,fhi,k0,k1,&tlo,&thi);
    uint32_t plo=0x01234567,phi=0x89abcdef,kclo,kchi; enc(plo,phi,k0,k1,&kclo,&kchi);
    uint32_t W2lo=ror(k0,2),W2hi=ror(k1,2);
    fprintf(stderr,"[*] secret k0=%08x k1=%08x ; true4=(whi2=%02x wlo2=%02x whi0=%02x wlo0=%02x)\n",
            k0,k1,B(W2hi,2),B(W2lo,2),B(W2hi,0),B(W2lo,0));
    for(int i=0;i<256;i++){g1[i]=B(SB1[i],1);g3[i]=B(SB1[i],3);g0[i]=B(SB1[i],0);g2[i]=B(SB1[i],2);}
    for(int s=0;s<NS;s++){
        C0[s]=malloc(NSET);C2[s]=malloc(NSET);H0[s]=malloc(NSET);H2[s]=malloc(NSET);
        uint32_t bl=((uint32_t)rand()<<16)^rand(), bh=((uint32_t)rand()<<16)^rand();
        int c6=0;
        #pragma omp parallel for reduction(^:c6) schedule(static)
        for(long long v=0;v<NSET;v++){int b3=v&0xff,b2=(v>>8)&0xff,b6=(v>>16)&0xff;
            uint32_t lo=(bl&0xffff0000u)|(b2<<8)|b3, hi=(bh&0xffff0000u)|(b6<<8)|(bh&0xff);
            uint32_t cl,ch;enc(lo,hi,k0,k1,&cl,&ch);
            C0[s][v]=B(cl,0);C2[s][v]=B(cl,2);H0[s][v]=B(ch,0);H2[s][v]=B(ch,2);c6^=B(ch,2);}
        C6[s]=c6;
    }
    fprintf(stderr,"[*] %d integral sets generated, starting partial-sums search\n",NS);
    struct timespec ts0; clock_gettime(CLOCK_MONOTONIC,&ts0);
    int prog=0;
    #pragma omp parallel
    {
        uint8_t *Hs[3]; for(int s=0;s<3;s++) Hs[s]=malloc(65536);
        uint8_t H2t[3][256];
        #pragma omp for schedule(dynamic) collapse(2)
        for(int whi2=0; whi2<256; whi2++)
        for(int wlo2=0; wlo2<256; wlo2++){
            int cst[3];
            for(int s=0;s<3;s++){
                memset(Hs[s],0,65536); int tT3=0;
                uint8_t*c0=C0[s],*c2=C2[s],*h0=H0[s],*h2=H2[s];
                for(long long v=0;v<NSET;v++){
                    int X6=h2[v]^whi2; uint32_t sb=SB1[X6]; int s2=g2[X6],s0=g0[X6];
                    int m1=(c2[v]^wlo2)^s2; uint32_t sm1=SB1[m1];
                    tT3^=B(sm1,3);
                    int a=h0[v]^B(sm1,1), b=c0[v]^s0;
                    Hs[s][(a<<8)|b]^=1;
                }
                cst[s]=C6[s]^tT3;
            }
            for(int whi0=0; whi0<256; whi0++){
                // build H2t for set0
                memset(H2t[0],0,256);
                for(int a=0;a<256;a++){int t=g1[a^whi0]; uint8_t*row=&Hs[0][a<<8];
                    for(int b=0;b<256;b++) if(row[b]) H2t[0][b^t]^=1;}
                int built1=0;
                for(int wlo0=0; wlo0<256; wlo0++){
                    int acc=0; for(int bp=0;bp<256;bp++) if(H2t[0][bp]) acc^=g1[bp^wlo0];
                    if(acc!=cst[0]) continue;
                    if(!built1){
                        for(int s=1;s<3;s++){memset(H2t[s],0,256);
                            for(int a=0;a<256;a++){int t=g1[a^whi0]; uint8_t*row=&Hs[s][a<<8];
                                for(int b=0;b<256;b++) if(row[b]) H2t[s][b^t]^=1;}}
                        built1=1;
                    }
                    int ok=1;
                    for(int s=1;s<3;s++){int ac=0; for(int bp=0;bp<256;bp++) if(H2t[s][bp]) ac^=g1[bp^wlo0]; if(ac!=cst[s]){ok=0;break;}}
                    if(ok){
                        long idx=__sync_fetch_and_add(&NC,1);
                        if(idx<MAXC){CW2[0][idx]=whi2;CW2[1][idx]=wlo2;CW2[2][idx]=whi0;CW2[3][idx]=wlo0;}
                    }
                }
            }
            #pragma omp atomic
            prog++;
            if((prog&0xfff)==0){ struct timespec ts1;clock_gettime(CLOCK_MONOTONIC,&ts1);
                double dt=(ts1.tv_sec-ts0.tv_sec); 
                fprintf(stderr,"[..] %d/65536 outer done, %.0fs, NC=%ld\n",prog,dt,NC);}
        }
        for(int s=0;s<3;s++) free(Hs[s]);
    }
    fprintf(stderr,"[*] search done, %ld raw candidates; filtering on set3\n",NC);
    long nc=NC; if(nc>MAXC) nc=MAXC;
    // filter candidates on set 3
    int fw[4]={-1,-1,-1,-1}; long nsurv=0;
    for(long i=0;i<nc;i++){
        if(balance_set(3,CW2[0][i],CW2[1][i],CW2[2][i],CW2[3][i])==0){
            fw[0]=CW2[0][i];fw[1]=CW2[1][i];fw[2]=CW2[2][i];fw[3]=CW2[3][i]; nsurv++;
            fprintf(stderr,"[+] survivor whi2=%02x wlo2=%02x whi0=%02x wlo0=%02x\n",fw[0],fw[1],fw[2],fw[3]);
            // brute the other 4 bytes against known PC
            uint32_t base_lo=(fw[3]<<24)|(fw[1]<<8), base_hi=(fw[2]<<24)|(fw[0]<<8);
            #pragma omp parallel for schedule(dynamic) collapse(2)
            for(int wlo1=0;wlo1<256;wlo1++) for(int wlo3=0;wlo3<256;wlo3++)
              for(int whi1=0;whi1<256;whi1++) for(int whi3=0;whi3<256;whi3++){
                uint32_t w2lo=base_lo|(wlo1<<16)|wlo3, w2hi=base_hi|(whi1<<16)|whi3;
                uint32_t kk0=rol(w2lo,2),kk1=rol(w2hi,2);
                uint32_t cl,ch; enc(plo,phi,kk0,kk1,&cl,&ch);
                if(cl==kclo&&ch==kchi){
                    uint32_t dlo,dhi; dec(tlo,thi,kk0,kk1,&dlo,&dhi);
                    #pragma omp critical
                    { fprintf(stderr,"[+] KEY k0=%08x k1=%08x\n",kk0,kk1);
                      printf("RECOVERED=%08x%08x  TRUE=%08x%08x  %s\n",dlo,dhi,flo,fhi,
                             (dlo==flo&&dhi==fhi)?"SUCCESS-FLAG-MATCH":"MISMATCH"); }
                }
              }
        }
    }
    fprintf(stderr,"[*] survivors=%ld\n",nsurv);
    return 0;
}
