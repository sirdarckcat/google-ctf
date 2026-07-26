/* How long does it take to BUILD the 16 transformed bit-planes once?
   If that is cheap, there is no reason to download them. */
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "sboxes.h"
#define N24 (1u<<24)
static inline uint32_t B(uint32_t x,int i){return (x>>(8*(3-i)))&0xff;}
static uint8_t g5[N24],g7[N24];
static uint32_t W[N24];
static void fwht(uint32_t*a){
    for(uint32_t h=1;h<N24;h<<=1)
      for(uint32_t i=0;i<N24;i+=h<<1)
        for(uint32_t j=i;j<i+h;j++){uint32_t x=a[j],y=a[j+h];a[j]=x+y;a[j+h]=x-y;}
}
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
int main(void){
    double t0=now();
    for(uint32_t A=0;A<256;A++){uint32_t s1=B(SB1[A],1),s3=B(SB1[A],3);
      for(uint32_t Bb=0;Bb<256;Bb++){uint32_t in=B(SB1[Bb^s1],1);
        for(uint32_t D=0;D<256;D++){uint32_t i=(A<<16)|(Bb<<8)|D,M=D^in;
          g5[i]=(uint8_t)(s3^B(SB1[M],1)); g7[i]=(uint8_t)(s1^B(SB1[M],3));}}}
    printf("build g5+g7 tables      : %.2f s\n",now()-t0);
    double t1=now();
    for(int which=0;which<2;which++){
      const uint8_t*g=which?g7:g5;
      for(int bit=0;bit<8;bit++){
        for(uint32_t i=0;i<N24;i++) W[i]=(g[i]>>bit)&1u;
        fwht(W);
      }
    }
    double d=now()-t1;
    printf("transform 16 bit-planes : %.2f s  (%.0f ms each)\n",d,d/16*1000);
    printf("\ntotal one-time cost to have all 16 planes resident: %.2f s\n",now()-t0);
    printf("versus downloading 232 MB gzipped:\n");
    for(int m=0;m<3;m++){int mb[3]={25,100,500}; printf("   %3d Mbps -> %.0f s\n",mb[m],232.0*8/mb[m]);}
    return 0;
}
