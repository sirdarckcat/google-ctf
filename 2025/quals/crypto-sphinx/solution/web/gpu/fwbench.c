/* minimal CPU baseline: one uint32 FWHT over 2^24 elements, wrapping mod 2^32 */
typedef unsigned int u32;
#define EXPORT __attribute__((visibility("default"),used))
static u32 LOGN=24;
static u32 A[1u<<24];
EXPORT u32* buf(void){return A;}
EXPORT u32 n(void){return 1u<<LOGN;}
EXPORT void seed(u32 s){ u32 x=s?s:1; for(u32 i=0;i<(1u<<LOGN);i++){x^=x<<13;x^=x>>17;x^=x<<5;A[i]=x;} }
EXPORT void run(u32 logn){
    u32 N=1u<<logn;
    for(u32 h=1;h<N;h<<=1)
        for(u32 i=0;i<N;i+=h<<1)
            for(u32 j=i;j<i+h;j++){u32 x=A[j],y=A[j+h];A[j]=x+y;A[j+h]=x-y;}
}
/* FWHT outputs accumulate factors of 2, so the low bits go to zero; fold the high
   bits down or the checksum would be insensitive to exactly the bits we rely on. */
EXPORT u32 checksum(u32 logn){
    u32 s=0x811c9dc5u,N=1u<<logn;
    for(u32 i=0;i<N;i++){ s^=A[i]; s=(s<<5)|(s>>27); s*=2654435761u; s^=s>>15; }
    return s;
}
