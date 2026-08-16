#include <zlib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void){
  z_stream s; memset(&s,0,sizeof(s));
  if(deflateInit2(&s,7,Z_DEFLATED,15,1,Z_FIXED)!=Z_OK)return 1;
  size_t n=1<<18; unsigned char*in=malloc(n),*out=malloc(n*2);
  for(size_t i=0;i<n;i++)in[i]=(i*2654435761u)>>24;
  s.next_in=in;s.avail_in=n;s.next_out=out;s.avail_out=n*2;
  int r=deflate(&s,Z_FINISH); deflateEnd(&s);
  printf("deflate ret=%d\n",r); return 0;
}
