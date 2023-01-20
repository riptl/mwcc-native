#include "compat.h"

#include <asm/prctl.h>     
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <immintrin.h>

int
main( int     argc,
      char ** argv ) {
  fprintf( stderr, "__builtin_return_address() = %p\n", __builtin_return_address( 0 ) );

  fprintf( stderr, "__pe_text_start       = %p\n", __pe_text_start       ); // 0x804820f
  fprintf( stderr, "__pe_data_start       = %p\n", __pe_data_start       ); // 0x82a7024
  fprintf( stderr, "__pe_data_idata_start = %p\n", __pe_data_idata_start ); // 0x830d424

  g_argc = argc;
  g_argv = argv;

  __pe_text_start_enter();
}
