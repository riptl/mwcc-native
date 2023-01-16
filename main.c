#include "compat.h"

#include <stddef.h>
#include <stdio.h>

int
main( void ) {
  size_t orig_text_start   = 0x401000;
  size_t orig_FUN_004031b0 = 0x4031b0;

  printf( "__builtin_return_address() = %p\n", __builtin_return_address( 0 ) );

  printf( "__pe_text_start       = %p\n", __pe_text_start       ); // 0x804820f
  printf( "__pe_data_start       = %p\n", __pe_data_start       ); // 0x82a7024
  printf( "__pe_data_idata_start = %p\n", __pe_data_idata_start ); // 0x830d424

  void (* FUN_004031b0)( void ) = (void *)( orig_FUN_004031b0 - orig_text_start + __pe_text_start );
  FUN_004031b0();

  puts( "It works!" );
}
