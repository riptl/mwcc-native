#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define ERROR_ACCESS_DENIED 5

extern char __pe_text_start[];

int
main( void ) {
  __attribute__((cdecl)) void(*FUN_00418130)() = (void(*)())(__pe_text_start + 0x17130);
  printf( "__builtin_return_address() = %p\n", __builtin_return_address( 0 ) );
  printf( "__pe_text_start = %p\n", __pe_text_start );
  printf( "FUN_00418130    = %p\n", FUN_00418130    );
  printf( "*FUN_00418130   = %02x %02x %02x %02x %02x %02x %02x %02x\n",
          ((uint8_t*)FUN_00418130)[0],
          ((uint8_t*)FUN_00418130)[1],
          ((uint8_t*)FUN_00418130)[2],
          ((uint8_t*)FUN_00418130)[3],
          ((uint8_t*)FUN_00418130)[4],
          ((uint8_t*)FUN_00418130)[5],
          ((uint8_t*)FUN_00418130)[6],
          ((uint8_t*)FUN_00418130)[7] );
  puts( "Calling FUN_00418130" );
  FUN_00418130();
}

__attribute__((stdcall)) int32_t
ADVAPI32_RegOpenKeyExA( void *       h_key,
                        const char * lp_sub_key,
                        uint32_t     ul_options,
                        uint32_t     sam_desired,
                        void **      phk_result ) {
  puts( "ADVAPI32_RegOpenKeyExA" );
  return ERROR_ACCESS_DENIED;
}

__attribute__((stdcall)) int32_t
ADVAPI32_RegQueryValueExA( void *       h_key,
                           const char * lp_value_name,
                           uint32_t *   lp_reserved,
                           uint32_t *   lp_type,
                           uint8_t *    lp_data,
                           uint32_t *   lpcb_data ) {
  puts( "ADVAPI32_RegQueryValueExA" );
  return ERROR_ACCESS_DENIED;
}

__attribute__((stdcall)) int32_t
ADVAPI32_RegCloseKey( void * h_key ) {
  puts( "ADVAPI32_RegCloseKey" );
  return ERROR_ACCESS_DENIED;
}

__attribute__((stdcall)) int32_t
KERNEL32_IsBadReadPtr( const void * lp,
                       uint32_t     ucb ) {
  puts( "KERNEL32_IsBadReadPtr" );
  return 1;
}

__attribute__((stdcall)) void
KERNEL32_RtlUnwind( void *       target_frame,
                    void *       target_ip,
                    void *       exception_record,
                    void *       return_value ) {
  puts( "KERNEL32_RtlUnwind" );
}

__attribute__((stdcall)) void
KERNEL32_ExitProcess( uint32_t exit_code ) {
  exit( exit_code );
}

__attribute__((stdcall)) int32_t
KERNEL32_GetCurrentProcess( void ) {
  puts( "KERNEL32_GetCurrentProcess" );
  return 0;
}

__attribute__((stdcall)) int32_t
KERNEL32_DuplicateHandle( void * h_source_process_handle,
                          void * h_source_handle,
                          void * h_target_process_handle,
                          void ** lp_target_handle,
                          uint32_t dw_desired_access,
                          int32_t b_inherit_handle,
                          uint32_t dw_options ) {
  puts( "KERNEL32_DuplicateHandle" );
  return 0;
}

__attribute__((stdcall)) int32_t
KERNEL32_GetLastError( void ) {
  puts( "KERNEL32_GetLastError" );
  return 0;
}

__attribute__((stdcall)) int32_t
KERNEL32_GetStdHandle( uint32_t n_std_handle ) {
  puts( "KERNEL32_GetStdHandle" );
  return 0;
}

__attribute__((stdcall)) void
KERNEL32_InitializeCriticalSection( void * lp_critical_section ) {
  printf( "KERNEL32_InitializeCriticalSection(%p)\n", lp_critical_section );
}

__attribute__((stdcall)) void
KERNEL32_DeleteCriticalSection( void * lp_critical_section ) {
  printf( "KERNEL32_DeleteCriticalSection(%p)\n", lp_critical_section );
}

__attribute__((stdcall)) void
KERNEL32_EnterCriticalSection( void * lp_critical_section ) {
  printf( "KERNEL32_EnterCriticalSection(%p)\n", lp_critical_section );
}

__attribute__((stdcall)) void
KERNEL32_LeaveCriticalSection( void * lp_critical_section ) {
  printf( "KERNEL32_LeaveCriticalSection(%p)\n", lp_critical_section );
}

__attribute__((stdcall)) uint32_t
KERNEL32_FindFirstFileA( const char * lp_file_name,
                         void *       lp_find_file_data ) {
  printf( "KERNEL32_FindFirstFileA(%s, %p)\n", lp_file_name, lp_find_file_data );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetFileAttributesA( const char * lp_file_name ) {
  printf( "KERNEL32_GetFileAttributesA(%p)", lp_file_name );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_FindNextFileA( uint32_t     h_find_file,
                        void *       lp_find_file_data ) {
  printf( "KERNEL32_FindNextFileA(%u, %p)\n", h_find_file, lp_find_file_data );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_FindClose( uint32_t h_find_file ) {
  printf( "KERNEL32_FindClose(%u)\n", h_find_file );
  return 0;
}

__attribute__((stdcall)) char *
KERNEL32_GetCommandLineA( void ) {
  puts( "KERNEL32_GetCommandLineA" );
  return "";
}

__attribute__((stdcall)) char *
KERNEL32_GetEnvironmentStrings( void ) {
  puts( "KERNEL32_GetEnvironmentStrings" );
  return "";
}

__attribute__((stdcall)) int
KERNEL32_FreeEnvironmentStringsA( char * lpsz_environment_block ) {
  printf( "KERNEL32_FreeEnvironmentStringsA(%p)\n", lpsz_environment_block );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetCurrentDirectoryA( uint32_t n_buffer_length,
                               char *   lp_buffer ) {
  printf( "KERNEL32_GetCurrentDirectoryA(%u, %p)\n", n_buffer_length, lp_buffer );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_CreateProcessA( const char * lp_application_name,
                         char *       lp_command_line,
                         void *       lp_process_attributes,
                         void *       lp_thread_attributes,
                         int32_t      b_inherit_handles,
                         uint32_t     dw_creation_flags,
                         void *       lp_environment,
                         const char * lp_current_directory,
                         void *       lp_startup_info,
                         void *       lp_process_information ) {
  printf( "KERNEL32_CreateProcessA(%p, %p, %p, %p, %d, %u, %p, %p, %p, %p)\n",
          lp_application_name,
          lp_command_line,
          lp_process_attributes,
          lp_thread_attributes,
          b_inherit_handles,
          dw_creation_flags,
          lp_environment,
          lp_current_directory,
          lp_startup_info,
          lp_process_information );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_WaitForSingleObject( uint32_t h_handle,
                              uint32_t dw_milliseconds ) {
  printf( "KERNEL32_WaitForSingleObject(%u, %u)\n", h_handle, dw_milliseconds );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_GetExitCodeProcess( uint32_t h_process,
                             uint32_t * lp_exit_code ) {
  printf( "KERNEL32_GetExitCodeProcess(%u, %p)\n", h_process, lp_exit_code );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_CloseHandle( uint32_t h_object ) {
  printf( "KERNEL32_CloseHandle(%u)\n", h_object );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_TlsAlloc( void ) {
  puts( "KERNEL32_TlsAlloc" );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_TlsFree( uint32_t dw_tls_index ) {
  printf( "KERNEL32_TlsFree(%u)\n", dw_tls_index );
  return 0;
}

__attribute__((stdcall)) void *
KERNEL32_TlsGetValue( uint32_t dw_tls_index ) {
  printf( "KERNEL32_TlsGetValue(%u)\n", dw_tls_index );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_TlsSetValue( uint32_t dw_tls_index,
                      void *   lp_tls_value ) {
  printf( "KERNEL32_TlsSetValue(%u, %p)\n", dw_tls_index, lp_tls_value );
  return 0;
}

__attribute__((stdcall)) void *
KERNEL32_GetModuleHandleA( const char * lp_module_name ) {
  printf( "KERNEL32_GetModuleHandleA(%p)\n", lp_module_name );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetModuleFileNameA( void *   h_module,
                             char *   lp_file_name,
                             uint32_t n_size ) {
  printf( "KERNEL32_GetModuleFileNameA(%p, %p, %u)\n", h_module, lp_file_name, n_size );
  return 0;
}

__attribute__((stdcall)) void *
KERNEL32_LoadLibraryA( const char * lp_lib_file_name ) {
  printf( "KERNEL32_LoadLibraryA(%p)\n", lp_lib_file_name );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_FreeLibrary( void * h_lib_module ) {
  printf( "KERNEL32_FreeLibrary(%p)\n", h_lib_module );
  return 0;
}

__attribute__((stdcall)) int32_t *
KERNEL32_GlobalAlloc( uint32_t u_flags,
                      uint32_t dw_bytes ) {
  printf( "KERNEL32_GlobalAlloc(%u, %u)\n", u_flags, dw_bytes );
  return 0;
}

__attribute__((stdcall)) int32_t *
KERNEL32_GlobalFree( int32_t * h_mem ) {
  printf( "KERNEL32_GlobalFree(%p)\n", h_mem );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetFullPathNameA( const char * lp_file_name,
                           uint32_t     n_buffer_length,
                           char *       lp_buffer,
                           char **      lp_file_part ) {
  printf( "KERNEL32_GetFullPathNameA(%p, %u, %p, %p)\n",
          lp_file_name,
          n_buffer_length,
          lp_buffer,
          lp_file_part );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_SetFilePointer( uint32_t h_file,
                         int32_t  l_distance_to_move,
                         int32_t * lp_distance_to_move_high,
                         uint32_t dw_move_method ) {
  printf( "KERNEL32_SetFilePointer(%u, %d, %p, %u)\n",
          h_file,
          l_distance_to_move,
          lp_distance_to_move_high,
          dw_move_method );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_WriteFile( uint32_t h_file,
                    const void * lp_buffer,
                    uint32_t n_number_of_bytes_to_write,
                    uint32_t * lp_number_of_bytes_written,
                    void * lp_overlapped ) {
  printf( "KERNEL32_WriteFile(%u, %p, %u, %p, %p)\n",
          h_file,
          lp_buffer,
          n_number_of_bytes_to_write,
          lp_number_of_bytes_written,
          lp_overlapped );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_ReadFile( uint32_t h_file,
                   void *   lp_buffer,
                   uint32_t n_number_of_bytes_to_read,
                   uint32_t * lp_number_of_bytes_read,
                   void *   lp_overlapped ) {
  printf( "KERNEL32_ReadFile(%u, %p, %u, %p, %p)\n",
          h_file,
          lp_buffer,
          n_number_of_bytes_to_read,
          lp_number_of_bytes_read,
          lp_overlapped );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_CreateFileA( const char * lp_file_name,
                      uint32_t     dw_desired_access,
                      uint32_t     dw_share_mode,
                      void *       lp_security_attributes,
                      uint32_t     dw_creation_disposition,
                      uint32_t     dw_flags_and_attributes,
                      uint32_t     h_template_file ) {
  printf( "KERNEL32_CreateFileA(%p, %u, %u, %p, %u, %u, %u)\n",
          lp_file_name,
          dw_desired_access,
          dw_share_mode,
          lp_security_attributes,
          dw_creation_disposition,
          dw_flags_and_attributes,
          h_template_file );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetTickCount( void ) {
  printf( "KERNEL32_GetTickCount()\n" );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_DeleteFileA( const char * lp_file_name ) {
  printf( "KERNEL32_DeleteFileA(%p)\n", lp_file_name );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_MoveFileA( const char * lp_existing_file_name,
                    const char * lp_new_file_name ) {
  printf( "KERNEL32_MoveFileA(%p, %p)\n", lp_existing_file_name, lp_new_file_name );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_FormatMessageA( uint32_t   dw_flags,
                         void *     lp_source,
                         uint32_t   dw_message_id,
                         uint32_t   dw_language_id,
                         char *     lp_buffer,
                         uint32_t   n_size,
                         va_list * arguments ) {
  printf( "KERNEL32_FormatMessageA(%u, %p, %u, %u, %p, %u, %p)\n",
          dw_flags,
          lp_source,
          dw_message_id,
          dw_language_id,
          lp_buffer,
          n_size,
          arguments );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_GetFileTime( uint32_t h_file,
                      void * lp_creation_time,
                      void * lp_last_access_time,
                      void * lp_last_write_time ) {
  printf( "KERNEL32_GetFileTime(%u, %p, %p, %p)\n",
          h_file,
          lp_creation_time,
          lp_last_access_time,
          lp_last_write_time );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_SetFileTime( uint32_t h_file,
                      void * lp_creation_time,
                      void * lp_last_access_time,
                      void * lp_last_write_time ) {
  printf( "KERNEL32_SetFileTime(%u, %p, %p, %p)\n",
          h_file,
          lp_creation_time,
          lp_last_access_time,
          lp_last_write_time );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetFileSize( uint32_t h_file,
                      uint32_t * lp_file_size_high ) {
  printf( "KERNEL32_GetFileSize(%u, %p)\n", h_file, lp_file_size_high );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_SetEndOfFile( uint32_t h_file ) {
  printf( "KERNEL32_SetEndOfFile(%u)\n", h_file );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_CreateDirectoryA( const char * lp_path_name,
                           void *       lp_security_attributes ) {
  printf( "KERNEL32_CreateDirectoryA(%p, %p)\n", lp_path_name, lp_security_attributes );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_RemoveDirectoryA( const char * lp_path_name ) {
  printf( "KERNEL32_RemoveDirectoryA(%p)\n", lp_path_name );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_SetStdHandle( uint32_t n_std_handle,
                       uint32_t h_handle ) {
  printf( "KERNEL32_SetStdHandle(%u, %u)\n", n_std_handle, h_handle );
  return 0;
}

__attribute__((stdcall)) void
KERNEL32_GetSystemTime( void * lp_system_time ) {
  printf( "KERNEL32_GetSystemTime(%p)\n", lp_system_time );
}

__attribute__((stdcall)) int
KERNEL32_SystemTimeToFileTime( void * lp_system_time,
                               void * lp_file_time ) {
  printf( "KERNEL32_SystemTimeToFileTime(%p, %p)\n", lp_system_time, lp_file_time );
  return 0;
}

__attribute__((stdcall)) int32_t
KERNEL32_CompareFileTime( void * lp_file_time_1,
                          void * lp_file_time_2 ) {
  printf( "KERNEL32_CompareFileTime(%p, %p)\n", lp_file_time_1, lp_file_time_2 );
  return 0;
}

__attribute__((stdcall)) int32_t *
KERNEL32_GlobalReAlloc( int32_t * h_mem,
                        uint32_t  u_bytes,
                        uint32_t  u_flags ) {
  printf( "KERNEL32_GlobalReAlloc(%p, %u, %u)\n", h_mem, u_bytes, u_flags );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GlobalFlags( int32_t * h_mem ) {
  printf( "KERNEL32_GlobalFlags(%p)\n", h_mem );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_FileTimeToSystemTime( void * lp_file_time,
                               void * lp_system_time ) {
  printf( "KERNEL32_FileTimeToSystemTime(%p, %p)\n", lp_file_time, lp_system_time );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_FindResourceA( uint32_t h_module,
                        const char * lp_name,
                        const char * lp_type ) {
  printf( "KERNEL32_FindResourceA(%u, %p, %p)\n", h_module, lp_name, lp_type );
  return 0;
}

__attribute__((stdcall)) int32_t *
KERNEL32_LoadResource( uint32_t h_module,
                       uint32_t h_resource ) {
  printf( "KERNEL32_LoadResource(%u, %u)\n", h_module, h_resource );
  return 0;
}

__attribute__((stdcall)) void *
KERNEL32_LockResource( int32_t * h_resource ) {
  printf( "KERNEL32_LockResource(%p)\n", h_resource );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_SizeofResource( uint32_t h_module,
                         uint32_t h_resource ) {
  printf( "KERNEL32_SizeofResource(%u, %u)\n", h_module, h_resource );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_CreateFileMappingA( uint32_t h_file,
                             void *   lp_file_mapping_attributes,
                             uint32_t fl_protect,
                             uint32_t dw_maximum_size_high,
                             uint32_t dw_maximum_size_low,
                             const char * lp_name ) {
  printf( "KERNEL32_CreateFileMappingA(%u, %p, %u, %u, %u, %p)\n",
          h_file,
          lp_file_mapping_attributes,
          fl_protect,
          dw_maximum_size_high,
          dw_maximum_size_low,
          lp_name );
  return 0;
}

__attribute__((stdcall)) int32_t *
KERNEL32_MapViewOfFile( uint32_t h_file_mapping_object,
                        uint32_t dw_desired_access,
                        uint32_t dw_file_offset_high,
                        uint32_t dw_file_offset_low,
                        uint32_t dw_number_of_bytes_to_map ) {
  printf( "KERNEL32_MapViewOfFile(%u, %u, %u, %u, %u)\n",
          h_file_mapping_object,
          dw_desired_access,
          dw_file_offset_high,
          dw_file_offset_low,
          dw_number_of_bytes_to_map );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_UnmapViewOfFile( int32_t * lp_base_address ) {
  printf( "KERNEL32_UnmapViewOfFile(%p)\n", lp_base_address );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetSystemDirectoryA( char * lp_buffer,
                              uint32_t u_size ) {
  printf( "KERNEL32_GetSystemDirectoryA(%p, %u)\n", lp_buffer, u_size );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetWindowsDirectoryA( char * lp_buffer,
                               uint32_t u_size ) {
  printf( "KERNEL32_GetWindowsDirectoryA(%p, %u)\n", lp_buffer, u_size );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_SetConsoleCtrlHandler( void * lp_handler_routine,
                                int    b_add ) {
  printf( "KERNEL32_SetConsoleCtrlHandler(%p, %u)\n", lp_handler_routine, b_add );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_GetConsoleScreenBufferInfo( uint32_t h_console_output,
                                     void *   lp_console_screen_buffer_info ) {
  printf( "KERNEL32_GetConsoleScreenBufferInfo(%u, %p)\n", h_console_output, lp_console_screen_buffer_info );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_SetFileAttributesA( const char * lp_file_name,
                             uint32_t     dw_file_attributes ) {
  printf( "KERNEL32_SetFileAttributesA(%p, %u)\n", lp_file_name, dw_file_attributes );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_OpenFileMappingA( uint32_t dw_desired_access,
                           int      b_inherit_handle,
                           const char * lp_name ) {
  printf( "KERNEL32_OpenFileMappingA(%u, %u, %p)\n", dw_desired_access, b_inherit_handle, lp_name );
  return 0;
}

__attribute__((stdcall)) int32_t
KERNEL32_MultiByteToWideChar( uint32_t   u_code_page,
                              uint32_t   dw_flags,
                              const char * lp_multi_byte_str,
                              int        cch_multi_byte,
                              void *     lp_wide_char_str,
                              int        cch_wide_char ) {
  printf( "KERNEL32_MultiByteToWideChar(%u, %u, %p, %u, %p, %u)\n",
          u_code_page,
          dw_flags,
          lp_multi_byte_str,
          cch_multi_byte,
          lp_wide_char_str,
          cch_wide_char );
  return 0;
}

__attribute__((stdcall)) int
KERNEL32_IsValidCodePage( uint32_t u_code_page ) {
  printf( "KERNEL32_IsValidCodePage(%u)\n", u_code_page );
  return 0;
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetACP( void ) {
  printf( "KERNEL32_GetACP()\n" );
  return 0;
}

__attribute__((stdcall)) void
KERNEL32_GetLocalTime( void * lp_system_time ) {
  printf( "KERNEL32_GetLocalTime(%p)\n", lp_system_time );
}

__attribute__((stdcall)) uint32_t
KERNEL32_GetTimeZoneInformation( void * lp_time_zone_information ) {
  printf( "KERNEL32_GetTimeZoneInformation(%p)\n", lp_time_zone_information );
  return 0;
}

__attribute__((stdcall)) int32_t
LMGR8C_6d4394( void ) {
  printf( "LMGR8C_6d4394()\n" );
  return 0;
}

__attribute__((stdcall)) int32_t
LMGR8C_6d4398( void ) {
  printf( "LMGR8C_6d4398()\n" );
  return 0;
}

__attribute__((stdcall)) int32_t
LMGR8C_6d439c( void ) {
  printf( "LMGR8C_6d4398()\n" );
  return 0;
}

__attribute__((stdcall)) int
USER32_MessageBoxA( uint32_t    h_wnd,
                    const char * lp_text,
                    const char * lp_caption,
                    uint32_t    u_type ) {
  printf( "USER32_MessageBoxA(%u, %p, %p, %u)\n", h_wnd, lp_text, lp_caption, u_type );
  return 0;
}

__attribute__((stdcall)) int32_t
USER32_LoadStringA( uint32_t    h_instance,
                    uint32_t    u_id,
                    char *      lp_buffer,
                    int         n_buffer_max ) {
  printf( "USER32_LoadStringA(%u, %u, %p, %u)\n", h_instance, u_id, lp_buffer, n_buffer_max );
  return 0;
}

__attribute__((stdcall)) uint32_t
VERSION_GetFileVersionInfoSizeA( const char * lptstr_filename,
                                 uint32_t *   lpdw_handle ) {
  printf( "VERSION_GetFileVersionInfoSizeA(%p, %p)\n", lptstr_filename, lpdw_handle );
  return 0;
}

__attribute__((stdcall)) int
VERSION_GetFileVersionInfoA( const char * lptstr_filename,
                             uint32_t     dw_handle,
                             uint32_t     dw_len,
                             void *       lp_data ) {
  printf( "VERSION_GetFileVersionInfoA(%p, %u, %u, %p)\n", lptstr_filename, dw_handle, dw_len, lp_data );
  return 0;
}

__attribute__((stdcall)) int
VERSION_VerQueryValueA( const void * p_block,
                        const char * lp_sub_block,
                        void **      lplp_buffer,
                        uint32_t *   pu_len ) {
  printf( "VERSION_VerQueryValueA(%p, %p, %p, %p)\n", p_block, lp_sub_block, lplp_buffer, pu_len );
  return 0;
}

__attribute__((stdcall)) int
ole32_CoInitialize( void * pv_reserved ) {
  printf( "ole32_CoInitialize(%p)\n", pv_reserved );
  return 0;
}

__attribute__((stdcall)) void
ole32_CoUninitialize( void ) {
  printf( "ole32_CoUninitialize()\n" );
}

__attribute__((stdcall)) int
ole32_CoCreateInstance( void *   rclsid,
                        void *   p_unk_outer,
                        uint32_t dw_cls_context,
                        void *   riid,
                        void **  ppv ) {
  printf( "ole32_CoCreateInstance(%p, %p, %u, %p, %p)\n", rclsid, p_unk_outer, dw_cls_context, riid, ppv );
  return 0;
}

__attribute__((stdcall)) void
ole32_CoTaskMemFree( void * pv ) {
  printf( "ole32_CoTaskMemFree(%p)\n", pv );
}

__attribute__((stdcall)) void *
ole32_CoTaskMemAlloc( uint32_t cb ) {
  printf( "ole32_CoTaskMemAlloc(%u)\n", cb );
  return 0;
}

// WS2_32_WSAStartup
__attribute__((stdcall)) int
WS2_32_6d43c0( uint16_t w_version_requested,
               void *   lp_wsa_data ) {
  printf( "WS2_32_WSAStartup(%u, %p)\n", w_version_requested, lp_wsa_data );
  return 0;
}

// WS2_32_WSAGetLastError
__attribute__((stdcall)) int
WS2_32_6d43c4( void ) {
  printf( "WS2_32_WSAGetLastError()\n" );
  return 0;
}

// WS2_32_ntohs
__attribute__((stdcall)) uint16_t
WS2_32_6d43c8( uint16_t netshort ) {
  printf( "WS2_32_ntohs(%u)\n", netshort );
  return 0;
}

// WS2_32_inet_ntoa
__attribute__((stdcall)) const char *
WS2_32_6d43cc( void * in_addr ) {
  printf( "WS2_32_inet_ntoa(%p)\n", in_addr );
  return 0;
}

// WS2_32_shutdown
__attribute__((stdcall)) int
WS2_32_6d43d0( uint32_t s,
               int      how ) {
  printf( "WS2_32_shutdown(%u, %u)\n", s, how );
  return 0;
}

// WS2_32_closesocket
__attribute__((stdcall)) int
WS2_32_6d43d4( uint32_t s ) {
  printf( "WS2_32_closesocket(%u)\n", s );
  return 0;
}

// WS2_32_WSACleanup
__attribute__((stdcall)) int
WS2_32_6d43d8( void ) {
  printf( "WS2_32_WSACleanup()\n" );
  return 0;
}

// WS2_32_socket
__attribute__((stdcall)) uint32_t
WS2_32_6d43dc( int af,
               int type,
               int protocol ) {
  printf( "WS2_32_socket(%u, %u, %u)\n", af, type, protocol );
  return 0;
}

// WS2_32_htons
__attribute__((stdcall)) uint16_t
WS2_32_6d43e0( uint16_t hostshort ) {
  printf( "WS2_32_htons(%u)\n", hostshort );
  return 0;
}

// WS2_32_inet_addr
__attribute__((stdcall)) uint32_t
WS2_32_6d43e4( const char * cp ) {
  printf( "WS2_32_inet_addr(%p)\n", cp );
  return 0;
}

// WS2_32_connect
__attribute__((stdcall)) int
WS2_32_6d43e8( uint32_t s,
               void *   name,
               int      namelen ) {
  printf( "WS2_32_connect(%u, %p, %u)\n", s, name, namelen );
  return 0;
}

// WS2_32_select
__attribute__((stdcall)) int
WS2_32_6d43ec( int          nfds,
               void *       readfds,
               void *       writefds,
               void *       exceptfds,
               void *       timeout ) {
  printf( "WS2_32_select(%u, %p, %p, %p, %p)\n", nfds, readfds, writefds, exceptfds, timeout );
  return 0;
}

// WS2_32___WSAFDIsSet
__attribute__((stdcall)) int
WS2_32_6d43f0( uint32_t s,
               void *   fd_set ) {
  printf( "WS2_32___WSAFDIsSet(%u, %p)\n", s, fd_set );
  return 0;
}

// WS2_32_send
__attribute__((stdcall)) int
WS2_32_6d43f4( uint32_t s,
               void *   buf,
               int      len,
               int      flags ) {
  printf( "WS2_32_send(%u, %p, %u, %u)\n", s, buf, len, flags );
  return 0;
}

// WS2_32_recv
__attribute__((stdcall)) int
WS2_32_6d43f8( uint32_t s,
               void *   buf,
               int      len,
               int      flags ) {
  printf( "WS2_32_recv(%u, %p, %u, %u)\n", s, buf, len, flags );
  return 0;
}
