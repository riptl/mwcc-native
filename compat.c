#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "compat.h"

extern char **      environ;
extern char const * __progname;

int     g_argc;
char ** g_argv;

static int g_last_error = ERROR_SUCCESS;

/* Dummy markers */
static int g_cur_module;
static int g_cur_library;

static __thread uint32_t win_last_error;

static FORCEINLINE HANDLE WINAPI GetProcessHeap(void)
{
    return ((HANDLE **)NtCurrentTeb())[12][6];
}

static inline void SetLastError( uint32_t err )
{
  win_last_error = err;
}

 SECTION_IMAGE_INFORMATION main_image_info = { NULL };
HMODULE ntdll_module = 0;
SYSTEM_SERVICE_TABLE KeServiceDescriptorTable[4];

USHORT native_machine = 0;
BOOL process_exiting = FALSE;
sigset_t server_block_set;
int is_wow64 = 0;
SYSTEM_CPU_INFORMATION cpu_info;

NTSYSAPI NTSTATUS WINAPI NtOpenSection(HANDLE*,ACCESS_MASK,const OBJECT_ATTRIBUTES*) {
  puts( "NtOpenSection" );
  return 0;
}


NTSYSAPI NTSTATUS WINAPI NtQueryInformationProcess(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG) {
  puts( "NtQueryInformationProcess" );
  return 0;
}

NTSYSAPI NTSTATUS  WINAPI NtTerminateProcess(HANDLE,LONG) {
  puts( "NtTerminateProcess" );
  return 0;
}

NTSYSAPI NTSTATUS  WINAPI NtWaitForSingleObject(HANDLE,BOOLEAN,const LARGE_INTEGER*) {
  puts( "NtWaitForSingleObject" );
  return 0;
}

NTSYSAPI ULONG WINAPI RtlGetNtGlobalFlags(void) {
  puts( "RtlGetNtGlobalFlags" );
  return 0;
}

NTSYSAPI NTSTATUS  WINAPI NtContinue(PCONTEXT,BOOLEAN) {
  puts( "NtContinue" );
  return 0;
}

NTSYSAPI NTSTATUS  WINAPI NtOpenProcess(PHANDLE,ACCESS_MASK,const OBJECT_ATTRIBUTES*,const CLIENT_ID*) {
  puts( "NtOpenProcess" );
  return 0;
}

NTSYSAPI NTSTATUS  WINAPI NtClose(HANDLE) {
  puts( "NtClose" );
  return 0;
}

NTSYSAPI NTSTATUS  WINAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS,PVOID,ULONG,PULONG) {
  puts( "NtQuerySystemInformation" );
  return 0;
}

NTSYSAPI NTSTATUS  WINAPI RtlInitializeCriticalSection(RTL_CRITICAL_SECTION *) {
  puts( "RtlInitializeCriticalSection" );
  return 0;
}

NTSYSAPI NTSTATUS  WINAPI RtlDeleteCriticalSection(RTL_CRITICAL_SECTION *) {
  puts( "RtlDeleteCriticalSection" );
  return 0;
}

__attribute__((stdcall))
int32_t
ADVAPI32_RegOpenKeyExA( uint32_t     h_key,
                        char const * lp_sub_key,
                        uint32_t     ul_options,
                        uint32_t     sam_desired,
                        void **      phk_result ) {

  char const * hkey_name;
  switch( h_key ) {
  case (uint32_t)HKEY_CLASSES_ROOT     : hkey_name = "HKEY_CLASSES_ROOT"     ; break;
  case (uint32_t)HKEY_CURRENT_USER     : hkey_name = "HKEY_CURRENT_USER"     ; break;
  case (uint32_t)HKEY_LOCAL_MACHINE    : hkey_name = "HKEY_LOCAL_MACHINE"    ; break;
  case (uint32_t)HKEY_USERS            : hkey_name = "HKEY_USERS"            ; break;
  case (uint32_t)HKEY_PERFORMANCE_DATA : hkey_name = "HKEY_PERFORMANCE_DATA" ; break;
  case (uint32_t)HKEY_CURRENT_CONFIG   : hkey_name = "HKEY_CURRENT_CONFIG"   ; break;
  case (uint32_t)HKEY_DYN_DATA         : hkey_name = "HKEY_DYN_DATA"         ; break;
  default                    : hkey_name = "<unknown>"             ; break;
  }

  fprintf( stderr, "ADVAPI32_RegOpenKeyExA(%s (%p), \"%s\", %x, %x, %p)\n",
          hkey_name, h_key,
          lp_sub_key,
          ul_options,
          sam_desired,
          phk_result );
  return ERROR_ACCESS_DENIED;
}

__attribute__((stdcall))
int32_t
ADVAPI32_RegQueryValueExA( void *       h_key,
                           char const * lp_value_name,
                           uint32_t *   lp_reserved,
                           uint32_t *   lp_type,
                           uint8_t *    lp_data,
                           uint32_t *   lpcb_data ) {
  puts( "ADVAPI32_RegQueryValueExA" );
  return ERROR_ACCESS_DENIED;
}

__attribute__((stdcall))
int32_t
ADVAPI32_RegCloseKey( void * h_key ) {
  puts( "ADVAPI32_RegCloseKey" );
  return ERROR_ACCESS_DENIED;
}

__attribute__((stdcall))
int32_t
KERNEL32_IsBadReadPtr( void const * lp,
                       uint32_t     ucb ) {
  puts( "KERNEL32_IsBadReadPtr" );
  return 1;
}

__attribute__((stdcall))
void
KERNEL32_RtlUnwind( void * target_frame,
                    void * target_ip,
                    void * exception_record,
                    void * return_value ) {
  puts( "KERNEL32_RtlUnwind" );
}

__attribute__((stdcall))
void
KERNEL32_ExitProcess( uint32_t exit_code ) {
  fprintf( stderr, "KERNEL32_ExitProcess(%d)\n", exit_code );
  exit( exit_code );
}

__attribute__((stdcall))
int32_t
KERNEL32_GetCurrentProcess( void ) {
  int32_t proc = -1;
  fprintf( stderr, "KERNEL32_GetCurrentProcess() = %d\n", proc );
  return proc;
}

__attribute__((stdcall))
int32_t
KERNEL32_DuplicateHandle( void *   h_source_process_handle,
                          void *   h_source_handle,
                          void *   h_target_process_handle,
                          void **  lp_target_handle,
                          uint32_t dw_desired_access,
                          int32_t  b_inherit_handle,
                          uint32_t dw_options ) {
  fprintf( stderr, "KERNEL32_DuplicateHandle(%p, %p, %p, %p, %x, %x, %x)\n",
          h_source_process_handle,
          h_source_handle,
          h_target_process_handle,
          lp_target_handle,
          dw_desired_access,
          b_inherit_handle,
          dw_options );
  return 0;
}

__attribute__((stdcall))
int32_t
KERNEL32_GetLastError( void ) {
  //fprintf( stderr, "KERNEL32_GetLastError() = %u\n", g_last_error );
  return g_last_error;
}

__attribute__((stdcall))
void *
KERNEL32_GetStdHandle( int32_t n_std_handle ) {
  switch( n_std_handle ) {
  case STD_INPUT_HANDLE  : return stdin;
  case STD_OUTPUT_HANDLE : return stdout;
  case STD_ERROR_HANDLE  : return stderr;
  default:
    fprintf( stderr, "KERNEL32_GetStdHandle(%p)\n", n_std_handle );
    return (void *)INVALID_HANDLE_VALUE;
  }
}

__attribute__((stdcall))
void
KERNEL32_InitializeCriticalSection( void * lp_critical_section ) {
# ifdef HAS_THREADS
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init( lp_critical_section, &attr );
# endif /* HAS_THREADS */
}

__attribute__((stdcall))
void
KERNEL32_DeleteCriticalSection( void * lp_critical_section ) {
# ifdef HAS_THREADS
  pthread_mutex_destroy( lp_critical_section );
# endif /* HAS_THREADS */
}

__attribute__((stdcall))
void
KERNEL32_EnterCriticalSection( void * lp_critical_section ) {
# ifdef HAS_THREADS
  fprintf( stderr, "KERNEL32_EnterCriticalSection(%p)\n", lp_critical_section );
  pthread_mutex_lock( lp_critical_section );
# endif /* HAS_THREADS */
}

__attribute__((stdcall))
void
KERNEL32_LeaveCriticalSection( void * lp_critical_section ) {
# ifdef HAS_THREADS
  pthread_mutex_unlock( lp_critical_section );
# endif /* HAS_THREADS */
}

__attribute__((stdcall))
uint32_t
KERNEL32_FindFirstFileA( char const * lp_file_name,
                         void *       lp_find_file_data ) {
  fprintf( stderr, "KERNEL32_FindFirstFileA(%s, %p)\n", lp_file_name, lp_find_file_data );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetFileAttributesA( char const * lp_file_name ) {
  fprintf( stderr, "KERNEL32_GetFileAttributesA(%s)\n", lp_file_name );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_FindNextFileA( uint32_t h_find_file,
                        void *   lp_find_file_data ) {
  fprintf( stderr, "KERNEL32_FindNextFileA(%u, %p)\n", h_find_file, lp_find_file_data );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_FindClose( uint32_t h_find_file ) {
  fprintf( stderr, "KERNEL32_FindClose(%u)\n", h_find_file );
  return 0;
}

__attribute__((stdcall))
char *
KERNEL32_GetCommandLineA( void ) {
  static char * cmd = NULL;
  if( cmd ) return cmd;

  int argc     = g_argc;
  char ** argv = g_argv;
  char x;

  /* Count number of chars required */
  int arglen = 1;
  for( int i=0; i<argc; i++ ) {
    arglen += 3; // quotes and space
    char * arg = argv[i];
    while( (x = *arg++) ) {
      if( *arg == '"' )
        arglen += 2;
      else
        arglen += 1;
    }
  }

  cmd = malloc( arglen );
  assert( cmd );

  char * c = cmd;
  for( int i=0; i<argc; i++ ) {
    *c++ = '"';
    char * arg = argv[i];
    while( (x = *arg++) ) {
      if( x == '"' ) {
        *c++ = '\\';
        *c++ = '"';
      } else {
        *c++ = x;
      }
    }
    *c++ = '"';
    *c++ = ' ';
  }
  *c = '\0';

  fprintf( stderr, "KERNEL32_GetCommandLineA() = %s\n", cmd );
  return cmd;
}

static char * g_envstr = NULL;

__attribute__((stdcall))
char *
KERNEL32_GetEnvironmentStrings( void ) {
  if( g_envstr ) return g_envstr;

  int envlen = 2;
  char ** env = environ;
  char * line;
  while( (line = *env++) ) {
    envlen += strlen( line ) + 1;
  }

  g_envstr = malloc( envlen );
  assert( g_envstr );
  char * s = g_envstr;

  env = environ;
  while( (line = *env++) ) {
    char x;
    while( (x = *line++) )
      *s++ = x;
    *s++ = '\0';
  }
  *s++ = '\0';

  assert( envlen >= (s - g_envstr) );
  return g_envstr;
}

__attribute__((stdcall))
int
KERNEL32_FreeEnvironmentStringsA( char * lpsz_environment_block ) {
  if( !g_envstr ) return 0;
  free( g_envstr );
  g_envstr = NULL;
  return 1;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetCurrentDirectoryA( uint32_t n_buffer_length,
                               char *   lp_buffer ) {
  fprintf( stderr, "KERNEL32_GetCurrentDirectoryA(%u, %p)\n", n_buffer_length, lp_buffer );
  snprintf( lp_buffer, n_buffer_length, "." );
  g_last_error = ERROR_SUCCESS;
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_SetCurrentDirectoryA( char const * lp_path_name ) {
  fprintf( stderr, "KERNEL32_SetCurrentDirectoryA(%s)\n", lp_path_name );
  g_last_error = ERROR_ACCESS_DENIED;
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_GetSystemDefaultLangID( void ) {
  fprintf( stderr, "KERNEL32_GetSystemDefaultLangID()\n" );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_GetShortPathNameA( char const * lpsz_long_path,
                            char *       lpsz_short_path,
                            int          cch_buffer ) {
  fprintf( stderr, "KERNEL32_GetShortPathNameA(%s, %p, %d)\n", lpsz_long_path, lpsz_short_path, cch_buffer );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_CreateProcessA( char const * lp_application_name,
                         char *       lp_command_line,
                         void *       lp_process_attributes,
                         void *       lp_thread_attributes,
                         int32_t      b_inherit_handles,
                         uint32_t     dw_creation_flags,
                         void *       lp_environment,
                         char const * lp_current_directory,
                         void *       lp_startup_info,
                         void *       lp_process_information ) {
  fprintf( stderr, "KERNEL32_CreateProcessA(%p, %p, %p, %p, %d, %u, %p, %p, %p, %p)\n",
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

__attribute__((stdcall))
uint32_t
KERNEL32_WaitForSingleObject( uint32_t h_handle,
                              uint32_t dw_milliseconds ) {
  fprintf( stderr, "KERNEL32_WaitForSingleObject(%u, %u)\n", h_handle, dw_milliseconds );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_GetExitCodeProcess( uint32_t h_process,
                             uint32_t * lp_exit_code ) {
  fprintf( stderr, "KERNEL32_GetExitCodeProcess(%u, %p)\n", h_process, lp_exit_code );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_CloseHandle( uint32_t h_object ) {
  fprintf( stderr, "KERNEL32_CloseHandle(%p)\n", h_object );
  return 0;
}

#define COMPAT_TLS_SIZE 32
static __thread uint32_t tls_index = 1; 
static __thread uint32_t tls_slots[COMPAT_TLS_SIZE];

__attribute__((stdcall))
uint32_t
KERNEL32_TlsAlloc( void ) {
  uint32_t index = tls_index++;
  if( index>=COMPAT_TLS_SIZE )
    return TLS_OUT_OF_INDEXES;
  tls_slots[ index ] = 0;
  fprintf( stderr, "KERNEL32_TlsAlloc() = %d\n", index );
  return index;
}

__attribute__((stdcall))
int
KERNEL32_TlsFree( uint32_t dw_tls_index ) {
  fprintf( stderr, "KERNEL32_TlsFree(%u)\n", dw_tls_index );
  if( dw_tls_index>=COMPAT_TLS_SIZE )
    return 0;
  g_last_error = ERROR_SUCCESS;
  return 1;
}

__attribute__((stdcall))
uint32_t
KERNEL32_TlsGetValue( uint32_t dw_tls_index ) {
  uint32_t val = tls_slots[ dw_tls_index ];
  //fprintf( stderr, "KERNEL32_TlsGetValue(%u) = %#x\n", dw_tls_index, val );
  g_last_error = ERROR_SUCCESS;
  return val;
}

__attribute__((stdcall))
int
KERNEL32_TlsSetValue( uint32_t dw_tls_index,
                      uint32_t lp_tls_value ) {
  fprintf( stderr, "KERNEL32_TlsSetValue(%u, %#x)\n", dw_tls_index, lp_tls_value );
  tls_slots[ dw_tls_index ] = lp_tls_value;
  g_last_error = ERROR_SUCCESS;
  return 1;
}

__attribute__((stdcall))
void *
KERNEL32_GetModuleHandleA( char const * lp_module_name ) {
  fprintf( stderr, "KERNEL32_GetModuleHandleA(\"%s\")\n", lp_module_name );
  void * handle = NULL;
  if( !lp_module_name ) {
    handle = &g_cur_module;
    return handle;
  }

  g_last_error = ERROR_FILE_NOT_FOUND;
  return NULL;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetModuleFileNameA( void *   h_module,
                             char *   lp_file_name,
                             uint32_t n_size ) {
  fprintf( stderr, "KERNEL32_GetModuleFileNameA(%p, %p, %u)\n", h_module, lp_file_name, n_size );
  if( h_module == &g_cur_module ) {
    snprintf( lp_file_name, n_size, "%s", __progname );
    return 1;
  }
  return 0;
}

__attribute__((stdcall))
void *
KERNEL32_LoadLibraryA( char const * lp_lib_file_name ) {
  fprintf( stderr, "KERNEL32_LoadLibraryA(\"%s\")\n", lp_lib_file_name );
  if( strcmp( lp_lib_file_name, __progname )==0 )
    return &g_cur_library;
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_FreeLibrary( void * h_lib_module ) {
  fprintf( stderr, "KERNEL32_FreeLibrary(%p)\n", h_lib_module );
  return 0;
}

__attribute__((stdcall))
int32_t *
KERNEL32_GlobalAlloc( uint32_t u_flags,
                      uint32_t dw_bytes ) {
  void * ptr = malloc( dw_bytes );
  if( ptr && (u_flags&0x40)!=0 ) {
    memset( ptr, 0, dw_bytes );
  }
  fprintf( stderr, "KERNEL32_GlobalAlloc(%u, %u) = %p\n", u_flags, dw_bytes, ptr );
  return (int32_t *)ptr;
}

__attribute__((stdcall))
int32_t *
KERNEL32_GlobalFree( int32_t * h_mem ) {
  fprintf( stderr, "KERNEL32_GlobalFree(%p)\n", h_mem );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetFullPathNameA( char const * lp_file_name,
                           uint32_t     n_buffer_length,
                           char *       lp_buffer,
                           char **      lp_file_part ) {
  fprintf( stderr, "KERNEL32_GetFullPathNameA(\"%s\", %u, %p, %p)\n",
          lp_file_name,
          n_buffer_length,
          lp_buffer,
          lp_file_part );
  snprintf( lp_buffer, n_buffer_length, "fuck you\n" );
  *lp_file_part = lp_buffer;
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_SetFilePointer( uint32_t  h_file,
                         int32_t   l_distance_to_move,
                         int32_t * lp_distance_to_move_high,
                         uint32_t  dw_move_method ) {
  fprintf( stderr, "KERNEL32_SetFilePointer(%u, %d, %p, %u)\n",
          h_file,
          l_distance_to_move,
          lp_distance_to_move_high,
          dw_move_method );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_WriteFile( uint32_t     h_file,
                    void const * lp_buffer,
                    uint32_t     n_number_of_bytes_to_write,
                    uint32_t *   lp_number_of_bytes_written,
                    void *       lp_overlapped ) {
  //FILE * f;
  //switch( h_file ) {
  //case STD_OUTPUT_HANDLE:
  //  
  //
  //}
  int nbytes = fwrite( lp_buffer, 1, n_number_of_bytes_to_write, stdout );
  if( lp_number_of_bytes_written ) {
    *lp_number_of_bytes_written = (uint32_t)nbytes;
  }
  fprintf( stderr, "KERNEL32_WriteFile(%p, \"%s\", %u, %p, %p)\n",
          h_file,
          lp_buffer,
          n_number_of_bytes_to_write,
          lp_number_of_bytes_written,
          lp_overlapped );
  return 1;
}

__attribute__((stdcall))
int
KERNEL32_ReadFile( uint32_t   h_file,
                   void *     lp_buffer,
                   uint32_t   n_number_of_bytes_to_read,
                   uint32_t * lp_number_of_bytes_read,
                   void *     lp_overlapped ) {
  fprintf( stderr, "KERNEL32_ReadFile(%u, %p, %u, %p, %p)\n",
          h_file,
          lp_buffer,
          n_number_of_bytes_to_read,
          lp_number_of_bytes_read,
          lp_overlapped );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_CreateFileA( char const * lp_file_name,
                      uint32_t     dw_desired_access,
                      uint32_t     dw_share_mode,
                      void *       lp_security_attributes,
                      uint32_t     dw_creation_disposition,
                      uint32_t     dw_flags_and_attributes,
                      uint32_t     h_template_file ) {
  fprintf( stderr, "KERNEL32_CreateFileA(%p, %u, %u, %p, %u, %u, %u)\n",
          lp_file_name,
          dw_desired_access,
          dw_share_mode,
          lp_security_attributes,
          dw_creation_disposition,
          dw_flags_and_attributes,
          h_template_file );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetTickCount( void ) {
  fprintf( stderr, "KERNEL32_GetTickCount()\n" );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_DeleteFileA( char const * lp_file_name ) {
  fprintf( stderr, "KERNEL32_DeleteFileA(%p)\n", lp_file_name );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_MoveFileA( char const * lp_existing_file_name,
                    char const * lp_new_file_name ) {
  fprintf( stderr, "KERNEL32_MoveFileA(%p, %p)\n", lp_existing_file_name, lp_new_file_name );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_FormatMessageA( uint32_t  dw_flags,
                         void *    lp_source,
                         uint32_t  dw_message_id,
                         uint32_t  dw_language_id,
                         char *    lp_buffer,
                         uint32_t  n_size,
                         void *    arguments ) {
  fprintf( stderr, "KERNEL32_FormatMessageA(%u, %p, %u, %u, %p, %u, %p)\n",
          dw_flags,
          lp_source,
          dw_message_id,
          dw_language_id,
          lp_buffer,
          n_size,
          arguments );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_GetFileTime( uint32_t h_file,
                      void *   lp_creation_time,
                      void *   lp_last_access_time,
                      void *   lp_last_write_time ) {
  fprintf( stderr, "KERNEL32_GetFileTime(%u, %p, %p, %p)\n",
          h_file,
          lp_creation_time,
          lp_last_access_time,
          lp_last_write_time );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_SetFileTime( uint32_t h_file,
                      void *   lp_creation_time,
                      void *   lp_last_access_time,
                      void *   lp_last_write_time ) {
  fprintf( stderr, "KERNEL32_SetFileTime(%u, %p, %p, %p)\n",
          h_file,
          lp_creation_time,
          lp_last_access_time,
          lp_last_write_time );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetFileSize( uint32_t h_file,
                      uint32_t * lp_file_size_high ) {
  fprintf( stderr, "KERNEL32_GetFileSize(%u, %p)\n", h_file, lp_file_size_high );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_SetEndOfFile( uint32_t h_file ) {
  fprintf( stderr, "KERNEL32_SetEndOfFile(%u)\n", h_file );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_CreateDirectoryA( char const * lp_path_name,
                           void *       lp_security_attributes ) {
  fprintf( stderr, "KERNEL32_CreateDirectoryA(%p, %p)\n", lp_path_name, lp_security_attributes );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_RemoveDirectoryA( char const * lp_path_name ) {
  fprintf( stderr, "KERNEL32_RemoveDirectoryA(%p)\n", lp_path_name );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_SetStdHandle( uint32_t n_std_handle,
                       uint32_t h_handle ) {
  fprintf( stderr, "KERNEL32_SetStdHandle(%u, %u)\n", n_std_handle, h_handle );
  return 0;
}

__attribute__((stdcall))
void
KERNEL32_GetSystemTime( void * lp_system_time ) {
  fprintf( stderr, "KERNEL32_GetSystemTime(%p)\n", lp_system_time );
}

__attribute__((stdcall))
int
KERNEL32_SystemTimeToFileTime( void * lp_system_time,
                               void * lp_file_time ) {
  fprintf( stderr, "KERNEL32_SystemTimeToFileTime(%p, %p)\n", lp_system_time, lp_file_time );
  return 0;
}

__attribute__((stdcall))
int32_t
KERNEL32_CompareFileTime( void * lp_file_time_1,
                          void * lp_file_time_2 ) {
  fprintf( stderr, "KERNEL32_CompareFileTime(%p, %p)\n", lp_file_time_1, lp_file_time_2 );
  return 0;
}

__attribute__((stdcall))
int32_t *
KERNEL32_GlobalReAlloc( int32_t * h_mem,
                        uint32_t  u_bytes,
                        uint32_t  u_flags ) {
  fprintf( stderr, "KERNEL32_GlobalReAlloc(%p, %u, %#x)\n", h_mem, u_bytes, u_flags );
  if( !h_mem ) return NULL;
  static int allocs = 0;
  void * obj = realloc( h_mem, u_bytes );
  if( u_bytes==256 ) obj = NULL;
  if( obj==NULL )
    g_last_error = ERROR_OUTOFMEMORY;
  else
    g_last_error = ERROR_SUCCESS;
  //g_last_error = ERROR_SUCCESS;
  return obj;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GlobalFlags( int32_t * h_mem ) {
  //fprintf( stderr, "KERNEL32_GlobalFlags(%p)\n", h_mem );
  if( !h_mem ) return GMEM_INVALID_HANDLE;
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_FileTimeToSystemTime( void * lp_file_time,
                               void * lp_system_time ) {
  fprintf( stderr, "KERNEL32_FileTimeToSystemTime(%p, %p)\n", lp_file_time, lp_system_time );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_FindResourceA( uint32_t     h_module,
                        char const * lp_name,
                        char const * lp_type ) {
  fprintf( stderr, "KERNEL32_FindResourceA(%u, %p, %p)\n", h_module, lp_name, lp_type );
  return 0;
}

__attribute__((stdcall))
int32_t *
KERNEL32_LoadResource( uint32_t h_module,
                       uint32_t h_resource ) {
  fprintf( stderr, "KERNEL32_LoadResource(%u, %u)\n", h_module, h_resource );
  return 0;
}

__attribute__((stdcall))
void *
KERNEL32_LockResource( int32_t * h_resource ) {
  fprintf( stderr, "KERNEL32_LockResource(%p)\n", h_resource );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_SizeofResource( uint32_t h_module,
                         uint32_t h_resource ) {
  fprintf( stderr, "KERNEL32_SizeofResource(%u, %u)\n", h_module, h_resource );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_CreateFileMappingA( uint32_t     h_file,
                             void *       lp_file_mapping_attributes,
                             uint32_t     fl_protect,
                             uint32_t     dw_maximum_size_high,
                             uint32_t     dw_maximum_size_low,
                             char const * lp_name ) {
  fprintf( stderr, "KERNEL32_CreateFileMappingA(%u, %p, %u, %u, %u, %p)\n",
          h_file,
          lp_file_mapping_attributes,
          fl_protect,
          dw_maximum_size_high,
          dw_maximum_size_low,
          lp_name );
  return 0;
}

__attribute__((stdcall))
int32_t *
KERNEL32_MapViewOfFile( uint32_t h_file_mapping_object,
                        uint32_t dw_desired_access,
                        uint32_t dw_file_offset_high,
                        uint32_t dw_file_offset_low,
                        uint32_t dw_number_of_bytes_to_map ) {
  fprintf( stderr, "KERNEL32_MapViewOfFile(%u, %u, %u, %u, %u)\n",
          h_file_mapping_object,
          dw_desired_access,
          dw_file_offset_high,
          dw_file_offset_low,
          dw_number_of_bytes_to_map );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_UnmapViewOfFile( int32_t * lp_base_address ) {
  fprintf( stderr, "KERNEL32_UnmapViewOfFile(%p)\n", lp_base_address );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetSystemDirectoryA( char * lp_buffer,
                              uint32_t u_size ) {
  fprintf( stderr, "KERNEL32_GetSystemDirectoryA(%p, %u)\n", lp_buffer, u_size );
  return snprintf( lp_buffer, u_size, "C:\\Windows\\System32" );
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetWindowsDirectoryA( char *   lp_buffer,
                               uint32_t u_size ) {
  fprintf( stderr, "KERNEL32_GetWindowsDirectoryA(%p, %u)\n", lp_buffer, u_size );
  return snprintf( lp_buffer, u_size, "C:\\Windows" );
}

__attribute__((stdcall))
int
KERNEL32_SetConsoleCtrlHandler( void * lp_handler_routine,
                                int    b_add ) {
  fprintf( stderr, "KERNEL32_SetConsoleCtrlHandler(%p, %u)\n", lp_handler_routine, b_add );
  return 0;
}

static CONSOLE_SCREEN_BUFFER_INFO console_buf;

__attribute__((stdcall))
int
KERNEL32_GetConsoleScreenBufferInfo( uint32_t h_console_output,
                                     void *   lp_console_screen_buffer_info ) {
  fprintf( stderr, "KERNEL32_GetConsoleScreenBufferInfo(%u, %p)\n", h_console_output, lp_console_screen_buffer_info );
  memcpy( lp_console_screen_buffer_info, &console_buf, sizeof(CONSOLE_SCREEN_BUFFER_INFO) );
  return 1;
}

__attribute__((stdcall))
int
KERNEL32_SetFileAttributesA( char const * lp_file_name,
                             uint32_t     dw_file_attributes ) {
  fprintf( stderr, "KERNEL32_SetFileAttributesA(%p, %u)\n", lp_file_name, dw_file_attributes );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_OpenFileMappingA( uint32_t     dw_desired_access,
                           int          b_inherit_handle,
                           char const * lp_name ) {
  fprintf( stderr, "KERNEL32_OpenFileMappingA(%u, %u, %p)\n", dw_desired_access, b_inherit_handle, lp_name );
  return 0;
}

__attribute__((stdcall))
int32_t
KERNEL32_MultiByteToWideChar( uint32_t     u_code_page,
                              uint32_t     dw_flags,
                              char const * lp_multi_byte_str,
                              int          cch_multi_byte,
                              void *       lp_wide_char_str,
                              int          cch_wide_char ) {
  fprintf( stderr, "KERNEL32_MultiByteToWideChar(%u, %u, %p, %u, %p, %u)\n",
          u_code_page,
          dw_flags,
          lp_multi_byte_str,
          cch_multi_byte,
          lp_wide_char_str,
          cch_wide_char );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_IsValidCodePage( uint32_t u_code_page ) {
  fprintf( stderr, "KERNEL32_IsValidCodePage(%u)\n", u_code_page );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetACP( void ) {
  fprintf( stderr, "KERNEL32_GetACP()\n" );
  return 0;
}

__attribute__((stdcall))
void
KERNEL32_GetLocalTime( void * lp_system_time ) {
  fprintf( stderr, "KERNEL32_GetLocalTime(%p)\n", lp_system_time );
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetTimeZoneInformation( void * lp_time_zone_information ) {
  fprintf( stderr, "KERNEL32_GetTimeZoneInformation(%p)\n", lp_time_zone_information );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_FileTimeToLocalFileTime( void const * lp_file_time,
                                  void *       lp_local_file_time ) {
  fprintf( stderr, "KERNEL32_FileTimeToLocalFileTime(%p, %p)\n", lp_file_time, lp_local_file_time );
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_IsDBCSLeadByte( uint8_t test_char ) {
  fprintf( stderr, "KERNEL32_IsDBCSLeadByte(%#x)\n", test_char );
  return 0;
}

__attribute__((cdecl))
int32_t
LMGR8C_lp_checkout( int32_t v1,
                    int32_t policy,
                    char *  feature,
                    char *  version,
                    int     num_lic,
                    char *  license_file_list ) {
  fprintf( stderr, "LMGR8C_lp_checkout(%p, %p, \"%s\", \"%s\", %u, \"%s\")\n",
           v1,
           policy,
           feature, 
           version,
           num_lic,
           license_file_list );
  return 0;
}

__attribute__((cdecl))
void
LMGR8C_lp_checkin( void * handle ) {
  fprintf( stderr, "LMGR8C_lp_checkin(%p)\n", handle );
}

static char lmgr8c_errbuf[4096] = {0};

/* lp_errstring	*/
__attribute__((cdecl))
char *
LMGR8C_lp_errstring( void ) {
  fprintf( stderr, "LMGR8C_lp_errstring()\n" );
  snprintf( lmgr8c_errbuf, sizeof(lmgr8c_errbuf), "fuck you" );
  return lmgr8c_errbuf;
}

__attribute__((cdecl))
int32_t
LMGR326B_lp_checkin() {
  fprintf( stderr, "LMGR326B_lp_checkin()\n" );
  return 0;
}

__attribute__((cdecl))
int32_t
LMGR326B_lp_checkout() {
  fprintf( stderr, "LMGR326B_lp_checkout()\n" );
  return 0;
}

__attribute__((cdecl))
int32_t
LMGR326B_lp_errstring() {
  fprintf( stderr, "LMGR326B_lp_errstring()\n" );
  return 0;
}

__attribute__((stdcall))
int
USER32_MessageBoxA( uint32_t    h_wnd,
                    char const * lp_text,
                    char const * lp_caption,
                    uint32_t    u_type ) {
  fprintf( stderr, "USER32_MessageBoxA(%u, %p, %p, %u)\n", h_wnd, lp_text, lp_caption, u_type );
  return 0;
}

__attribute__((stdcall))
int32_t
USER32_LoadStringA( uint32_t h_instance,
                    uint32_t u_id,
                    char *   lp_buffer,
                    int      n_buffer_max ) {
  fprintf( stderr, "USER32_LoadStringA(%u, %u, %p, %u)\n", h_instance, u_id, lp_buffer, n_buffer_max );
  if( u_id>=__pe_str_cnt )
    return 0;
  snprintf( lp_buffer, n_buffer_max, "%s", __pe_strs[u_id] );
  return 1;
}

__attribute__((stdcall))
uint32_t
VERSION_GetFileVersionInfoSizeA( char const * lptstr_filename,
                                 uint32_t *   lpdw_handle ) {
  fprintf( stderr, "VERSION_GetFileVersionInfoSizeA(%p, %p)\n", lptstr_filename, lpdw_handle );
  return 0;
}

__attribute__((stdcall))
int
VERSION_GetFileVersionInfoA( char const * lptstr_filename,
                             uint32_t     dw_handle,
                             uint32_t     dw_len,
                             void *       lp_data ) {
  fprintf( stderr, "VERSION_GetFileVersionInfoA(%p, %u, %u, %p)\n", lptstr_filename, dw_handle, dw_len, lp_data );
  return 0;
}

__attribute__((stdcall))
int
VERSION_VerQueryValueA( void const * p_block,
                        char const * lp_sub_block,
                        void **      lplp_buffer,
                        uint32_t *   pu_len ) {
  fprintf( stderr, "VERSION_VerQueryValueA(%p, %p, %p, %p)\n", p_block, lp_sub_block, lplp_buffer, pu_len );
  return 0;
}

__attribute__((stdcall))
int
ole32_CoInitialize( void * pv_reserved ) {
  fprintf( stderr, "ole32_CoInitialize(%p)\n", pv_reserved );
  return 0;
}

__attribute__((stdcall))
void
ole32_CoUninitialize( void ) {
  fprintf( stderr, "ole32_CoUninitialize()\n" );
}

__attribute__((stdcall))
int
ole32_CoCreateInstance( void *   rclsid,
                        void *   p_unk_outer,
                        uint32_t dw_cls_context,
                        void *   riid,
                        void **  ppv ) {
  fprintf( stderr, "ole32_CoCreateInstance(%p, %p, %u, %p, %p)\n", rclsid, p_unk_outer, dw_cls_context, riid, ppv );
  return 0;
}

__attribute__((stdcall))
void
ole32_CoTaskMemFree( void * pv ) {
  fprintf( stderr, "ole32_CoTaskMemFree(%p)\n", pv );
}

__attribute__((stdcall))
void *
ole32_CoTaskMemAlloc( uint32_t cb ) {
  fprintf( stderr, "ole32_CoTaskMemAlloc(%u)\n", cb );
  return 0;
}

__attribute__((stdcall))
int
WS2_32_WSAStartup( uint16_t w_version_requested,
                   void *   lp_wsa_data ) {
  fprintf( stderr, "WS2_32_WSAStartup(%u, %p)\n", w_version_requested, lp_wsa_data );
  return 0;
}

__attribute__((stdcall))
int
WS2_32_WSAGetLastError( void ) {
  fprintf( stderr, "WS2_32_WSAGetLastError()\n" );
  return 0;
}

__attribute__((stdcall))
uint16_t
WS2_32_ntohs( uint16_t netshort ) {
  fprintf( stderr, "WS2_32_ntohs(%u)\n", netshort );
  return 0;
}

__attribute__((stdcall))
char const *
WS2_32_inet_ntoa( void * in_addr ) {
  fprintf( stderr, "WS2_32_inet_ntoa(%p)\n", in_addr );
  return 0;
}

__attribute__((stdcall))
int
WS2_32_shutdown( uint32_t s,
                 int      how ) {
  fprintf( stderr, "WS2_32_shutdown(%u, %u)\n", s, how );
  return 0;
}

__attribute__((stdcall))
int
WS2_32_closesocket( uint32_t s ) {
  fprintf( stderr, "WS2_32_closesocket(%u)\n", s );
  return 0;
}

__attribute__((stdcall))
int
WS2_32_WSACleanup( void ) {
  fprintf( stderr, "WS2_32_WSACleanup()\n" );
  return 0;
}

__attribute__((stdcall))
uint32_t
WS2_32_socket( int af,
               int type,
               int protocol ) {
  fprintf( stderr, "WS2_32_socket(%u, %u, %u)\n", af, type, protocol );
  return 0;
}

__attribute__((stdcall))
uint16_t
WS2_32_htons( uint16_t hostshort ) {
  fprintf( stderr, "WS2_32_htons(%u)\n", hostshort );
  return 0;
}

__attribute__((stdcall))
uint32_t
WS2_32_inet_addr( char const * cp ) {
  fprintf( stderr, "WS2_32_inet_addr(%p)\n", cp );
  return 0;
}

__attribute__((stdcall))
int
WS2_32_connect( uint32_t s,
                void *   name,
                int      namelen ) {
  fprintf( stderr, "WS2_32_connect(%u, %p, %u)\n", s, name, namelen );
  return 0;
}

__attribute__((stdcall))
int
WS2_32_select( int    nfds,
               void * readfds,
               void * writefds,
               void * exceptfds,
               void * timeout ) {
  fprintf( stderr, "WS2_32_select(%u, %p, %p, %p, %p)\n", nfds, readfds, writefds, exceptfds, timeout );
  return 0;
}

__attribute__((stdcall))
int
WS2_32___WSAFDIsSet( uint32_t s,
                     void *   fd_set ) {
  fprintf( stderr, "WS2_32___WSAFDIsSet(%u, %p)\n", s, fd_set );
  return 0;
}

__attribute__((stdcall))
int
WS2_32_send( uint32_t s,
             void *   buf,
             int      len,
             int      flags ) {
  fprintf( stderr, "WS2_32_send(%u, %p, %u, %u)\n", s, buf, len, flags );
  return 0;
}

__attribute__((stdcall))
int
WS2_32_recv( uint32_t s,
             void *   buf,
             int      len,
             int      flags ) {
  fprintf( stderr, "WS2_32_recv(%u, %p, %u, %u)\n", s, buf, len, flags );
  return 0;
}

/* Stub NT functions */

NTSYSAPI NTSTATUS WINAPI RtlEnterCriticalSection(RTL_CRITICAL_SECTION *) { return STATUS_SUCCESS; }
NTSYSAPI NTSTATUS WINAPI RtlLeaveCriticalSection(RTL_CRITICAL_SECTION *) { return STATUS_SUCCESS; }

NTSYSAPI void WINAPI RtlRaiseStatus(NTSTATUS status) {
  fprintf( stderr, "RtlRaiseStatus: %d\n", status );
  abort();
}

/*********************************************************************************************
 * Copied from Wine: dlls/ntdll
 *********************************************************************************************/

#include "wine/dlls/ntdll/error.c"
#include "wine/dlls/ntdll/heap.c"
#include "wine/dlls/ntdll/unix/env.c"
#include "wine/dlls/ntdll/unix/thread.c"
#include "wine/dlls/ntdll/unix/virtual.c"
#include "wine/dlls/ntdll/unix/signal_i386.c"

/*********************************************************************************************
 * Copied from Wine: dlls/kernelbase/memory.c
 *********************************************************************************************/

#include "wine/dlls/kernel32/kernel_private.h"

/* some undocumented flags (names are made up) */
#define HEAP_ADD_USER_INFO    0x00000100

#define MEM_FLAG_USED        1
#define MEM_FLAG_MOVEABLE    2
#define MEM_FLAG_DISCARDABLE 4
#define MEM_FLAG_DISCARDED   8
#define MEM_FLAG_DDESHARE    0x8000

struct mem_entry
{
    union
    {
        struct
        {
            WORD flags;
            BYTE lock;
        };
        void *next_free;
    };
    void *ptr;
};

C_ASSERT(sizeof(struct mem_entry) == 2 * sizeof(void *));

struct kernelbase_global_data *kernelbase_global_data;

static inline struct mem_entry *unsafe_mem_from_HLOCAL( HLOCAL handle )
{
    struct mem_entry *mem = CONTAINING_RECORD( *(volatile HANDLE *)&handle, struct mem_entry, ptr );
    struct kernelbase_global_data *data = kernelbase_global_data;
    if (((UINT_PTR)handle & ((sizeof(void *) << 1) - 1)) != sizeof(void *)) return NULL;
    if (mem < data->mem_entries || mem >= data->mem_entries_end) return NULL;
    if (!(mem->flags & MEM_FLAG_USED)) return NULL;
    return mem;
}

static inline void *unsafe_ptr_from_HLOCAL( HLOCAL handle )
{
    if (((UINT_PTR)handle & ((sizeof(void *) << 1) - 1))) return NULL;
    return handle;
}

/*********************************************************************************************
 * Copied from Wine: dlls/kernelbase/memory.c
 *********************************************************************************************/

LPVOID WINAPI DECLSPEC_HOTPATCH LocalLock( HLOCAL handle )
{
    HANDLE heap = GetProcessHeap();
    struct mem_entry *mem;
    void *ret = NULL;

    if (!handle) return NULL;
    if ((ret = unsafe_ptr_from_HLOCAL( handle )))
    {
        return ret;
    }

    RtlLockHeap( heap );
    if ((mem = unsafe_mem_from_HLOCAL( handle )))
    {
        if (!(ret = mem->ptr)) SetLastError( ERROR_DISCARDED );
        else if (!++mem->lock) mem->lock--;
    }
    else
    {
        SetLastError( ERROR_INVALID_HANDLE );
    }
    RtlUnlockHeap( heap );

    return ret;
}

BOOL WINAPI DECLSPEC_HOTPATCH LocalUnlock( HLOCAL handle )
{
    HANDLE heap = GetProcessHeap();
    struct mem_entry *mem;
    BOOL ret = FALSE;

    TRACE_(globalmem)( "handle %p\n", handle );

    if (unsafe_ptr_from_HLOCAL( handle ))
    {
        SetLastError( ERROR_NOT_LOCKED );
        return FALSE;
    }

    RtlLockHeap( heap );
    if ((mem = unsafe_mem_from_HLOCAL( handle )))
    {
        if (mem->lock)
        {
            ret = (--mem->lock != 0);
            if (!ret) SetLastError( NO_ERROR );
        }
        else
        {
            WARN_(globalmem)( "handle %p not locked\n", handle );
            SetLastError( ERROR_NOT_LOCKED );
        }
    }
    else
    {
        WARN_(globalmem)( "invalid handle %p\n", handle );
        SetLastError( ERROR_INVALID_HANDLE );
    }
    RtlUnlockHeap( heap );

    return ret;
}

/*********************************************************************************************
 * Copied from Wine: dlls/kernel32/heap.c
 *********************************************************************************************/

__attribute__((stdcall))
void *
KERNEL32_GlobalLock( void * handle ) {
  return LocalLock( handle );
}

__attribute__((stdcall))
int
KERNEL32_GlobalUnlock( void * handle ) {
  if (unsafe_ptr_from_HLOCAL( handle )) return 1;
  return LocalUnlock( handle );
}

/*********************************************************************************************
 * Entrypoint
 *********************************************************************************************/

int
main( int     argc,
      char ** argv ) {
  //fprintf( stderr, "__builtin_return_address() = %p\n", __builtin_return_address( 0 ) );

  //fprintf( stderr, "__pe_text_start       = %p\n", __pe_text_start       ); // 0x804820f
  //fprintf( stderr, "__pe_data_start       = %p\n", __pe_data_start       ); // 0x82a7024
  //fprintf( stderr, "__pe_data_idata_start = %p\n", __pe_data_idata_start ); // 0x830d424

  g_argc = argc;
  g_argv = argv;

  __pe_text_start_enter();
}


unsigned int CDECL wine_server_call( void *req_ptr ) {
  puts( "wine_server_call" );
  return 0;
}

void server_enter_uninterrupted_section( pthread_mutex_t *mutex, sigset_t *sigset ) {
  puts( "server_enter_uninterrupted_section" );
}

void server_leave_uninterrupted_section( pthread_mutex_t *mutex, sigset_t *sigset ) {
  puts( "server_leave_uninterrupted_section" );
}

 void server_init_thread( void *entry_point, BOOL *suspend ) {
  puts( "server_init_thread" );
}
 int server_pipe( int fd[2] ) {
  puts( "server_pipe" );
  return 0;
 }


extern unsigned int server_call_unlocked( void *req_ptr ) {
  puts( "server_call_unlocked" );
  return 0;
} 

extern int server_get_unix_fd( HANDLE handle, unsigned int wanted_access, int *unix_fd,
                               int *needs_close, enum server_fd_type *type, unsigned int *options ) {
  puts( "server_get_unix_fd" );
}

extern unsigned int server_queue_process_apc( HANDLE process, const apc_call_t *call,
                                              apc_result_t *result ) {
  puts( "server_queue_process_apc" );
}

extern unsigned int server_select( const select_op_t *select_op, data_size_t size, UINT flags,
                                   timeout_t abs_timeout, context_t *context, user_apc_t *user_apc ) {
  puts( "server_select" );
} 

extern void wine_server_send_fd( int fd ) {
  puts( "wine_server_send_fd" );
} 



const unixlib_entry_t __wine_unix_call_funcs[] = {};

void     (WINAPI *pDbgUiRemoteBreakin)( void *arg ) = NULL;
NTSTATUS (WINAPI *pKiRaiseUserExceptionDispatcher)(void) = NULL;
NTSTATUS (WINAPI *pKiUserExceptionDispatcher)(EXCEPTION_RECORD*,CONTEXT*) = NULL;
void     (WINAPI *pKiUserApcDispatcher)(CONTEXT*,ULONG_PTR,ULONG_PTR,ULONG_PTR,PNTAPCFUNC) = NULL;
void     (WINAPI *pKiUserCallbackDispatcher)(ULONG,void*,ULONG) = NULL;
void     (WINAPI *pLdrInitializeThunk)(CONTEXT*,void**,ULONG_PTR,ULONG_PTR) = NULL;
void     (WINAPI *pRtlUserThreadStart)( PRTL_THREAD_START_ROUTINE entry, void *arg ) = NULL;
void     (WINAPI *p__wine_ctrl_routine)(void*);
SYSTEM_DLL_INIT_BLOCK *pLdrSystemDllInitBlock = NULL;

BOOL xstate_compaction_enabled = FALSE;

unsigned int alloc_object_attributes( const OBJECT_ATTRIBUTES *attr, struct object_attributes **ret,
                                             data_size_t *ret_len ){
  puts( "alloc_object_attributes" );
                                             }

NTSTATUS load_builtin( const pe_image_info_t *image_info, WCHAR *filename,
                              void **addr_ptr, SIZE_T *size_ptr, ULONG_PTR zero_bits ) {
  puts( "load_builtin" );
                              }
