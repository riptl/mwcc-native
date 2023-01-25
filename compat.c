#define _LARGEFILE64_SOURCE
#include <assert.h>
#include <dirent.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "compat.h"

/* libc symbols */

extern char **      environ;
extern char const * __progname;

/* Globals */

int     g_argc;
char ** g_argv;

static __thread int g_last_error = ERROR_SUCCESS;

/* Handles */

static uint32_t compat_stdin;
static uint32_t compat_stdout;
static uint32_t compat_stderr;

/* Main handle table */
compat_handle_t compat_handles[COMPAT_HANDLE_CNT];

/* Use simple bump alloc (no frees).
   Might change to a bitmap-backed alloc */
static uint32_t handle_nonce = 0;

uint32_t
compat_handle_alloc( void *     data,
                     uint32_t (*closefn)(void *) ) {
  uint32_t h = ++handle_nonce;
  if( h>=COMPAT_HANDLE_CNT ) {
    LOG_FATAL(( "Out of Win32 handles" ));
    return INVALID_HANDLE_VALUE;
  }
  compat_handle_t * handle = &compat_handles[h];
  handle->data  = data;
  handle->close = closefn;
  return h;
}

void
compat_handle_free( uint32_t h ) {
  assert( h<COMPAT_HANDLE_CNT );
  memset( &compat_handles[h], 0, sizeof(compat_handle_t) );
}

static uint32_t
compat_handle_stdio_close( void * h ) {
  LOG_TRACE(( "Ignoring request to close stdin/stdout/stderr" ));
  g_last_error = ERROR_SUCCESS;
  return 1;
}

static uint32_t
compat_handle_file_close( void * h ) {
  FILE * f = (FILE *)h;
  int res = fclose( (FILE *)h );
  if( res ) {
    LOG_DEBUG(( "CloseHandle: fclose(%d)", fileno( f ) ));
    g_last_error = ERROR_SUCCESS;
    return 1;
  } else {
    LOG_WARN(( "CloseHandle: fclose(%d) failed: %s", fileno( f ), strerror( errno ) ));
    g_last_error = ERROR_INVALID_HANDLE;
    return 0;
  }
}

/* Logging */

static int log_level = LOGLVL_FATAL;

__attribute__((format(printf,1,2)))
char const *
compat_log0_( char const * fmt, ... ) {
  static __thread char msg[ 4096 ];
  va_list ap;
  va_start( ap, fmt );
  int len = vsnprintf( msg, sizeof(msg), fmt, ap );
  if( len<0               ) len = 0;
  if( len>(sizeof(msg)-1) ) len = sizeof(msg)-1;
  msg[ len ] = '\0';
  va_end( ap );
  return msg;
}

void
compat_log1_( int level,
              char const * msg ) {
  if( level<0 || level>LOGLVL_FATAL || level<log_level ) return;

  fprintf( stderr, "%s  %s\n", compat_level_str_[ level ], msg );
}

/* Glue functions */

/* compat_check_winpath_absolute: Checks whether a path is absolute.

   Returns NULL if not, returns a pointer to the root excluding the drive name. */
static inline
char const *
compat_check_winpath_absolute( char const * path ) {
  if( *path == '\\' ) return path;

  if( !isupper( *path++ ) ) return NULL;
  if( *path++ != ':'      ) return NULL;
  if( *path   != '\\'     ) return NULL;
  return path;
}

/* compat_winpath_to_posix: Converts a Windows path to a POSIX path.

   Returns the number of bytes occupied by the POSIX string including trailing NULL.
   If this number is greater than out_size, assume error.

   Returns 0 if the Windows path is not representable in POSIX. */
static inline
uint32_t
compat_winpath_to_posix( char *       out,
                         size_t       out_sz,
                         char const * win ) {
  assert( out_sz>0 );
  out[0] = '\0';

  char const * str = compat_check_winpath_absolute( win );
  if( str && win[0]!='\\' && win[0]!='U' ) {
    /* Absolute path, but not in unix volume */
    return 0;
  }

  if( !str ) str = win;

  size_t sz = strlen( str )+1;
  if( sz>out_sz ) return sz;

  /* Copy path, converting slashes */
  char * orig = out;
  while( *str ) {
    if( *str=='\\' ) *out = '/';
    else             *out = *str;
    ++out; ++str;
  }
  *out = '\0';

  return sz;
}

/* Dummy markers */
static int g_cur_module;
static int g_cur_library;

typedef struct _COORD {
  uint16_t X;
  uint16_t Y;
} COORD, *PCOORD;

typedef struct _SMALL_RECT {
  uint16_t Left;
  uint16_t Top;
  uint16_t Right;
  uint16_t Bottom;
} SMALL_RECT;

struct _CONSOLE_SCREEN_BUFFER_INFO {
  COORD      dwSize;
  COORD      dwCursorPosition;
  uint32_t   wAttributes;
  SMALL_RECT srWindow;
  COORD      dwMaximumWindowSize;
};
typedef struct _CONSOLE_SCREEN_BUFFER_INFO CONSOLE_SCREEN_BUFFER_INFO;

static CONSOLE_SCREEN_BUFFER_INFO console_buf = {0};

__attribute__((stdcall))
int32_t
ADVAPI32_RegOpenKeyExA( uint32_t     h_key,
                        char const * lp_sub_key,
                        uint32_t     ul_options,
                        uint32_t     sam_desired,
                        void **      phk_result ) {

  char const * hkey_name;
  switch( h_key ) {
  case HKEY_CLASSES_ROOT     : hkey_name = "HKEY_CLASSES_ROOT"     ; break;
  case HKEY_CURRENT_USER     : hkey_name = "HKEY_CURRENT_USER"     ; break;
  case HKEY_LOCAL_MACHINE    : hkey_name = "HKEY_LOCAL_MACHINE"    ; break;
  case HKEY_USERS            : hkey_name = "HKEY_USERS"            ; break;
  case HKEY_PERFORMANCE_DATA : hkey_name = "HKEY_PERFORMANCE_DATA" ; break;
  case HKEY_CURRENT_CONFIG   : hkey_name = "HKEY_CURRENT_CONFIG"   ; break;
  case HKEY_DYN_DATA         : hkey_name = "HKEY_DYN_DATA"         ; break;
  default                    : hkey_name = "<unknown>"             ; break;
  }

  LOG_DEBUG(( "[TODO] ADVAPI32_RegOpenKeyExA(%s (%p), \"%s\", %x, %x, %p)",
              hkey_name, h_key, lp_sub_key, ul_options, sam_desired, phk_result ));

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
  LOG_ERR(( "[TODO] ADVAPI32_RegQueryValueExA(%p, \"%s\", %p, %p, %p, %p)",
          h_key,
          lp_value_name,
          lp_reserved,
          lp_type,
          lp_data,
          lpcb_data ));
  return ERROR_ACCESS_DENIED;
}

__attribute__((stdcall))
int32_t
ADVAPI32_RegCloseKey( void * h_key ) {
  LOG_ERR(( "[TODO] ADVAPI32_RegCloseKey(%p)", h_key ));
  return ERROR_ACCESS_DENIED;
}

__attribute__((stdcall))
int32_t
KERNEL32_IsBadReadPtr( void const * lp,
                       uint32_t     ucb ) {
  LOG_ERR(( "[TODO] KERNEL32_IsBadReadPtr(%p, %x)", lp, ucb ));
  abort();
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
  LOG_INFO(( "KERNEL32_ExitProcess(%d)\n", exit_code ));
  exit( exit_code );
}

__attribute__((stdcall))
int32_t
KERNEL32_GetCurrentProcess( void ) {
  return -1;
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
  //fprintf( stderr, "KERNEL32_DuplicateHandle(%p, %p, %p, %p, %x, %x, %x)\n",
  //        h_source_process_handle,
  //        h_source_handle,
  //        h_target_process_handle,
  //        lp_target_handle,
  //        dw_desired_access,
  //        b_inherit_handle,
  //        dw_options );
  int fd = dup( fileno( (FILE *)h_source_handle ) );
  if( fd<0 ) {
    fprintf( stderr, "KERNEL32_DuplicateHandle: dup() failed: %s\n",
            strerror( errno ) );
    g_last_error = ERROR_INVALID_HANDLE;
    return 0;
  }
  *lp_target_handle = fdopen( fd, "r+" );
  return 1;
}

__attribute__((stdcall))
int32_t
KERNEL32_GetLastError( void ) {
  return g_last_error;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetStdHandle( int32_t n_std_handle ) {
  uint32_t h;
  switch( n_std_handle ) {
  case STD_INPUT_HANDLE  : h = compat_stdin;  break;
  case STD_OUTPUT_HANDLE : h = compat_stdout; break;
  case STD_ERROR_HANDLE  : h = compat_stderr; break;
  default:
    h = INVALID_HANDLE_VALUE;
  }
  LOG_INFO(( "KERNEL32_GetStdHandle(%p) = %p", n_std_handle, h ));
  return h;
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

/* FindFile API */

#define COMPAT_FINDFILE_PATSZ 256

struct compat_findfile {
  DIR * dir;
  char pattern[ COMPAT_FINDFILE_PATSZ ];
};

/* compat_findfile_match: implements basic wildcard matching.
   question marks not handled yet. */
static int
compat_findfile_match( char const * name,
                       char const * pat ) {
  char const * wild;
  wild = strchr( pat, '*' );

  if( wild==NULL ) return 0==strcmp( name, pat );
  if( wild==pat  ) return 1;

  return 0==strncmp( name, pat, wild-pat );
}

static void
compat_findfile_dirent( struct dirent * ent,
                        WIN32_FIND_DATAA * lp_find_file_data ) {
  if( ent->d_type==DT_DIR ) {
    lp_find_file_data->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
  } else {
    lp_find_file_data->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
  }
  lp_find_file_data->ftCreationTime  .dwLowDateTime  = 0;
  lp_find_file_data->ftCreationTime  .dwHighDateTime = 0;
  lp_find_file_data->ftLastAccessTime.dwLowDateTime  = 0;
  lp_find_file_data->ftLastAccessTime.dwHighDateTime = 0;
  lp_find_file_data->ftLastWriteTime .dwLowDateTime  = 0;
  lp_find_file_data->ftLastWriteTime .dwHighDateTime = 0;
  lp_find_file_data->nFileSizeHigh = 0;
  lp_find_file_data->nFileSizeLow  = 0;
  strncpy( lp_find_file_data->cFileName, ent->d_name, 259 );
  lp_find_file_data->cAlternateFileName[0] = '\0';
}

static int
compat_findfile_next( struct compat_findfile * ff,
                      WIN32_FIND_DATAA *       lp_find_file_data ) {
  struct dirent * ent;
  while( (ent=readdir( ff->dir ))!=NULL ) {
    if( compat_findfile_match( ent->d_name, ff->pattern ) ) {
      compat_findfile_dirent( ent, lp_find_file_data );
      return 1;
    }
  }
  return 0;
}

static uint32_t
compat_handle_findfile_close( void * opaque ) {
  LOG_WARN(( "CloseHandle called on FindFirstFileA" ));
  g_last_error = ERROR_INVALID_HANDLE;
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_FindFirstFileA( char const *       lp_file_name,
                         WIN32_FIND_DATAA * lp_find_file_data ) {
  char dir_path[ PATH_MAX ];

  uint32_t n = compat_winpath_to_posix( dir_path, sizeof(dir_path), lp_file_name );
  if( n==0 ) {
    LOG_TRACE(( "KERNEL32_FindFirstFileA: Cannot represent path \"%s\"", lp_file_name ));
    g_last_error = ERROR_FILE_NOT_FOUND;
    return INVALID_FILE_ATTRIBUTES;
  }
  if( n>sizeof(dir_path) ) {
    LOG_TRACE(( "KERNEL32_FindFirstFileA: Oversize unix path (%lu bytes)", n ));
    g_last_error = ERROR_FILE_NOT_FOUND;
    return INVALID_FILE_ATTRIBUTES;
  }

  /* Split dir name and file name */
  uint32_t pathsz;
  char * name = strrchr( dir_path, '/' );
  if( !name ) {
    dir_path[0] = '.'; dir_path[1] = '\0';
    pathsz = 1;
    name = dir_path;
  } else {
    pathsz = name-dir_path;
    if( pathsz > sizeof(dir_path)-1 ) {
      LOG_WARN(( "FindFirstFileA: path too long (%d bytes)", pathsz ));
      g_last_error = ERROR_INSUFFICIENT_BUFFER;
      return 0;
    }
    *name = '\0'; // split path into two separate strings
    name++;
  }

  if( strlen(name) >= COMPAT_FINDFILE_PATSZ ) {
    LOG_WARN(( "FindFirstFileA: pattern too long (\"%s\"; %d bytes)", name, pathsz ));
    g_last_error = ERROR_INSUFFICIENT_BUFFER;
    return 0;
  }

  /* Open directory */
  DIR * dir = opendir( dir_path );
  if( !dir ) {
    LOG_WARN(( "FindFirstFileA: opendir(\"%s\") failed: %s", dir_path, strerror( errno ) ));
    g_last_error = ERROR_PATH_NOT_FOUND;
    return 0;
  }

  /* Create compat handle */
  struct compat_findfile * find = calloc(1, sizeof(struct compat_findfile));
  find->dir = dir;
  strcpy( find->pattern, name );

  if( !compat_findfile_next( find, lp_find_file_data ) ) {
    /* Don't alloc handle if no file matches */
    closedir( dir );
    free( find );
    LOG_DEBUG(( "FindFirstFileA(\"%s\"): not found", lp_file_name ));
    g_last_error = ERROR_FILE_NOT_FOUND;
    return INVALID_HANDLE_VALUE;
  }

  /* Create handle for finding further files */
  uint32_t h = compat_handle_alloc( (void *)find, compat_handle_findfile_close );
  LOG_DEBUG(( "FindFirstFileA(\"%s\"): found \"%s\"", lp_file_name, lp_find_file_data->cFileName ));
  g_last_error = ERROR_SUCCESS;
  return h;
}

__attribute__((stdcall))
int
KERNEL32_FindNextFileA( uint32_t h_find_file,
                        void *   lp_find_file_data ) {
  compat_handle_t * h = compat_handle_get( h_find_file );
  if( !h ) {
    LOG_ERR(( "KERNEL32_FindNextFileA: invalid handle %u", h ));
    g_last_error = ERROR_INVALID_HANDLE;
    return 0;
  }

  struct compat_findfile * find = (struct compat_findfile *)h->data;

  if( !compat_findfile_next( find, lp_find_file_data ) ) {
    LOG_DEBUG(( "KERNEL32_FindNextFileA(%u, %p): not found", h_find_file, lp_find_file_data ));
    g_last_error = ERROR_NO_MORE_FILES;
    return 0;
  }

  g_last_error = ERROR_SUCCESS;
  return 1;
}

__attribute__((stdcall))
int
KERNEL32_FindClose( uint32_t h_find_file ) {
  compat_handle_t * h = compat_handle_get( h_find_file );
  if( !h ) {
    if( h_find_file!=INVALID_HANDLE_VALUE )
      LOG_ERR(( "KERNEL32_FindClose: invalid handle %u", h ));
    g_last_error = ERROR_INVALID_HANDLE;
    return 0;
  }

  struct compat_findfile * find = (struct compat_findfile *)h->data;
  closedir( find->dir );

  free( find );
  compat_handle_free( h_find_file );
  g_last_error = ERROR_SUCCESS;
  return 1;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetFileAttributesA( char const * lp_file_name ) {
  /* Special case: Check if current program */
  static char sys32[] = "C:\\Windows\\System32\\";
  if( 0==strncmp( lp_file_name,                                      sys32,      strlen( sys32      ) ) &&
      0==strncmp( lp_file_name+strlen( sys32 ),                      __progname, strlen( __progname ) ) &&
      0==strcmp ( lp_file_name+strlen( sys32 )+strlen( __progname ), ".exe" ) ) {
    LOG_TRACE(( "KERNEL32_GetFileAttributesA: %s is current program", lp_file_name ));
    g_last_error = ERROR_SUCCESS;
    return FILE_ATTRIBUTE_NORMAL;
  }

  /* Special case: Mock license.dat */
  if( 0==strcmp( lp_file_name, "L:\\license.dat" ) ) {
    LOG_TRACE(( "KERNEL32_GetFileAttributesA: Reporting \"%s\" as exist", lp_file_name ));
    g_last_error = ERROR_SUCCESS;
    return FILE_ATTRIBUTE_NORMAL;
  }

  /* Convert path to POSIX */
  char path[ PATH_MAX ];
  size_t n = compat_winpath_to_posix( path, sizeof(path), lp_file_name );
  if( n==0 ) {
    LOG_TRACE(( "KERNEL32_GetFileAttributesA: Cannot represent path \"%s\"", lp_file_name ));
    g_last_error = ERROR_FILE_NOT_FOUND;
    return INVALID_FILE_ATTRIBUTES;
  }
  if( n>sizeof(path) ) {
    LOG_TRACE(( "KERNEL32_GetFileAttributesA: Oversize unix path (%lu bytes)", n ));
    g_last_error = ERROR_FILE_NOT_FOUND;
    return INVALID_FILE_ATTRIBUTES;
  }

  /* Stat file */
  struct stat posix_stat;
  if( -1==stat( path, &posix_stat ) ) {
    LOG_TRACE(( "KERNEL32_GetFileAttributesA: stat(\"%s\") failed: %s", path, strerror( errno ) ));
    g_last_error = ERROR_FILE_NOT_FOUND;
    return INVALID_FILE_ATTRIBUTES;
  }

  /* Convert stat to KERNEL32 format */
  uint32_t mode = 0;
  if( S_ISDIR( posix_stat.st_mode )   ) mode |= FILE_ATTRIBUTE_DIRECTORY;
 // if( !(posix_stat.st_mode & S_IWUSR) ) mode |= FILE_ATTRIBUTE_READONLY;
  if( mode==0U ) mode = FILE_ATTRIBUTE_NORMAL;

  LOG_TRACE(( "KERNEL32_GetFileAttributesA(\"%s\") = 0x%08x", lp_file_name, mode ));

  g_last_error = ERROR_SUCCESS;
  return mode;
}

__attribute__((stdcall))
char *
KERNEL32_GetCommandLineA( void ) {
  static char * cmd = NULL;
  if( cmd ) return cmd;

  int argc     = g_argc-1;
  char ** argv = g_argv+1;
  char x;

  char const * progname = __progname;
  size_t progname_len = strlen( progname );

  /* Count number of chars required */
  int arglen = progname_len + 4;
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

  /* Copy program name */
  char * c = cmd;
  *c++ = '"';
  memcpy( c, progname, progname_len );
  c += progname_len;
  *c++ = '"';

  /* Copy arguments */
  for( int i=0; i<argc; i++ ) {
    *c++ = ' ';
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
  }
  *c = '\0';

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
  char unix_path[ PATH_MAX ];
  if( !getcwd( unix_path, sizeof(unix_path) ) ) {
    LOG_ERR(( "KERNEL32_GetCurrentDirectoryA(%u, %p) failed: %s", n_buffer_length, lp_buffer, strerror(errno) ));
    g_last_error = ERROR_OUTOFMEMORY;
    return 0;
  }

  size_t const prefix_sz = 2; // strlen( "U:\\" );
  size_t unix_path_sz = strlen( unix_path )+1;
  size_t sz = prefix_sz + unix_path_sz;

  /* Bounds check */
  if( unix_path_sz > n_buffer_length-prefix_sz ) {
    LOG_ERR(( "KERNEL32_GetCurrentDirectoryA(%u, %p) failed: insufficient buffer" ));
    g_last_error = ERROR_INSUFFICIENT_BUFFER;
    return sz;
  }

  /* Replace slashes with backslashes */
  char * s = unix_path;
  do {
    if( *s == '/' )
      *s = '\\';
  } while( *s++ );

  /* Copy to output buffer */
  lp_buffer[0] = 'U';
  lp_buffer[1] = ':';
  memcpy( lp_buffer+prefix_sz, unix_path, unix_path_sz );

  LOG_TRACE(( "KERNEL32_GetCurrentDirectoryA(%u, %p) = \"%s\"", n_buffer_length, lp_buffer, lp_buffer ));

  g_last_error = ERROR_SUCCESS;
  return sz-1;
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
  LOG_WARN(( "[TODO] KERNEL32_GetSystemDefaultLangID()" ));
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
  compat_handle_t * hdl = compat_handle_get( h_object );
  if( !hdl ) {
    g_last_error = ERROR_INVALID_HANDLE;
    return 0;
  }
  uint32_t res = hdl->close( hdl->data );
  compat_handle_free( h_object );
  return res;
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
  //fprintf( stderr, "KERNEL32_TlsAlloc() = %d\n", index );
  return index;
}

__attribute__((stdcall))
int
KERNEL32_TlsFree( uint32_t dw_tls_index ) {
  //fprintf( stderr, "KERNEL32_TlsFree(%u)\n", dw_tls_index );
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
  //fprintf( stderr, "KERNEL32_TlsSetValue(%u, %#x)\n", dw_tls_index, lp_tls_value );
  tls_slots[ dw_tls_index ] = lp_tls_value;
  g_last_error = ERROR_SUCCESS;
  return 1;
}

__attribute__((stdcall))
void *
KERNEL32_GetModuleHandleA( char const * lp_module_name ) {
  LOG_DEBUG(( "KERNEL32_GetModuleHandleA(\"%s\")", lp_module_name ));

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
  g_last_error = ERROR_FILE_NOT_FOUND;
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
  if( dw_bytes==0 )
    dw_bytes=1;
  void * ptr = malloc( dw_bytes );
  if( ptr && (u_flags&0x40)!=0 ) {
    memset( ptr, 0, dw_bytes );
  }
  //fprintf( stderr, "KERNEL32_GlobalAlloc(%#x, %u) = %p\n", u_flags, dw_bytes, ptr );
  return (int32_t *)ptr;
}

__attribute__((stdcall))
int32_t *
KERNEL32_GlobalFree( int32_t * h_mem ) {
  //fprintf( stderr, "KERNEL32_GlobalFree(%p)\n", h_mem );
  free( h_mem );
  return 0;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetFullPathNameA( char const * lp_file_name,
                           uint32_t     n_buffer_length,
                           char *       lp_buffer,
                           char **      lp_file_part ) {
  /* Special case: Check if program is searching for itself */
  if( 0==strncmp( lp_file_name,                    __progname, strlen(__progname) ) &&
      0==strcmp(  lp_file_name+strlen(__progname), ".exe" ) ) {
    LOG_DEBUG(( "KERNEL32_GetFullPathNameA: requested System32 self exe path" ));
    return snprintf( lp_buffer, n_buffer_length, "C:\\Windows\\System32\\%s.exe", __progname );
  }

  /* Special case: license.dat */
  if( strstr( lp_file_name, "\\license.dat" ) ) {
    LOG_DEBUG(( "KERNEL32_GetFullPathNameA: requested license.dat" ));
    return snprintf( lp_buffer, n_buffer_length, "L:\\license.dat" );
  }

  size_t name_sz = strlen( lp_file_name )+1;
  size_t sz;

  /* Check if path is absolute */
  if( compat_check_winpath_absolute( lp_file_name ) ) {
    /* Bounds check */
    if( name_sz > n_buffer_length ) {
      g_last_error = ERROR_INSUFFICIENT_BUFFER;
      name_sz++;
    } else {
      /* Copy path as-is */
      memcpy( lp_buffer, lp_file_name, name_sz );
      g_last_error = ERROR_SUCCESS;
    }
    sz = name_sz;
  } else {
    /* Prepend cwdir */
    uint32_t n = KERNEL32_GetCurrentDirectoryA( n_buffer_length, lp_buffer );
    sz = n+name_sz;
    if( sz>n_buffer_length ) {
      LOG_WARN(( "KERNEL32_GetFullPathNameA(\"%s\", %u, %p, %p) failed: insufficient buffer",
                 lp_file_name, n_buffer_length, lp_buffer, lp_file_part ));
      g_last_error = ERROR_INSUFFICIENT_BUFFER;
      return sz;
    }

    /* Join with relative path */
    char * s = lp_buffer+n;
    *s++ = '\\';
    memcpy( s, lp_file_name, name_sz );
  }

  /* Fill in base name */
  char const * dbg_file_part = "";
  if( lp_file_part ) {
    char * last = strrchr( lp_buffer, '\\' );
    if( !last ) last = lp_buffer;
    dbg_file_part = *lp_file_part = last+1;
  }

  LOG_TRACE(( "KERNEL32_GetFullPathNameA(\"%s\", %u, %p, %p) => (\"%s\", \"%s\")",
              lp_file_name, n_buffer_length, lp_buffer, lp_file_part, lp_buffer, dbg_file_part ));
  g_last_error = ERROR_SUCCESS;
  return sz-1;
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

  LOG_TRACE(( "KERNEL32_WriteFile(%p, %p, %u, %p, %p)",
              h_file, lp_buffer,
              n_number_of_bytes_to_write, lp_number_of_bytes_written,
              lp_overlapped ));

  /* Check handle type */
  compat_handle_t * hdl = compat_handle_get( h_file );
  if( !hdl || (hdl->close!=compat_handle_stdio_close && hdl->close!=compat_handle_file_close) ) {
    g_last_error = ERROR_INVALID_HANDLE;
    return 0;
  }

  /* Write to file */
  FILE * f = (FILE *)hdl->data;
  size_t nbytes = fwrite( lp_buffer, 1, n_number_of_bytes_to_write, f );
  if( lp_number_of_bytes_written ) {
    *lp_number_of_bytes_written = nbytes;
  }

  if( nbytes!=n_number_of_bytes_to_write ) {
    LOG_WARN(( "KERNEL32_WriteFile(%u) failed: %s", h_file, strerror( errno ) ));
    g_last_error = ERROR_INVALID_HANDLE;
    return 0;
  }

  /* TODO check errno */

  return 1;
}

__attribute__((stdcall))
int
KERNEL32_ReadFile( uint32_t   h_file,
                   void *     lp_buffer,
                   uint32_t   n_number_of_bytes_to_read,
                   uint32_t * lp_number_of_bytes_read,
                   void *     lp_overlapped ) {
  LOG_TRACE(( "KERNEL32_ReadFile(%u, %p, %u, %p, %p)",
              h_file, lp_buffer,
              n_number_of_bytes_to_read, lp_number_of_bytes_read, lp_overlapped ));

  compat_handle_t * h = compat_handle_get( h_file );
  compat_handle_t * hdl = compat_handle_get( h_file );
  if( !hdl || (hdl->close!=compat_handle_stdio_close && hdl->close!=compat_handle_file_close) ) {
    g_last_error = ERROR_INVALID_HANDLE;
    return 0;
  }

  FILE * f = (FILE *)hdl->data;
  size_t n = fread( lp_buffer, 1, n_number_of_bytes_to_read, f );
  if( lp_number_of_bytes_read ) *lp_number_of_bytes_read = n;

  if( n!=n_number_of_bytes_to_read ) {
    LOG_WARN(( "KERNEL32_ReadFile(%u): fread failed: %s", h_file, strerror( errno ) ));
  }

  return 1;
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
  char file_path[ PATH_MAX ];

  uint32_t n = compat_winpath_to_posix( file_path, sizeof(file_path), lp_file_name );
  if( n==0 ) {
    LOG_TRACE(( "KERNEL32_CreateFileA: Cannot represent path \"%s\"", lp_file_name ));
    g_last_error = ERROR_FILE_NOT_FOUND;
    return INVALID_HANDLE_VALUE;
  }
  if( n>sizeof(file_path) ) {
    LOG_TRACE(( "KERNEL32_CreateFileA: Oversize unix path (%lu bytes)", n ));
    g_last_error = ERROR_INSUFFICIENT_BUFFER;
    return INVALID_HANDLE_VALUE;
  }

  FILE * file;
  switch( dw_desired_access ) {
  case 0x80000000: file = fopen( file_path, "rb"  ); break;
  case 0x40000000: file = fopen( file_path, "wb"  ); break;
  case 0xc0000000: file = fopen( file_path, "wb+" ); break;
  default:
    LOG_ERR(( "Unsupported CreateFileA dw_desired_access mode 0x%08x", dw_desired_access ));
    g_last_error = ERROR_INVALID_PARAMETER;
    return INVALID_HANDLE_VALUE;
  }

  LOG_DEBUG(( "KERNEL32_CreateFileA(\"%s\", %#x, %#x, %p, %u, %u, %u)",
              lp_file_name,
              dw_desired_access, dw_share_mode,
              lp_security_attributes,
              dw_creation_disposition,
              dw_flags_and_attributes,
              h_template_file ));

  if( !file ) {
    LOG_WARN(( "KERNEL32_CreateFileA: fopen(\"%s\") failed: %s", file_path, strerror( errno ) ));
    switch( errno ) {
    case EACCES:  g_last_error = ERROR_ACCESS_DENIED;  break;
    case EEXIST:  g_last_error = ERROR_ALREADY_EXISTS; break;
    case ENOENT:  g_last_error = ERROR_FILE_NOT_FOUND; break;
    case ENOTDIR: g_last_error = ERROR_PATH_NOT_FOUND; break;
    default:
      LOG_WARN(( "don't have a Win32 error code for %s", strerror( errno ) ));
      g_last_error = ERROR_NOT_SUPPORTED;
      break;
    }
    return INVALID_HANDLE_VALUE;
  }

  uint32_t h = compat_handle_alloc( file, compat_handle_file_close );
  return h;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetTickCount( void ) {
  LOG_WARN(( "[TODO] KERNEL32_GetTickCount()" ));
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

  /* Check handle type */
  compat_handle_t * hdl = compat_handle_get( h_file );
  if( !hdl || (hdl->close!=compat_handle_stdio_close && hdl->close!=compat_handle_file_close) ) {
    g_last_error = ERROR_INVALID_HANDLE;
    return 0;
  }

  FILE * f = (FILE *)hdl->data;
  int fd = fileno( f );

  /* Backup current seek */
  int64_t prev = lseek64( fd, 0,    SEEK_CUR );
  if( prev<0 ) {
    LOG_WARN(( "KERNEL32_GetFileSize(%u): fseek64 failed: %s", h_file, strerror( errno ) ));
    g_last_error = ERROR_FILE_NOT_FOUND;
    return INVALID_FILE_SIZE;
  }

  /* TODO check for errors */
  int64_t end  = lseek64( fd, 0,    SEEK_END );
                 lseek64( fd, prev, SEEK_SET );

  LOG_DEBUG(( "KERNEL32_GetFileSize(%u) = %lld", h_file, end ));

  if( *lp_file_size_high ) *lp_file_size_high = ((uint64_t)end)<<32;
  return (uint32_t)end;
}

__attribute__((stdcall))
int
KERNEL32_SetEndOfFile( uint32_t h_file ) {
  LOG_WARN(( "KERNEL32_SetEndOfFile(%u)", h_file ));
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
  //fprintf( stderr, "KERNEL32_GlobalReAlloc(%p, %u, %#x)\n", h_mem, u_bytes, u_flags );
  if( u_bytes==0 )
    u_bytes=1;

  /* libc realloc always moves */
  if( u_flags & 0x02 == 0 ) {
    g_last_error = ERROR_OUTOFMEMORY;
    return NULL;
  }

  /* Remember occupied byte range if we're instructed to zero */
  int zero = (u_flags&0x40)!=0;
  size_t sz_old;
  if (zero)
    sz_old = malloc_usable_size( h_mem );

  void * obj = realloc( h_mem, u_bytes );

  if( obj==NULL ) {
    g_last_error = ERROR_OUTOFMEMORY;
    return NULL;
  }

  /* Zero new bytes */
  g_last_error = ERROR_SUCCESS;
  if( (u_flags&0x40)!=0 ) {
    size_t sz_new = malloc_usable_size( obj );
    if( sz_new>sz_old ) {
      memset((char*)obj + sz_old, 0, sz_new - sz_old);
    }
  }
  
  return obj;
}

__attribute__((stdcall))
uint32_t
KERNEL32_GlobalFlags( int32_t * h_mem ) {
  //fprintf( stderr, "KERNEL32_GlobalFlags(%p)\n", h_mem );
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
  //fprintf( stderr, "KERNEL32_GetSystemDirectoryA(%p, %u)\n", lp_buffer, u_size );
  return snprintf( lp_buffer, u_size, "C:\\Windows\\System32" );
}

__attribute__((stdcall))
uint32_t
KERNEL32_GetWindowsDirectoryA( char *   lp_buffer,
                               uint32_t u_size ) {
  return snprintf( lp_buffer, u_size, "C:\\Windows" );
}

__attribute__((stdcall))
int
KERNEL32_SetConsoleCtrlHandler( void * lp_handler_routine,
                                int    b_add ) {
  LOG_WARN(( "[TODO] KERNEL32_SetConsoleCtrlHandler(%p, %u)", lp_handler_routine, b_add ));
  return 0;
}

__attribute__((stdcall))
int
KERNEL32_GetConsoleScreenBufferInfo( uint32_t h_console_output,
                                     void *   lp_console_screen_buffer_info ) {
  //fprintf( stderr, "KERNEL32_GetConsoleScreenBufferInfo(%u, %p)\n", h_console_output, lp_console_screen_buffer_info );
  
  struct winsize w;
  int res = ioctl( STDOUT_FILENO, TIOCGWINSZ, &w );
  if( res<0 ) {
    console_buf.dwSize.X = 80;
    console_buf.dwSize.Y = 25;
  } else {
    console_buf.dwSize.X = w.ws_col;
    console_buf.dwSize.Y = w.ws_row;
  }
  
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
  //fprintf( stderr, "LMGR8C_lp_checkout(%p, %p, \"%s\", \"%s\", %u, \"%s\")\n",
  //         v1,
  //         policy,
  //         feature, 
  //         version,
  //         num_lic,
  //         license_file_list );
  return 0;
}

__attribute__((cdecl))
void
LMGR8C_lp_checkin( void * handle ) {
  //fprintf( stderr, "LMGR8C_lp_checkin(%p)\n", handle );
}

static char lmgr8c_errbuf[4096] = {0};

/* lp_errstring	*/
__attribute__((cdecl))
char *
LMGR8C_lp_errstring( void ) {
  fprintf( stderr, "LMGR8C_lp_errstring()\n" );
  snprintf( lmgr8c_errbuf, sizeof(lmgr8c_errbuf), "Hello!" );
  return lmgr8c_errbuf;
}

__attribute__((cdecl))
int32_t
LMGR326B_lp_checkin() {
  LOG_INFO(( "LMGR326B_lp_checkin()" ));
  return 0;
}

__attribute__((cdecl))
int32_t
LMGR326B_lp_checkout() {
  LOG_INFO(( "LMGR326B_lp_checkout()" ));
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
  LOG_WARN(( "[TODO] VERSION_GetFileVersionInfoSizeA(%p, %p)", lptstr_filename, lpdw_handle ));
  lpdw_handle = NULL;
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
  fprintf( stderr, "ole32_CoCreateInstance(%04x%04x-%04x-%04x-%04x-%04x%04x%04x, %p, %u, %p, %p)\n",
                   ((uint16_t*)rclsid)[1],
                   ((uint16_t*)rclsid)[0],
                   ((uint16_t*)rclsid)[2],
                   ((uint16_t*)rclsid)[3],
                   __builtin_bswap16( ((uint16_t*)rclsid)[4] ),
                   __builtin_bswap16( ((uint16_t*)rclsid)[5] ),
                   __builtin_bswap16( ((uint16_t*)rclsid)[6] ),
                   __builtin_bswap16( ((uint16_t*)rclsid)[7] ),
                   p_unk_outer, dw_cls_context, riid, ppv );
  *ppv = NULL;
  return 1;
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
  LOG_ERR(( "[TODO] WS2_32_WSAGetLastError()" ));
  return 0;
}

__attribute__((stdcall))
uint16_t
WS2_32_ntohs( uint16_t netshort ) {
  return __builtin_bswap16( netshort );
}

__attribute__((stdcall))
char const *
WS2_32_inet_ntoa( void * in_addr ) {
  LOG_ERR(( "[TODO] WS2_32_inet_ntoa(%p)", in_addr ));
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

static int
compat_parse_loglvl_( char * lvl ) {
  if( !lvl ) return LOGLVL_DEFAULT;

  for( char *s = lvl; *s; ++s ) *s = toupper( *s );

  if( !strcmp( lvl, "FATAL"   ) ) return LOGLVL_FATAL;
  if( !strcmp( lvl, "ERR"     ) ) return LOGLVL_ERR;
  if( !strcmp( lvl, "ERROR"   ) ) return LOGLVL_ERR;
  if( !strcmp( lvl, "WARN"    ) ) return LOGLVL_WARN;
  if( !strcmp( lvl, "WARNING" ) ) return LOGLVL_WARN;
  if( !strcmp( lvl, "INFO"    ) ) return LOGLVL_INFO;
  if( !strcmp( lvl, "DBG"     ) ) return LOGLVL_DEBUG;
  if( !strcmp( lvl, "DEBUG"   ) ) return LOGLVL_DEBUG;
  if( !strcmp( lvl, "TRACE"   ) ) return LOGLVL_TRACE;

  return LOGLVL_DEFAULT;
}

int
main( int     argc,
      char ** argv ) {
  g_argc = argc;
  g_argv = argv;

  static char const * const level_str_plain[] = {
    /* 0 */ "TRACE",
    /* 1 */ "DEBUG",
    /* 2 */ "INFO ",
    /* 3 */ "WARN ",
    /* 4 */ "ERR  ",
    /* 5 */ "FATAL"
  };
  static char const * const level_str_color[] = {
    /* 0 */ "\x1b[37m" "TRACE" "\x1b[0m",
    /* 1 */ "\x1b[37m" "DEBUG" "\x1b[0m",
    /* 2 */ "\x1b[36m" "INFO " "\x1b[0m",
    /* 3 */ "\x1b[33m" "WARN " "\x1b[0m",
    /* 4 */ "\x1b[31m" "ERR  " "\x1b[0m",
    /* 5 */ "\x1b[31m" "FATAL" "\x1b[0m"
  };

  int tty = isatty( STDERR_FILENO );
  if( tty ) compat_level_str_ = level_str_color;
  else      compat_level_str_ = level_str_plain;

  log_level = compat_parse_loglvl_( getenv("WIN32_LOG") );

  unsetenv( "PATH" );

  assert( compat_stdin  = compat_handle_alloc( stdin,  compat_handle_stdio_close ) );
  assert( compat_stdout = compat_handle_alloc( stdout, compat_handle_stdio_close ) );
  assert( compat_stderr = compat_handle_alloc( stderr, compat_handle_stdio_close ) );

  __pe_text_start_enter();
}
