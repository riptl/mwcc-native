#pragma once

#include <stdint.h>
#include <stdlib.h>

#define ERROR_SUCCESS                      0
#define ERROR_INVALID_FUNCTION             1
#define ERROR_FILE_NOT_FOUND               2
#define ERROR_PATH_NOT_FOUND               3
#define ERROR_TOO_MANY_OPEN_FILES          4
#define ERROR_ACCESS_DENIED                5
#define ERROR_INVALID_HANDLE               6
#define ERROR_ARENA_TRASHED                7
#define ERROR_NOT_ENOUGH_MEMORY            8
#define ERROR_INVALID_BLOCK                9
#define ERROR_BAD_ENVIRONMENT             10
#define ERROR_BAD_FORMAT                  11
#define ERROR_INVALID_ACCESS              12
#define ERROR_INVALID_DATA                13
#define ERROR_OUTOFMEMORY                 14
#define ERROR_INVALID_DRIVE               15
#define ERROR_CURRENT_DIRECTORY           16
#define ERROR_NOT_SAME_DEVICE             17
#define ERROR_NO_MORE_FILES               18
#define ERROR_WRITE_PROTECT               19
#define ERROR_BAD_UNIT                    20
#define ERROR_NOT_READY                   21
#define ERROR_BAD_COMMAND                 22
#define ERROR_CRC                         23
#define ERROR_BAD_LENGTH                  24
#define ERROR_SEEK                        25
#define ERROR_NOT_DOS_DISK                26
#define ERROR_SECTOR_NOT_FOUND            27
#define ERROR_OUT_OF_PAPER                28
#define ERROR_WRITE_FAULT                 29
#define ERROR_READ_FAULT                  30
#define ERROR_GEN_FAILURE                 31
#define ERROR_SHARING_VIOLATION           32
#define ERROR_LOCK_VIOLATION              33
#define ERROR_WRONG_DISK                  34
#define ERROR_SHARING_BUFFER_EXCEEDED     36
#define ERROR_HANDLE_EOF                  38
#define ERROR_HANDLE_DISK_FULL            39
#define ERROR_NOT_SUPPORTED               50
#define ERROR_REM_NOT_LIST                51
#define ERROR_DUP_NAME                    52
#define ERROR_BAD_NETPATH                 53
#define ERROR_NETWORK_BUSY                54
#define ERROR_DEV_NOT_EXIST               55
#define ERROR_TOO_MANY_CMDS               56
#define ERROR_ADAP_HDW_ERR                57
#define ERROR_BAD_NET_RESP                58
#define ERROR_UNEXP_NET_ERR               59
#define ERROR_BAD_REM_ADAP                60
#define ERROR_PRINTQ_FULL                 61
#define ERROR_NO_SPOOL_SPACE              62
#define ERROR_PRINT_CANCELLED             63
#define ERROR_NETNAME_DELETED             64
#define ERROR_NETWORK_ACCESS_DENIED       65
#define ERROR_BAD_DEV_TYPE                66
#define ERROR_BAD_NET_NAME                67
#define ERROR_TOO_MANY_NAMES              68
#define ERROR_TOO_MANY_SESS               69
#define ERROR_SHARING_PAUSED              70
#define ERROR_REQ_NOT_ACCEP               71
#define ERROR_REDIR_PAUSED                72
#define ERROR_FILE_EXISTS                 80
#define ERROR_CANNOT_MAKE                 82
#define ERROR_FAIL_I24                    83
#define ERROR_OUT_OF_STRUCTURES           84
#define ERROR_ALREADY_ASSIGNED            85
#define ERROR_INVALID_PASSWORD            86
#define ERROR_INVALID_PARAMETER           87
#define ERROR_NET_WRITE_FAULT             88
#define ERROR_NO_PROC_SLOTS               89
#define ERROR_TOO_MANY_SEMAPHORES        100
#define ERROR_EXCL_SEM_ALREADY_OWNED     101
#define ERROR_SEM_IS_SET                 102
#define ERROR_TOO_MANY_SEM_REQUESTS      103
#define ERROR_INVALID_AT_INTERRUPT_TIME  104
#define ERROR_SEM_OWNER_DIED             105
#define ERROR_SEM_USER_LIMIT             106
#define ERROR_DISK_CHANGE                107
#define ERROR_DRIVE_LOCKED               108
#define ERROR_BROKEN_PIPE                109
#define ERROR_OPEN_FAILED                110
#define ERROR_BUFFER_OVERFLOW            111
#define ERROR_DISK_FULL                  112
#define ERROR_NO_MORE_SEARCH_HANDLES     113
#define ERROR_INVALID_TARGET_HANDLE      114
#define ERROR_INVALID_CATEGORY           117
#define ERROR_INVALID_VERIFY_SWITCH      118
#define ERROR_BAD_DRIVER_LEVEL           119
#define ERROR_CALL_NOT_IMPLEMENTED       120
#define ERROR_SEM_TIMEOUT                121
#define ERROR_INSUFFICIENT_BUFFER        122
#define ERROR_INVALID_NAME               123
#define ERROR_INVALID_LEVEL              124
#define ERROR_NO_VOLUME_LABEL            125
#define ERROR_MOD_NOT_FOUND              126
#define ERROR_PROC_NOT_FOUND             127
#define ERROR_WAIT_NO_CHILDREN           128
#define ERROR_CHILD_NOT_COMPLETE         129
#define ERROR_DIRECT_ACCESS_HANDLE       130
#define ERROR_NEGATIVE_SEEK              131
#define ERROR_SEEK_ON_DEVICE             132
#define ERROR_IS_JOIN_TARGET             133
#define ERROR_IS_JOINED                  134
#define ERROR_IS_SUBSTED                 135
#define ERROR_NOT_JOINED                 136
#define ERROR_NOT_SUBSTED                137
#define ERROR_JOIN_TO_JOIN               138
#define ERROR_SUBST_TO_SUBST             139
#define ERROR_JOIN_TO_SUBST              140
#define ERROR_SUBST_TO_JOIN              141
#define ERROR_BUSY_DRIVE                 142
#define ERROR_SAME_DRIVE                 143
#define ERROR_DIR_NOT_ROOT               144
#define ERROR_DIR_NOT_EMPTY              145
#define ERROR_IS_SUBST_PATH              146
#define ERROR_IS_JOIN_PATH               147
#define ERROR_PATH_BUSY                  148
#define ERROR_IS_SUBST_TARGET            149
#define ERROR_SYSTEM_TRACE               150
#define ERROR_INVALID_EVENT_COUNT        151
#define ERROR_TOO_MANY_MUXWAITERS        152
#define ERROR_INVALID_LIST_FORMAT        153
#define ERROR_LABEL_TOO_LONG             154
#define ERROR_TOO_MANY_TCBS              155
#define ERROR_SIGNAL_REFUSED             156
#define ERROR_DISCARDED                  157
#define ERROR_NOT_LOCKED                 158
#define ERROR_BAD_THREADID_ADDR          159
#define ERROR_BAD_ARGUMENTS              160
#define ERROR_BAD_PATHNAME               161
#define ERROR_SIGNAL_PENDING             162
#define ERROR_MAX_THRDS_REACHED          164
#define ERROR_LOCK_FAILED                167
#define ERROR_BUSY                       170
#define ERROR_CANCEL_VIOLATION           173
#define ERROR_ATOMIC_LOCKS_NOT_SUPPORTED 174
#define ERROR_INVALID_SEGMENT_NUMBER     180
#define ERROR_INVALID_ORDINAL            182
#define ERROR_ALREADY_EXISTS             183
#define ERROR_INVALID_FLAG_NUMBER        186
#define ERROR_SEM_NOT_FOUND              187
#define ERROR_INVALID_STARTING_CODESEG   188
#define ERROR_INVALID_STACKSEG           189
#define ERROR_INVALID_MODULETYPE         190
#define ERROR_INVALID_EXE_SIGNATURE      191
#define ERROR_EXE_MARKED_INVALID         192
#define ERROR_BAD_EXE_FORMAT             193
#define ERROR_ITERATED_DATA_EXCEEDS_64k  194
#define ERROR_INVALID_MINALLOCSIZE       195
#define ERROR_DYNLINK_FROM_INVALID_RING  196
#define ERROR_IOPL_NOT_ENABLED           197
#define ERROR_INVALID_SEGDPL             198
#define ERROR_AUTODATASEG_EXCEEDS_64k    199
#define ERROR_RING2SEG_MUST_BE_MOVABLE   200
#define ERROR_RELOC_CHAIN_XEEDS_SEGLIM   201
#define ERROR_INFLOOP_IN_RELOC_CHAIN     202
#define ERROR_ENVVAR_NOT_FOUND           203
#define ERROR_NO_SIGNAL_SENT             205
#define ERROR_FILENAME_EXCED_RANGE       206
#define ERROR_RING2_STACK_IN_USE         207
#define ERROR_META_EXPANSION_TOO_LONG    208
#define ERROR_INVALID_SIGNAL_NUMBER      209
#define ERROR_THREAD_1_INACTIVE          210
#define ERROR_LOCKED                     212
#define ERROR_TOO_MANY_MODULES           214
#define ERROR_NESTING_NOT_ALLOWED        215
#define ERROR_EXE_MACHINE_TYPE_MISMATCH  216
#define ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY        217
#define ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY 218
#define ERROR_FILE_CHECKED_OUT           220
#define ERROR_CHECKOUT_REQUIRED          221
#define ERROR_BAD_FILE_TYPE              222
#define ERROR_FILE_TOO_LARGE             223
#define ERROR_FORMS_AUTH_REQUIRED        224
#define ERROR_VIRUS_INFECTED             225
#define ERROR_VIRUS_DELETED              226
#define ERROR_PIPE_LOCAL                 229
#define ERROR_BAD_PIPE                   230
#define ERROR_PIPE_BUSY                  231
#define ERROR_NO_DATA                    232
#define ERROR_PIPE_NOT_CONNECTED         233
#define ERROR_MORE_DATA                  234
#define ERROR_VC_DISCONNECTED            240
#define ERROR_INVALID_EA_NAME            254
#define ERROR_EA_LIST_INCONSISTENT       255
#define WAIT_TIMEOUT                     258
#define ERROR_NO_MORE_ITEMS              259
#define ERROR_CANNOT_COPY                266
#define ERROR_DIRECTORY                  267
#define ERROR_EAS_DIDNT_FIT              275
#define ERROR_EA_FILE_CORRUPT            276
#define ERROR_EA_TABLE_FULL              277
#define ERROR_INVALID_EA_HANDLE          278
#define ERROR_EAS_NOT_SUPPORTED          282
#define ERROR_NOT_OWNER                  288
#define ERROR_TOO_MANY_POSTS             298
#define ERROR_PARTIAL_COPY               299
#define ERROR_OPLOCK_NOT_GRANTED         300
#define ERROR_INVALID_OPLOCK_PROTOCOL    301
#define ERROR_DISK_TOO_FRAGMENTED        302
#define ERROR_DELETE_PENDING             303
#define ERROR_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING 304
#define ERROR_SHORT_NAMES_NOT_ENABLED_ON_VOLUME  305
#define ERROR_SECURITY_STREAM_IS_INCONSISTENT    306
#define ERROR_INVALID_LOCK_RANGE                 307
#define ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT        308
#define ERROR_NOTIFICATION_GUID_ALREADY_DEFINED  309
#define ERROR_INVALID_EXCEPTION_HANDLER          310
#define ERROR_DUPLICATE_PRIVILEGES               311
#define ERROR_NO_RANGES_PROCESSED                312
#define ERROR_NOT_ALLOWED_ON_SYSTEM_FILE         313
#define ERROR_DISK_RESOURCES_EXHAUSTED           314
#define ERROR_INVALID_TOKEN                      315
#define ERROR_DEVICE_FEATURE_NOT_SUPPORTED       316
#define ERROR_MR_MID_NOT_FOUND           317
#define ERROR_SCOPE_NOT_FOUND            318
#define ERROR_UNDEFINED_SCOPE            319
#define ERROR_INVALID_CAP                320
#define ERROR_DEVICE_UNREACHABLE         321
#define ERROR_DEVICE_NO_RESOURCES        322
#define ERROR_DATA_CHECKSUM_ERROR        323
#define ERROR_INTERMIXED_KERNEL_EA_OPERATION     324
#define ERROR_FILE_LEVEL_TRIM_NOT_SUPPORTED      326
#define ERROR_OFFSET_ALIGNMENT_VIOLATION         327
#define ERROR_INVALID_FIELD_IN_PARAMETER_LIST    328
#define ERROR_OPERATION_IN_PROGRESS      329
#define ERROR_BAD_DEVICE_PATH            330
#define ERROR_TOO_MANY_DESCRIPTORS       331
#define ERROR_SCRUB_DATA_DISABLED        332
#define ERROR_NOT_REDUNDANT_STORAGE      333
#define ERROR_RESIDENT_FILE_NOT_SUPPORTED        334
#define ERROR_COMPRESSED_FILE_NOT_SUPPORTED      335
#define ERROR_DIRECTORY_NOT_SUPPORTED    336
#define ERROR_NOT_READ_FROM_COPY         337
#define ERROR_FAIL_NOACTION_REBOOT       350
#define ERROR_FAIL_SHUTDOWN              351
#define ERROR_FAIL_RESTART               352
#define ERROR_MAX_SESSIONS_REACHED       353
#define ERROR_THREAD_MODE_ALREADY_BACKGROUND     400
#define ERROR_THREAD_MODE_NOT_BACKGROUND         401
#define ERROR_PROCESS_MODE_ALREADY_BACKGROUND    402
#define ERROR_PROCESS_MODE_NOT_BACKGROUND        403
#define ERROR_INVALID_ADDRESS            487

#define TLS_OUT_OF_INDEXES 0xFFFFFFFF

#define HKEY_CLASSES_ROOT     0x80000000
#define HKEY_CURRENT_USER     0x80000001
#define HKEY_LOCAL_MACHINE    0x80000002
#define HKEY_USERS            0x80000003
#define HKEY_PERFORMANCE_DATA 0x80000004
#define HKEY_CURRENT_CONFIG   0x80000005
#define HKEY_DYN_DATA         0x80000006

#define INVALID_HANDLE_VALUE (-1)

#define GMEM_INVALID_HANDLE 0x8000

#define STD_INPUT_HANDLE  (-10)
#define STD_OUTPUT_HANDLE (-11)
#define STD_ERROR_HANDLE  (-12)

/* If HAS_THREADS is 0, locking-related syscalls are no-ops */
//#define HAS_THREADS 1

#ifdef __cplusplus
extern "C" {
#endif

extern int     g_argc;
extern char ** g_argv;

// Generated by pe2elf

extern uint8_t __pe_text_start[];
extern uint8_t __pe_rodata_exc_start[];
extern uint8_t __pe_rodata_start[];
extern uint8_t __pe_data_start[];
extern uint8_t __pe_data_CRT_start[];
extern uint8_t __pe_data_idata_start[];

#define __pe_text_start_enter() __asm__ volatile ("jmp __pe_text_start")

extern int const __pe_str_cnt;
extern char const * const __pe_strs[];

// PE imports

__attribute__((stdcall))
int32_t
ADVAPI32_RegOpenKeyExA( uint32_t     h_key,
                        const char * lp_sub_key,
                        uint32_t     ul_options,
                        uint32_t     sam_desired,
                        void **      phk_result );

__attribute__((stdcall))
int32_t
ADVAPI32_RegQueryValueExA( void *       h_key,
                           const char * lp_value_name,
                           uint32_t *   lp_reserved,
                           uint32_t *   lp_type,
                           uint8_t *    lp_data,
                           uint32_t *   lpcb_data );

__attribute__((stdcall))
int32_t
ADVAPI32_RegCloseKey( void * h_key );

__attribute__((stdcall))
int32_t
KERNEL32_IsBadReadPtr( const void * lp,
                       uint32_t     ucb );

__attribute__((stdcall))
void
KERNEL32_RtlUnwind( void * target_frame,
                    void * target_ip,
                    void * exception_record,
                    void * return_value );

__attribute__((stdcall))
void
KERNEL32_ExitProcess( uint32_t exit_code );

__attribute__((stdcall))
int32_t
KERNEL32_GetCurrentProcess( void );

__attribute__((stdcall))
int32_t
KERNEL32_DuplicateHandle( void *   h_source_process_handle,
                          void *   h_source_handle,
                          void *   h_target_process_handle,
                          void **  lp_target_handle,
                          uint32_t dw_desired_access,
                          int32_t  b_inherit_handle,
                          uint32_t dw_options );

__attribute__((stdcall))
int32_t
KERNEL32_GetLastError( void );

__attribute__((stdcall))
void *
KERNEL32_GetStdHandle( int32_t n_std_handle );

__attribute__((stdcall))
void
KERNEL32_InitializeCriticalSection( void * lp_critical_section );

__attribute__((stdcall))
void
KERNEL32_DeleteCriticalSection( void * lp_critical_section );

__attribute__((stdcall))
uint32_t
KERNEL32_FindFirstFileA( const char * lp_file_name,
                         void *       lp_find_file_data );

__attribute__((stdcall))
uint32_t
KERNEL32_GetFileAttributesA( const char * lp_file_name );

__attribute__((stdcall))
int
KERNEL32_FindNextFileA( uint32_t h_find_file,
                        void *   lp_find_file_data );

__attribute__((stdcall))
int
KERNEL32_FindClose( uint32_t h_find_file );


__attribute__((stdcall))
char *
KERNEL32_GetCommandLineA( void );

__attribute__((stdcall))
char *
KERNEL32_GetEnvironmentStrings( void );

__attribute__((stdcall))
int
KERNEL32_FreeEnvironmentStringsA( char * lpsz_environment_block );

__attribute__((stdcall))
uint32_t
KERNEL32_GetCurrentDirectoryA( uint32_t n_buffer_length,
                               char *   lp_buffer );

__attribute__((stdcall))
int
KERNEL32_CreateProcessA( const char * lp_application_name,
                         char *       lp_command_line,
                         void *       lp_process_attributes,
                         void *       lp_thread_attributes,
                         int32_t      b_inherit_handles,
                         uint32_t     dw_creation_flags,
                         void *       lp_environment,
                         const char * lp_current_directory,
                         void *       lp_startup_info,
                         void *       lp_process_information );

__attribute__((stdcall))
uint32_t
KERNEL32_WaitForSingleObject( uint32_t h_handle,
                              uint32_t dw_milliseconds );

__attribute__((stdcall))
int
KERNEL32_GetExitCodeProcess( uint32_t h_process,
                             uint32_t * lp_exit_code );

__attribute__((stdcall))
int
KERNEL32_CloseHandle( uint32_t h_object );

__attribute__((stdcall))
uint32_t
KERNEL32_TlsAlloc( void );

__attribute__((stdcall))
int
KERNEL32_TlsFree( uint32_t dw_tls_index );

__attribute__((stdcall))
uint32_t
KERNEL32_TlsGetValue( uint32_t dw_tls_index );

__attribute__((stdcall))
int
KERNEL32_TlsSetValue( uint32_t dw_tls_index,
                      uint32_t lp_tls_value );

__attribute__((stdcall))
void *
KERNEL32_GetModuleHandleA( char const * lp_module_name );

__attribute__((stdcall))
uint32_t
KERNEL32_GetModuleFileNameA( void *   h_module,
                             char *   lp_file_name,
                             uint32_t n_size );

__attribute__((stdcall))
void *
KERNEL32_LoadLibraryA( char const * lp_lib_file_name );

__attribute__((stdcall))
int
KERNEL32_FreeLibrary( void * h_lib_module );

__attribute__((stdcall))
int32_t *
KERNEL32_GlobalAlloc( uint32_t u_flags,
                      uint32_t dw_bytes );

__attribute__((stdcall))
int32_t *
KERNEL32_GlobalFree( int32_t * h_mem );

__attribute__((stdcall))
uint32_t
KERNEL32_GetFullPathNameA( char const * lp_file_name,
                           uint32_t     n_buffer_length,
                           char *       lp_buffer,
                           char **      lp_file_part );

__attribute__((stdcall))
uint32_t
KERNEL32_SetFilePointer( uint32_t  h_file,
                         int32_t   l_distance_to_move,
                         int32_t * lp_distance_to_move_high,
                         uint32_t  dw_move_method );

__attribute__((stdcall))
int
KERNEL32_WriteFile( uint32_t     h_file,
                    void const * lp_buffer,
                    uint32_t     n_number_of_bytes_to_write,
                    uint32_t *   lp_number_of_bytes_written,
                    void *       lp_overlapped );

__attribute__((stdcall))
int
KERNEL32_ReadFile( uint32_t   h_file,
                   void *     lp_buffer,
                   uint32_t   n_number_of_bytes_to_read,
                   uint32_t * lp_number_of_bytes_read,
                   void *     lp_overlapped );

__attribute__((stdcall))
uint32_t
KERNEL32_CreateFileA( char const * lp_file_name,
                      uint32_t     dw_desired_access,
                      uint32_t     dw_share_mode,
                      void *       lp_security_attributes,
                      uint32_t     dw_creation_disposition,
                      uint32_t     dw_flags_and_attributes,
                      uint32_t     h_template_file );

__attribute__((stdcall))
uint32_t
KERNEL32_GetTickCount( void );

__attribute__((stdcall))
int
KERNEL32_DeleteFileA( char const * lp_file_name );

__attribute__((stdcall))
int
KERNEL32_MoveFileA( char const * lp_existing_file_name,
                    char const * lp_new_file_name );

__attribute__((stdcall))
uint32_t
KERNEL32_FormatMessageA( uint32_t  dw_flags,
                         void *    lp_source,
                         uint32_t  dw_message_id,
                         uint32_t  dw_language_id,
                         char *    lp_buffer,
                         uint32_t  n_size,
                         void *    arguments );

__attribute__((stdcall))
int
KERNEL32_GetFileTime( uint32_t h_file,
                      void *   lp_creation_time,
                      void *   lp_last_access_time,
                      void *   lp_last_write_time );

__attribute__((stdcall))
int
KERNEL32_SetFileTime( uint32_t h_file,
                      void *   lp_creation_time,
                      void *   lp_last_access_time,
                      void *   lp_last_write_time );

__attribute__((stdcall))
uint32_t
KERNEL32_GetFileSize( uint32_t h_file,
                      uint32_t * lp_file_size_high );

__attribute__((stdcall))
int
KERNEL32_SetEndOfFile( uint32_t h_file );

__attribute__((stdcall))
int
KERNEL32_CreateDirectoryA( char const * lp_path_name,
                           void *       lp_security_attributes );

__attribute__((stdcall))
int
KERNEL32_RemoveDirectoryA( char const * lp_path_name );

__attribute__((stdcall))
int
KERNEL32_SetStdHandle( uint32_t n_std_handle,
                       uint32_t h_handle );

__attribute__((stdcall))
void
KERNEL32_GetSystemTime( void * lp_system_time );

__attribute__((stdcall))
int
KERNEL32_SystemTimeToFileTime( void * lp_system_time,
                               void * lp_file_time );

__attribute__((stdcall))
int32_t
KERNEL32_CompareFileTime( void * lp_file_time_1,
                          void * lp_file_time_2 );

__attribute__((stdcall))
int32_t *
KERNEL32_GlobalReAlloc( int32_t * h_mem,
                        uint32_t  u_bytes,
                        uint32_t  u_flags );

__attribute__((stdcall))
uint32_t
KERNEL32_GlobalFlags( int32_t * h_mem );

__attribute__((stdcall))
int
KERNEL32_FileTimeToSystemTime( void * lp_file_time,
                               void * lp_system_time );

__attribute__((stdcall))
uint32_t
KERNEL32_FindResourceA( uint32_t     h_module,
                        char const * lp_name,
                        char const * lp_type );

__attribute__((stdcall))
int32_t *
KERNEL32_LoadResource( uint32_t h_module,
                       uint32_t h_resource );

__attribute__((stdcall))
void *
KERNEL32_LockResource( int32_t * h_resource );

__attribute__((stdcall))
uint32_t
KERNEL32_SizeofResource( uint32_t h_module,
                         uint32_t h_resource );

__attribute__((stdcall))
uint32_t
KERNEL32_CreateFileMappingA( uint32_t     h_file,
                             void *       lp_file_mapping_attributes,
                             uint32_t     fl_protect,
                             uint32_t     dw_maximum_size_high,
                             uint32_t     dw_maximum_size_low,
                             char const * lp_name );

__attribute__((stdcall))
int32_t *
KERNEL32_MapViewOfFile( uint32_t h_file_mapping_object,
                        uint32_t dw_desired_access,
                        uint32_t dw_file_offset_high,
                        uint32_t dw_file_offset_low,
                        uint32_t dw_number_of_bytes_to_map );

__attribute__((stdcall))
int
KERNEL32_UnmapViewOfFile( int32_t * lp_base_address );

__attribute__((stdcall))
uint32_t
KERNEL32_GetSystemDirectoryA( char * lp_buffer,
                              uint32_t u_size );

__attribute__((stdcall))
uint32_t
KERNEL32_GetWindowsDirectoryA( char *   lp_buffer,
                               uint32_t u_size );

__attribute__((stdcall))
int
KERNEL32_SetConsoleCtrlHandler( void * lp_handler_routine,
                                int    b_add );

__attribute__((stdcall))
int
KERNEL32_GetConsoleScreenBufferInfo( uint32_t h_console_output,
                                     void *   lp_console_screen_buffer_info );

__attribute__((stdcall))
int
KERNEL32_SetFileAttributesA( char const * lp_file_name,
                             uint32_t     dw_file_attributes );

__attribute__((stdcall))
uint32_t
KERNEL32_OpenFileMappingA( uint32_t     dw_desired_access,
                           int          b_inherit_handle,
                           char const * lp_name );

__attribute__((stdcall))
int32_t
KERNEL32_MultiByteToWideChar( uint32_t     u_code_page,
                              uint32_t     dw_flags,
                              char const * lp_multi_byte_str,
                              int          cch_multi_byte,
                              void *       lp_wide_char_str,
                              int          cch_wide_char );

__attribute__((stdcall))
int
KERNEL32_IsValidCodePage( uint32_t u_code_page );

__attribute__((stdcall))
uint32_t
KERNEL32_GetACP( void );

__attribute__((stdcall))
void
KERNEL32_GetLocalTime( void * lp_system_time );

__attribute__((stdcall))
uint32_t
KERNEL32_GetTimeZoneInformation( void * lp_time_zone_information );

__attribute__((cdecl))
int32_t
LMGR8C_lp_checkout( int32_t v1,
                    int32_t policy,
                    char *  feature,
                    char *  version,
                    int     num_lic,
                    char *  license_file_list );

__attribute__((cdecl))
int32_t
LMGR8C_lp_checkin( int32_t, int32_t, int32_t, int32_t, int32_t, int32_t );

__attribute__((cdecl))
int32_t
LMGR8C_lp_errstring( void );

__attribute__((stdcall))
int
USER32_MessageBoxA( uint32_t     h_wnd,
                    char const * lp_text,
                    char const * lp_caption,
                    uint32_t     u_type );

__attribute__((stdcall))
int32_t
USER32_LoadStringA( uint32_t h_instance,
                    uint32_t u_id,
                    char *   lp_buffer,
                    int      n_buffer_max );

__attribute__((stdcall))
uint32_t
VERSION_GetFileVersionInfoSizeA( char const * lptstr_filename,
                                 uint32_t *   lpdw_handle );

__attribute__((stdcall))
int
VERSION_GetFileVersionInfoA( char const * lptstr_filename,
                             uint32_t     dw_handle,
                             uint32_t     dw_len,
                             void *       lp_data );

__attribute__((stdcall))
int
VERSION_VerQueryValueA( void const * p_block,
                        char const * lp_sub_block,
                        void **      lplp_buffer,
                        uint32_t *   pu_len );

__attribute__((stdcall))
int
ole32_CoInitialize( void * pv_reserved );

__attribute__((stdcall))
void
ole32_CoUninitialize( void );

__attribute__((stdcall))
int
ole32_CoCreateInstance( void *   rclsid,
                        void *   p_unk_outer,
                        uint32_t dw_cls_context,
                        void *   riid,
                        void **  ppv );

__attribute__((stdcall))
void
ole32_CoTaskMemFree( void * pv );

__attribute__((stdcall))
void *
ole32_CoTaskMemAlloc( uint32_t cb );

__attribute__((stdcall))
int
WS2_32_WSAStartup( uint16_t w_version_requested,
                   void *   lp_wsa_data );

__attribute__((stdcall))
int
WS2_32_WSAGetLastError( void );

__attribute__((stdcall))
uint16_t
WS2_32_ntohs( uint16_t netshort );

__attribute__((stdcall))
char const *
WS2_32_inet_ntoa( void * in_addr );

__attribute__((stdcall))
int
WS2_32_shutdown( uint32_t s,
                 int      how );

__attribute__((stdcall))
int
WS2_32_closesocket( uint32_t s );

__attribute__((stdcall))
int
WS2_32_WSACleanup( void );

__attribute__((stdcall))
uint32_t
WS2_32_socket( int af,
               int type,
               int protocol );

__attribute__((stdcall))
uint16_t
WS2_32_htons( uint16_t hostshort );

__attribute__((stdcall))
uint32_t
WS2_32_inet_addr( char const * cp );

__attribute__((stdcall))
int
WS2_32_connect( uint32_t s,
                void *   name,
                int      namelen );

__attribute__((stdcall))
int
WS2_32_select( int    nfds,
               void * readfds,
               void * writefds,
               void * exceptfds,
               void * timeout );

__attribute__((stdcall))
int
WS2_32___WSAFDIsSet( uint32_t s,
                     void *   fd_set );

__attribute__((stdcall))
int
WS2_32_send( uint32_t s,
             void *   buf,
             int      len,
             int      flags );

__attribute__((stdcall))
int
WS2_32_recv( uint32_t s,
             void *   buf,
             int      len,
             int      flags );

__attribute__((stdcall))
void
KERNEL32_EnterCriticalSection( void * lp_critical_section );

__attribute__((stdcall))
void
KERNEL32_LeaveCriticalSection( void * lp_critical_section );

#ifdef __cplusplus
}
#endif
