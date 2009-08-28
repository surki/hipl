#include "netwrap.h"
#include <string.h>
#include "fwint.h"
#include <errno.h>

int
inet_pton(const int af,
	  const char *src,
	  void *dst)
{
    int ret = -1;

    if (AF_INET == af) {
	*(uint32_t *)dst = inet_addr(src);
	ret = 1;
    } else if (AF_INET6 == af) {
	INT err;
	struct sockaddr_in6 saddr;
	INT saddr_len = sizeof(saddr);
	
	err = WSAStringToAddress((char *)src, // LPTSTR AddressString,
	    af, // INT AddressFamily,
	    NULL, // LPWSAPROTOCOL_INFO lpProtocolInfo,
	    (LPSOCKADDR)&saddr, // LPSOCKADDR lpAddress,
	    &saddr_len); // LPINT lpAddressLength
	if (0 == err) {
	    memcpy((char *)dst, saddr.sin6_addr.u.Byte, sizeof(struct in6_addr));
	    ret = 1;
	} else {
	    ret = 0;
	}
    }

    return ret;
}

const char *
inet_ntop(const int af,
	  const void *src,
	  char *dst,
	  const size_t cnt)
{
    char *ret = NULL;

    if (AF_INET == af) {
	char *res = inet_ntoa(*(struct in_addr *)src);
	if (cnt > strlen(res)) {
	    strcpy(dst, res);
	    ret = dst;
	}
    } else if (AF_INET6 == af) {
	// WSAAddressToString() does a bit more than we need
    }

    return ret;
}

int
nw_init(void)
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    
    wVersionRequested = MAKEWORD( 2, 2 );
     
    err = WSAStartup( wVersionRequested, &wsaData );
    if ( err == 0 ) {
	if ( LOBYTE( wsaData.wVersion ) == 2 && HIBYTE( wsaData.wVersion ) == 2 ) {
	    return 0;
	}
	WSACleanup( );
    }
     
    return 1;
}

int
nw_fini(void)
{
    return WSACleanup();
}

int
nw_close(nw_skt_t socket)
{
    return closesocket(socket);
}

int
nw_error(void)
{
    // return UNIX errno values
    int err = WSAGetLastError();
    switch (err) {
	case WSANOTINITIALISED:
	case WSAEINVAL:
	case WSAEINPROGRESS:
	case WSAEADDRNOTAVAIL:
	case WSAEAFNOSUPPORT:
	    return EINVAL;
	case WSAEINTR:
	    return EINTR;
	case WSAENOTSOCK:
	    return EBADF;
	case WSAENETDOWN:
	    return ENETDOWN;
	case WSAEACCES:
	    return EAFNOSUPPORT;
	case WSAEFAULT:
	    return EFAULT;
	case WSAENETRESET:
	    return ECONNRESET;
	case WSAENOBUFS:
	    return ENOBUFS;
	case WSAENOTCONN:
	    return ENOTCONN;
	case WSAEOPNOTSUPP:
	    return EOPNOTSUPP;
	case WSAESHUTDOWN:
	    return ENOTCONN;
	case WSAEWOULDBLOCK:
	    return EWOULDBLOCK;
	case WSAEMSGSIZE:
	    return EMSGSIZE;
	case WSAEHOSTUNREACH:
	    return EHOSTUNREACH;
	case WSAECONNABORTED:
	case WSAECONNRESET:
	    return ECONNRESET;
	case WSAEDESTADDRREQ:
	    return EDESTADDRREQ;
	case WSAENETUNREACH:
	    return ENETUNREACH;
	case WSAETIMEDOUT:
	    return EHOSTUNREACH;
	default:
	    return err;
    }
}

int
nw_set_nblk(nw_skt_t socket, int nblk)
{
    u_long par = (u_long)nblk;
    return ioctlsocket(socket, FIONBIO, &par);
}
