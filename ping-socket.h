#ifndef _PING_SOCKET_
#define _PING_SOCKET_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* for additional type definitions */
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 /* for inet_XtoY functions on MinGW */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <process.h> /* _getpid() */
#include <winsock2.h>
#include <ws2tcpip.h> /* getaddrinfo() */
#include <mswsock.h>  /* WSARecvMsg() */

#undef CMSG_SPACE
#define CMSG_SPACE WSA_CMSG_SPACE
#undef CMSG_FIRSTHDR
#define CMSG_FIRSTHDR WSA_CMSG_FIRSTHDR
#undef CMSG_NXTHDR
#define CMSG_NXTHDR WSA_CMSG_NXTHDR
#undef CMSG_DATA
#define CMSG_DATA WSA_CMSG_DATA

typedef SOCKET socket_t;
typedef WSAMSG msghdr_t;
typedef WSACMSGHDR cmsghdr_t;

/*
 * Pointer to the WSARecvMsg() function. It must be obtained at runtime...
 */
static LPFN_WSARECVMSG WSARecvMsg;

#else /* NOT _WIN32 */

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542 /* for IPv6 definitions on Apple platforms */
#endif

#include <errno.h>
#include <fcntl.h> /* fcntl() */
#include <netdb.h> /* getaddrinfo() */
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>  /* inet_XtoY() */
#include <netinet/in.h> /* IPPROTO_ICMP */
#include <netinet/ip6.h> 
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h> /* struct icmp */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

typedef int socket_t;
typedef struct msghdr msghdr_t;
typedef struct cmsghdr cmsghdr_t;

#endif /* !_WIN32 */

#define IP_VERSION_ANY 0
#define IP_V4 4
#define IP_V6 6

#define ICMP_HEADER_LENGTH 8
#define MESSAGE_BUFFER_SIZE 1024

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHO6
#define ICMP6_ECHO 128
#endif
#ifndef ICMP_ECHO_REPLY
#define ICMP_ECHO_REPLY 0
#endif
#ifndef ICMP_ECHO_REPLY6
#define ICMP6_ECHO_REPLY 129
#endif

#define REQUEST_TIMEOUT 1000000
#define REQUEST_INTERVAL 1000000

#ifdef _WIN32
#define socket(af, type, protocol) \
    WSASocketW(af, type, protocol, NULL, 0, 0)
#define close_socket closesocket
#define getpid _getpid
#define usleep(usec) Sleep((DWORD)((usec) / 1000))
#else
#define close_socket close
#endif

#pragma pack(push, 1)

#if defined _WIN32 || defined __CYGWIN__

#if defined _MSC_VER || defined __MINGW32__
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#endif

struct icmp
{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_cksum;
    uint16_t icmp_id;
    uint16_t icmp_seq;
};

#endif /* _WIN32 || __CYGWIN__ */

struct ip6_pseudo_hdr
{
    struct in6_addr src;
    struct in6_addr dst;
    uint8_t unused1[2];
    uint16_t plen;
    uint8_t unused2[3];
    uint8_t nxt;
};

struct icmp6_packet
{
    struct ip6_pseudo_hdr ip6_hdr;
    struct icmp icmp;
};

#pragma pack(pop)

int get_ping_result(char* targetIP);

static uint16_t compute_checksum(const char* buf, size_t size);
// Convert IP address string to sockaddr structure
int convert_ip_to_sockaddr(const char* ip_address, struct sockaddr_storage* addr, socklen_t* dst_addr_len);
// Create a raw socket
socket_t create_raw_socket(int family);
// Set socket to non-blocking mode
int set_socket_non_blocking(socket_t sockfd);
// Set socket options
int set_socket_options(socket_t sockfd, int family);
// Drop superuser privileges
void drop_privileges();
// Send ICMP echo request
int send_icmp_request(socket_t sockfd, struct sockaddr* addr, socklen_t addr_len, uint16_t id, int seq, int family);
// Receive ICMP echo reply
int receive_icmp_reply(socket_t sockfd, struct sockaddr_storage* addr, uint16_t id, int seq, uint64_t start_time);

// Returns a timestamp with microsecond resolution.
static uint64_t utime(void);

#ifdef _WIN32
// psockerror() is like perror() but for the Windows Sockets API.
static void psockerror(const char* s);
#else /* _WIN32 */
#define psockerror perror
#endif /* !_WIN32 */

#endif // !_PING_SOCKET_