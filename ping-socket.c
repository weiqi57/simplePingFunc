#include "ping-socket.h"

/* only can used in qt and c++ environment  */
/*
#include <QTcpSocket>
#include <QString>
bool is_ping_success(QString ip, int port, int timeout_ms) {
    QTcpSocket tcpClient;
    tcpClient.abort();
    tcpClient.connectToHost(ip, port);
    bool ret = tcpClient.waitForConnected(timeout_ms);  //timeout毫秒没有连接上则判断不在线
    printf(":%d state:%d", ip.toStdString().c_str(), port, ret);
    return ret;
}
*/

int main(int argc, char **argv)
{
    char *targetIP = "192.168.1.1";

    printf("try ping to %s\n", targetIP);

    int res = get_ping_result(targetIP);
    if (res == 1)
    {
        printf("ping success!\n");
    }
    else
    {
        printf("ping failed!\n");
    }
}


#ifndef _WIN32
#include <netinet/in.h> 
struct in6_pktinfo
{
    struct in6_addr ipi6_addr;	/* src/dst IPv6 address */
    unsigned int ipi6_ifindex;	/* send/recv interface index */
};
#endif


#ifdef _WIN32

static void init_winsock_lib(void)
{
    int error;
    WSADATA wsa_data;

    error = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (error != 0)
    {
        printf("Failed to initialize WinSock: %d\n", error);
        exit(EXIT_FAILURE);
    }
}

static void init_winsock_extensions(socket_t sockfd)
{
    int error;
    GUID recvmsg_id = WSAID_WSARECVMSG;
    DWORD size;

    /*
     * Obtain a pointer to the WSARecvMsg (recvmsg) function.
     */
    error = WSAIoctl(sockfd,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &recvmsg_id,
        sizeof(recvmsg_id),
        &WSARecvMsg,
        sizeof(WSARecvMsg),
        &size,
        NULL,
        NULL);
    if (error == SOCKET_ERROR)
    {
        psockerror("WSAIoctl");
        exit(EXIT_FAILURE);
    }
}

#endif /* _WIN32 */


int get_ping_result(char* targetIP)
{
    char* ip_address = targetIP;
    int ip_version = IP_VERSION_ANY;
    int error;
    socket_t sockfd = -1;
    char addr_str[INET6_ADDRSTRLEN] = "<unknown>";
    struct sockaddr_storage addr;
    socklen_t dst_addr_len;
    uint16_t id = (uint16_t)getpid();
    uint64_t start_time;
    uint64_t delay;

#ifdef _WIN32
    init_winsock_lib();
#endif

    // Convert IP address to sockaddr structure
    if (convert_ip_to_sockaddr(ip_address, &addr, &dst_addr_len) != 0)
    {
        goto exit_error;
    }

    // Create raw socket
    sockfd = create_raw_socket(addr.ss_family);
    if (sockfd < 0)
    {
        goto exit_error;
    }

    // OK Set socket to non-blocking mode
    if (set_socket_non_blocking(sockfd) != 0)
    {
        goto exit_error;
    }

    // Set socket options
    if (set_socket_options(sockfd, addr.ss_family) != 0)
    {
        goto exit_error;
    }

    // Drop superuser privileges
#if !defined _WIN32
    drop_privileges();
#endif

    /*
     * Convert the destination IP-address to a string.
     */
    inet_ntop(addr.ss_family,
        addr.ss_family == AF_INET6
        ? (void*)&((struct sockaddr_in6*)&addr)->sin6_addr
        : (void*)&((struct sockaddr_in*)&addr)->sin_addr,
        addr_str,
        sizeof(addr_str));
    int count = 0;
    for (int seq = 0; seq < 3; seq++)
    {

        // Send ICMP request
        if (send_icmp_request(sockfd, (struct sockaddr*)&addr, dst_addr_len, id, seq, addr.ss_family) != 0)
        {
            goto exit_error;
        }

        start_time = utime();   //记录发送时间

        // Receive ICMP reply
        if (receive_icmp_reply(sockfd, &addr, id, seq, start_time) != 0){
            continue;
        }else{
            count++;
        }
    }
    if (count == 3) {
        printf("get ping result success for %s!\n", targetIP);
        close_socket(sockfd);
        return 1;
    }
exit_error:
    printf("get ping result timeout for %s!\n", targetIP);
    close_socket(sockfd);
    return 0;
}


// 检查和计算校验和
static uint16_t compute_checksum(const char* buf, size_t size)
{
    /* RFC 1071 - http://tools.ietf.org/html/rfc1071 */

    size_t i;
    uint64_t sum = 0;

    for (i = 0; i < size; i += 2)
    {
        sum += *(uint16_t*)buf;
        buf += 2;
    }
    if (size - i > 0)
        sum += *(uint8_t*)buf;

    // 使得sum的高16位为0
    while ((sum >> 16) != 0)
        sum = (sum & 0xffff) + (sum >> 16);

    // 求反得到校验和
    return (uint16_t)~sum;
}

// Convert IP address string to sockaddr structure
int convert_ip_to_sockaddr(const char* ip_address, struct sockaddr_storage* addr, socklen_t* dst_addr_len)
{
    int error;
    struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
    struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;

    addr_in->sin_family = AF_INET;
    error = inet_pton(AF_INET, ip_address, &(addr_in->sin_addr));
    if (error == 1)
    {
        addr->ss_family = AF_INET;
        *dst_addr_len = sizeof(struct sockaddr_in);
        return 0;
    }
    else
    {
        addr_in6->sin6_family = AF_INET6;
        error = inet_pton(AF_INET6, ip_address, &(addr_in6->sin6_addr));
        if (error == 1)
        {
            addr->ss_family = AF_INET6;
            *dst_addr_len = sizeof(struct sockaddr_in6);
            return 0;
        }
    }

    printf("inet_pton: invalid IP address %s\n", ip_address);
    return -1;
}

// Create a raw socket
socket_t create_raw_socket(int family)
{
    socket_t sockfd = socket(family, SOCK_RAW, family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6);
    if (sockfd < 0)
    {
        psockerror("socket");
        return -1;
    }

#ifdef _WIN32
    init_winsock_extensions(sockfd);
#endif

    return sockfd;
}

// Set socket to non-blocking mode
int set_socket_non_blocking(socket_t sockfd)
{
#ifdef _WIN32
    u_long opt_value = 1;
    if (ioctlsocket(sockfd, FIONBIO, &opt_value) != 0)
    {
        psockerror("ioctlsocket");
        return -1;
    }
#else
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1)
    {
        psockerror("fcntl");
        return -1;
    }
#endif

    return 0;
}

// Set socket options
int set_socket_options(socket_t sockfd, int family)
{
    int error;
    if (family == AF_INET6)
    {
        /*
         * This allows us to receive IPv6 packet headers in incoming messages.
         */
        int opt_value = 1;
        error = setsockopt(sockfd,
            IPPROTO_IPV6,
#if defined _WIN32 || defined __CYGWIN__
            IPV6_PKTINFO,
#else
            IPV6_RECVPKTINFO,
#endif
            (char*)&opt_value,
            sizeof(opt_value));
        if (error != 0)
        {
            psockerror("setsockopt");
            return -1;
        }
    }

    return 0;
}

// Drop superuser privileges
void drop_privileges()
{
#if !defined _WIN32
    if (setgid(getgid()) != 0)
    {
        perror("setgid");
        exit(EXIT_FAILURE);
    }
    if (setuid(getuid()) != 0)
    {
        perror("setuid");
        exit(EXIT_FAILURE);
    }
#endif
}

// Send ICMP echo request
int send_icmp_request(socket_t sockfd, struct sockaddr* addr, socklen_t addr_len, uint16_t id, int seq, int family)
{
    struct icmp request;

    request.icmp_type = family == AF_INET6 ? ICMP6_ECHO : ICMP_ECHO;
    request.icmp_code = 0;
    request.icmp_cksum = 0;
    request.icmp_id = htons(id);
    request.icmp_seq = htons(seq);

    if (family == AF_INET6)
    {
        struct icmp6_packet request_packet = { 0 };
        request_packet.ip6_hdr.src = in6addr_loopback;
        request_packet.ip6_hdr.dst = ((struct sockaddr_in6*)addr)->sin6_addr;
        request_packet.ip6_hdr.plen = htons((uint16_t)ICMP_HEADER_LENGTH);
        request_packet.ip6_hdr.nxt = IPPROTO_ICMPV6;
        request_packet.icmp = request;
        request.icmp_cksum = compute_checksum((char*)&request_packet, sizeof(request_packet));
    }
    else
    {
        request.icmp_cksum = compute_checksum((char*)&request, sizeof(request));
    }

    int error = (int)sendto(sockfd, (char*)&request, sizeof(request), 0, addr, addr_len);
    if (error < 0)
    {
        psockerror("sendto");
        return -1;
    }

    return 0;
}

// Receive ICMP echo reply
int receive_icmp_reply(socket_t sockfd, struct sockaddr_storage* addr, uint16_t id, int seq, uint64_t start_time)
{
    int index = 0;
    while (1)
    {
        index++;

        char msg_buf[MESSAGE_BUFFER_SIZE];
        char packet_info_buf[MESSAGE_BUFFER_SIZE];
        struct in6_addr msg_addr = { 0 };

#ifdef _WIN32
        WSABUF msg_buf_struct = {
            sizeof(msg_buf),
            msg_buf };
        WSAMSG msg = {
            NULL,
            0,
            &msg_buf_struct,
            1,
            {sizeof(packet_info_buf), packet_info_buf},
            0 };
        DWORD msg_len = 0;
#else  /* _WIN32 */
        struct iovec msg_buf_struct = {
            msg_buf,
            sizeof(msg_buf) };
        struct msghdr msg = {
            NULL,
            0,
            &msg_buf_struct,
            1,
            packet_info_buf,
            sizeof(packet_info_buf),
            0 };
        size_t msg_len;
#endif /* !_WIN32 */

        cmsghdr_t* cmsg;
        size_t ip_hdr_len;
        struct icmp* reply;
        int reply_id, reply_seq;
        uint16_t reply_checksum, checksum;
        uint64_t delay;
        int error;

        // 接收icmp响应
#ifdef _WIN32
        error = WSARecvMsg(sockfd, &msg, &msg_len, NULL, NULL);
#else
        error = (int)recvmsg(sockfd, &msg, 0);
#endif
        delay = utime() - start_time;

        if (error < 0)
        {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
#else
            if (errno == EAGAIN)
            {
#endif
                if (delay > REQUEST_TIMEOUT)
                {
                    goto sleep_part;
                }
                else
                {
                    /* No data available yet, try to receive again. */
                    continue;
                }
            }
            else
            {
                psockerror("recvmsg");
                goto sleep_part;
            }
            }

#ifndef _WIN32
        msg_len = error;
#endif


        if (addr->ss_family == AF_INET6)
        {
            ip_hdr_len = 0;
            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg))
            {
                if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)
                {
                    struct in6_pktinfo* pktinfo = (void*)CMSG_DATA(cmsg);
                    memcpy(&msg_addr, &pktinfo->ipi6_addr, sizeof(struct in6_addr));
                }
            }
        }
        else
        {
            ip_hdr_len = ((*(uint8_t*)msg_buf) & 0x0F) * 4;
        }

        reply = (struct icmp*)(msg_buf + ip_hdr_len);
        reply_id = ntohs(reply->icmp_id);
        reply_seq = ntohs(reply->icmp_seq);

        if (!(addr->ss_family == AF_INET && reply->icmp_type == ICMP_ECHO_REPLY) &&
            !(addr->ss_family == AF_INET6 && reply->icmp_type == ICMP6_ECHO_REPLY))
        {
            continue;
        }

        if (reply_id != id || reply_seq != seq)
        {
            continue;
        }

        reply_checksum = reply->icmp_cksum;
        reply->icmp_cksum = 0;

        if (addr->ss_family == AF_INET6)
        {
            size_t size = sizeof(struct ip6_pseudo_hdr) + msg_len;
            struct icmp6_packet* reply_packet = calloc(1, size);

            if (reply_packet == NULL)
            {
                psockerror("malloc");
                return -1;
            }

            memcpy(&reply_packet->ip6_hdr.src, &((struct sockaddr_in6*)addr)->sin6_addr, sizeof(struct in6_addr));
            reply_packet->ip6_hdr.dst = msg_addr;
            reply_packet->ip6_hdr.plen = htons((uint16_t)msg_len);
            reply_packet->ip6_hdr.nxt = IPPROTO_ICMPV6;
            memcpy(&reply_packet->icmp, msg_buf + ip_hdr_len, msg_len - ip_hdr_len);

            checksum = compute_checksum((char*)reply_packet, size);
            free(reply_packet);
        }
        else
        {
            checksum = compute_checksum(msg_buf + ip_hdr_len, msg_len - ip_hdr_len);
        }

        printf("Received reply: seq=%d, time=%.3f ms%s\n",
            seq, (double)delay / 1000.0, reply_checksum != checksum ? " (bad checksum)" : "");
        return 0;

    sleep_part:
        {
            uint64_t sleep_time = delay - REQUEST_TIMEOUT;
            if (sleep_time > 500000) {
                printf("TimeOut for this time ping failed...\n");
                return -1;
            }
            usleep(sleep_time);
        }
        }
    printf("receive_icmp_reply timeout\n");
    return -1;
}


#ifdef _WIN32

// psockerror() is like perror() but for the Windows Sockets API.
static void psockerror(const char* s)
{
    char* message = NULL;
    DWORD format_flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
        | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK;
    DWORD result;

    result = FormatMessageA(format_flags,
        NULL,
        WSAGetLastError(),
        0,
        (char*)&message,
        0,
        NULL);

    if (result > 0)
    {
        printf("psocketerror:  %s: %s\n", s, message);
        LocalFree(message);
    }
    else
    {
        printf("psocketerror %s: Unknown error\n", s);
    }
}

#endif /* _WIN32 */


// Returns a timestamp with microsecond resolution.
static uint64_t utime(void)
{
#ifdef _WIN32
    LARGE_INTEGER count;
    LARGE_INTEGER frequency;
    if (QueryPerformanceCounter(&count) == 0 || QueryPerformanceFrequency(&frequency) == 0)
    {
        return 0;
    }
    return count.QuadPart * 1000000 / frequency.QuadPart;
#else
    struct timeval now;
    return gettimeofday(&now, NULL) != 0
        ? 0
        : now.tv_sec * 1000000 + now.tv_usec;
#endif
}