#include "ping.h"
#include "types.h"
#include "utils.h"

#include <arpa/inet.h>
#include <bits/types/struct_iovec.h>
#include <bits/types/struct_timeval.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static const int TTL = 115;
static const struct timeval TIMEOUT = { .tv_sec = 2 };

static const char* progname = NULL;

static volatile sig_atomic_t pingloop = 1;

static void
int_handler(int signal) {
    (void)signal;
    pingloop = 0;
    printf("\n");
}

static void
usage(void) {
    dprintf(STDERR_FILENO, "usage: %s [options] <destination>\n", progname);
}

static bool
is_ipv4(const u8* str) {
    u32 dots = 0;
    for (u32 i = 0; str[i]; i++) {
        if (!isdigit(str[i]) && str[i] != '.') {
            return false;
        }
        if (str[i] == '.') {
            dots += 1;
        }
    }

    if (dots > 3) {
        return false;
    }

    return true;
}

static struct sockaddr_in
lookup_addr(const u8* dst) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_RAW,
        .ai_protocol = IPPROTO_ICMP,
    };
    struct addrinfo* result = NULL;

    const i32 res = getaddrinfo((const char*)dst, NULL, &hints, &result);
    if (res != 0) {
        const char* err = gai_strerror(res);
        dprintf(STDERR_FILENO, "%s: %s: %s\n", progname, dst, err);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in out = *(struct sockaddr_in*)result->ai_addr;
    freeaddrinfo(result);

    return out;
}

static void
lookup_hostname(PingData* ping) {
    const size_t addrlen = sizeof(struct sockaddr_in);
    const i32 res = getnameinfo(
        (struct sockaddr*)&ping->addr,
        addrlen,
        (char*)ping->host,
        sizeof(ping->host),
        NULL,
        0,
        NI_NAMEREQD
    );

    if (res != 0) {
        if (res == EAI_NONAME) return;
        const char* err = gai_strerror(res);
        dprintf(STDERR_FILENO, "%s: %s: %s\n", progname, ping->dst, err);
        exit(EXIT_FAILURE);
    }
}

static u16
checksum(const void* data, u64 len) {
    u32 sum = 0;

    const u16* ptr;
    for (ptr = data; len > 1; len -= 2) {
        sum += *ptr;
        ptr++;
    }

    if (len == 1) {
        sum += *(const u8*)ptr;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

static bool
decode_msg(const u8* buffer, const u64 buffer_size, Packet* out) {
    const struct ip* ip_header = (struct ip*)buffer;
    const u64 header_size = ip_header->ip_hl << 2;
    if (buffer_size < header_size + PKTSIZE) {
        return false;
    }

    Packet* pkt = (Packet*)(buffer + header_size);
    *out = *pkt;

    if (pkt->header.type != Icmp_EchoReply) {
        return false;
    }

    const u16 cksum = pkt->header.cksum;
    pkt->header.cksum = 0;
    pkt->header.cksum = checksum(pkt, buffer_size - header_size);
    if (cksum != pkt->header.cksum) {
        return false;
    }
    return true;
}

static void
init_socket(const i32 fd) {
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, &TTL, sizeof(TTL)) != 0) {
        const char* err = strerror(errno);
        dprintf(STDERR_FILENO, "%s: %s\n", progname, err);
        exit(EXIT_FAILURE);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &TIMEOUT, sizeof(TIMEOUT)) != 0) {
        const char* err = strerror(errno);
        dprintf(STDERR_FILENO, "%s: %s\n", progname, err);
        exit(EXIT_FAILURE);
    }
}

static Packet
init_packet(const pid_t pid, const u16 seq) {
    Packet pkt = {
            .header = {
                .type = Icmp_EchoRequest,
                .code = 0,
                .id = pid,
                .seq = htons(seq),
            },
        };
    for (u32 i = 0; i < sizeof(pkt.msg); i++) {
        pkt.msg[i] = i + '0';
    }

    pkt.header.cksum = checksum(&pkt, sizeof(pkt));

    return pkt;
}

static const u8*
pretty_hostname(const PingData* ping, u8* buffer, const u64 len) {
    const u8* hostname;
    if (ping->is_ip_format) {
        hostname = ping->ip;
    } else {
        hostname = ping->host;
        snprintf((char*)buffer, len, " (%s)", ping->ip);
    }

    return hostname;
}

static void
send_ping(PingData* ping) {
    const pid_t pid = getpid();

    init_socket(ping->fd);

    u8 host_ip[INET_ADDRSTRLEN + 8] = { 0 };
    const u8* hostname = pretty_hostname(ping, host_ip, sizeof(host_ip));

    u16 msg_count = 0;
    u16 pkt_transmitted = 0;
    u16 pkt_received = 0;

    struct timeval begin_timestamp;
    struct timeval end_timestamp;
    gettimeofday(&begin_timestamp, NULL);

    while (pingloop) {
        Packet pkt = init_packet(pid, msg_count++);

        struct timeval start;
        gettimeofday(&start, NULL);

        const i64 res = sendto(
            ping->fd,
            &pkt,
            sizeof(pkt),
            0,
            (struct sockaddr*)&ping->addr,
            sizeof(struct sockaddr)
        );

        if (res < 0) {
            const char* err = strerror(errno);
            dprintf(STDERR_FILENO, "%s: %s\n", progname, err);
            exit(EXIT_FAILURE);
        }

        pkt_transmitted++;

        u8 buffer[256];
        struct iovec iov = {
            .iov_base = buffer,
            .iov_len = sizeof(buffer),
        };

        struct msghdr rmsg = {
            .msg_name = &ping->addr,
            .msg_namelen = sizeof(ping->addr),
            .msg_iov = &iov,
            .msg_iovlen = 1,
        };
        const i64 bytes = recvmsg(ping->fd, &rmsg, 0);

        struct timeval end;
        gettimeofday(&end, NULL);

        if (bytes < 0) {
            const char* err = strerror(errno);
            dprintf(STDERR_FILENO, "%s: %s\n", progname, err);
            exit(EXIT_FAILURE);
        }

        Packet r_pkt;
        if (!decode_msg(buffer, bytes, &r_pkt)) {
            printf("invalid packet\n");
            continue;
        }

        pkt_received++;

        const double time = to_ms(time_diff(end, start));
        printf(
            "%lu bytes from %s%s: icmp_seq=%u ttl=%u time=%.2lf ms\n",
            sizeof(Packet),
            hostname,
            host_ip,
            ntohs(r_pkt.header.seq),
            TTL,
            time
        );

        gettimeofday(&end_timestamp, NULL);

        usleep(1000 * 1000);
    }

    double total_time = to_ms(time_diff(end_timestamp, begin_timestamp));

    printf("--- %s ping statistics ---\n", ping->dst);
    printf(
        "%u packets transmitted, %u received, %u%% packet loss, time %.0lfms\n",
        pkt_transmitted,
        pkt_received,
        1 - (u16)((float)pkt_received / pkt_transmitted),
        total_time
    );
}

int
main(int argc, char* const* argv) {
    progname = argc > 0 ? argv[0] : "ft_ping";
    if (argc < 2) {
        usage();
        exit(EXIT_FAILURE);
    }

    const bool is_root = getuid() == 0;

    PingData ping = {
        .dst = (const u8*)argv[argc - 1],
    };

    ping.is_ip_format = is_ipv4(ping.dst);

    ping.addr = lookup_addr(ping.dst);
    inet_ntop(AF_INET, &ping.addr.sin_addr.s_addr, (char*)ping.ip, INET_ADDRSTRLEN);
    if (!ping.is_ip_format) {
        lookup_hostname(&ping);
    } else {
        ft_strcpy(ping.host, ping.ip);
    }

    if (is_root) {
        ping.fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    } else {
        ping.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    }

    if (ping.fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            dprintf(STDERR_FILENO, "%s: lacking priviledge for icmp socket\n", progname);
        } else {
            const char* err = strerror(errno);
            dprintf(STDERR_FILENO, "%s: %s\n", progname, err);
        }
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, int_handler);

    printf(
        "PING %s (%s) %lu(%lu) bytes of data.\n",
        ping.dst,
        ping.ip,
        sizeof(Packet) - MIN_ICMPSIZE,
        sizeof(Packet) + sizeof(struct ip) // check for non-root if ip header is present
    );

    send_ping(&ping);

    close(ping.fd);
}

// TODO: check for dupes
// TODO: check 127.0.0.1
