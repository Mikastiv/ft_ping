#include "ping.h"
#include "types.h"
#include "utils.h"

#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <bits/types/struct_timeval.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static const char* progname = NULL;
PingData global_ping = { 0 };
Options options = { .no_dns = true };
Stats stats = { .min_rtt = FLT_MAX };

static void
print_stats(void);

static void
int_handler(int signal) {
    (void)signal;
    printf("\n");
    print_stats();
    exit(EXIT_SUCCESS);
}

static void
alarm_handler(int signal) {
    (void)signal;
    print_stats();
    exit(EXIT_SUCCESS);
}

static void
print_option(const char* name, const char* desc) {
    dprintf(STDERR_FILENO, "  %-20s%s\n", name, desc);
}

static void
usage(void) {
    dprintf(STDERR_FILENO, "usage: %s [options] <destination>\n\n", progname);
    print_option("<destination>", "dns name or ip address");
    dprintf(STDERR_FILENO, "options: \n");
    print_option("-h", "print help ane exit");
    print_option("-v", "verbose output");
    print_option("-n", "no dns name resolution");
    print_option("-m <ttl>", "outgoing packets time to live");
    print_option("-t <timeout>", "time in seconds before program exits");
    print_option("-W <waittime>", "time in seconds to wait for a packet");
}

static struct sockaddr_in
lookup_addr(const char* dst) {
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

static bool
dns_lookup(struct sockaddr_in addr, char* buffer, const u64 buf_size) {
    const i32 res = getnameinfo(
        (struct sockaddr*)&addr,
        sizeof(struct sockaddr_in),
        buffer,
        buf_size,
        NULL,
        0,
        NI_NAMEREQD
    );

    if (res != 0) {
        buffer[0] = 0;

        if (res == EAI_NONAME || res == EAI_AGAIN) return false;

        char tmp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, (const char*)&addr.sin_addr.s_addr, tmp, sizeof(tmp));

        const char* err = gai_strerror(res);
        dprintf(STDERR_FILENO, "%s: %s: %s\n", progname, tmp, err);
        exit(EXIT_FAILURE);
    }

    return true;
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
decode_msg(const u8* buffer, const u64 buffer_size, Packet* out, struct ip** ip) {
    *ip = (struct ip*)buffer;
    const u32 header_size = (*ip)->ip_hl << 2;

    Packet* pkt = (Packet*)(buffer + header_size);
    *out = *pkt;

    if (pkt->header.type != Icmp_EchoReply) {
        return false;
    }

    if (buffer_size < header_size + PKTSIZE) {
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
init_socket(const i32 fd, const i32 waittime) {
    if (options.ttl) {
        const i32 ttl = options.ttl_value;
        if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
            const char* err = strerror(errno);
            dprintf(STDERR_FILENO, "%s: %s\n", progname, err);
            exit(EXIT_FAILURE);
        }
    }

    const struct timeval tv = { .tv_sec = waittime };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
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

static void
dump_ip_hdr(struct ip* ip, struct sockaddr_in* dst) {
    u32 hlen = ip->ip_hl << 2;
    u8* cp = (unsigned char*)ip + sizeof(*ip);
    u32 j;

    printf("IP Hdr Dump:\n ");
    for (j = 0; j < sizeof(*ip); ++j)
        printf("%02x%s", *((unsigned char*)ip + j), (j % 2) ? " " : "");
    printf("\n");

    printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src\tDst\tData\n");
    printf(" %1x  %1x  %02x", ip->ip_v, ip->ip_hl, ip->ip_tos);
    printf(" %04x %04x", (ip->ip_len > 0x2000) ? ntohs(ip->ip_len) : ip->ip_len, ntohs(ip->ip_id));
    printf("   %1x %04x", (ntohs(ip->ip_off) & 0xe000) >> 13, ntohs(ip->ip_off) & 0x1fff);
    printf("  %02x  %02x %04x", ip->ip_ttl, ip->ip_p, ntohs(ip->ip_sum));
    printf(" %s ", inet_ntoa(*((struct in_addr*)&ip->ip_src)));
    printf(" %s ", inet_ntoa(*((struct in_addr*)&dst->sin_addr.s_addr)));
    while (hlen-- > sizeof(*ip)) printf("%02x", *cp++);

    printf("\n");
}

static void
dump_packet(struct ip* ip, IcmpEchoHeader hdr, struct sockaddr_in* dst) {
    dump_ip_hdr(ip, dst);
    printf(
        "ICMP: type %d, code %d, size %u, id 0x%04x, seq 0x%04x\n",
        hdr.type,
        hdr.code,
        ntohs(ip->ip_len) - (ip->ip_hl << 2),
        hdr.id,
        ntohs(hdr.seq)
    );
}

static bool
ping_timeout(struct timeval starttime, const u32 waittime) {
    struct timeval now;
    gettimeofday(&now, NULL);

    struct timeval diff = time_diff(now, starttime);
    if (diff.tv_sec >= waittime) {
        return true;
    } else {
        return false;
    }
}

static void
print_stats(void) {
    printf("--- %s ping statistics ---\n", global_ping.dst);
    printf(
        "%u packets transmitted, %u received, %u%% packet loss\n",
        stats.pkt_transmitted,
        stats.pkt_received,
        (u32)((float)(stats.pkt_transmitted - stats.pkt_received) / stats.pkt_transmitted * 100.0)
    );

    if (stats.pkt_received > 0) {
        const f64 total = stats.pkt_received + stats.pkt_duplicate;
        const f64 avg = stats.sum_rtt / total;
        const f64 variation = stats.sumsq_rtt / total - avg * avg;
        printf(
            "round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
            stats.min_rtt,
            avg,
            stats.max_rtt,
            sqrt(variation)
        );
    }
}

static void
send_ping(PingData* ping) {
    const pid_t pid = getpid();

    if (options.timeout) {
        alarm(options.timeout_value);
        signal(SIGALRM, alarm_handler);
    }

    init_socket(ping->fd, options.waittime_value);

    printf("PING %s (%s) %lu data bytes", ping->dst, ping->ip, sizeof(Packet) - MIN_ICMPSIZE);
    if (options.verbose) {
        printf(", id 0x%04x = %d", pid, pid);
    }
    printf("\n");

    u16 msg_count = 0;

    u64 pkt_duplicate = 0;
    u8 bits_duplicate[128] = { 0 };

    while (true) {
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

        if (ping_timeout(start, options.waittime_value)) continue;

        if (res == 0) {
            dprintf(STDERR_FILENO, "%s: socket closed\n", progname);
            exit(EXIT_FAILURE);
        }

        if (res < 0) {
            const char* err = strerror(errno);
            dprintf(STDERR_FILENO, "%s: %s\n", progname, err);
            exit(EXIT_FAILURE);
        }

        stats.pkt_transmitted++;

        u8 buffer[256];
        struct iovec iov = {
            .iov_base = buffer,
            .iov_len = sizeof(buffer),
        };

        struct sockaddr_in addr = ping->addr;
        struct msghdr rmsg = {
            .msg_name = &addr,
            .msg_namelen = sizeof(ping->addr),
            .msg_iov = &iov,
            .msg_iovlen = 1,
        };
        const ssize_t bytes = recvmsg(ping->fd, &rmsg, 0);

        struct timeval end;
        gettimeofday(&end, NULL);

        if (ping_timeout(start, options.waittime_value)) continue;

        if (bytes == 0) {
            dprintf(STDERR_FILENO, "%s: socket closed\n", progname);
            exit(EXIT_FAILURE);
        }

        if (bytes < 0) {
            const char* err = strerror(errno);
            dprintf(STDERR_FILENO, "%s: %s\n", progname, err);
            exit(EXIT_FAILURE);
        }

        Packet r_pkt;
        struct ip* ip;

        const bool receive_success = decode_msg(buffer, bytes, &r_pkt, &ip);

        char src_ip[INET_ADDRSTRLEN] = { 0 };
        char addrname[NI_MAXHOST] = { 0 };

        struct sockaddr_in* src_addr = rmsg.msg_name;
        inet_ntop(AF_INET, &src_addr->sin_addr.s_addr, src_ip, sizeof(src_ip));
        const bool dns_lookup_success = dns_lookup(*src_addr, addrname, sizeof(addrname));

        if (!receive_success) {
            switch (r_pkt.header.type) {
                case Icmp_TimeExceeded:
                    if (options.verbose) {
                        dump_packet(ip, pkt.header, (struct sockaddr_in*)&ping->addr);
                    }

                    printf("%lu bytes from ", bytes - (ip->ip_hl << 2));
                    if (!options.no_dns && dns_lookup_success) {
                        printf("%s (%s): ", addrname, src_ip);
                    } else {
                        printf("%s: ", src_ip);
                    }
                    printf("Time to live exceeded\n");
                    break;
                case Icmp_EchoReply:
                    if (options.verbose) {
                        dump_packet(ip, pkt.header, (struct sockaddr_in*)&ping->addr);
                    }

                    printf("checksum mismatch\n");
                    break;
                case Icmp_EchoRequest:
                    // from localhost
                    stats.pkt_transmitted--;
                    continue;
                default:
                    if (options.verbose) {
                        dump_packet(ip, pkt.header, (struct sockaddr_in*)&ping->addr);
                    }

                    printf("unknown error\n");
                    break;
            }

            goto next_ping;
        }

        const u16 packet_seq = ntohs(r_pkt.header.seq);
        const u64 bit_index = (packet_seq / 8) % sizeof(bits_duplicate);
        const u64 bit_mask = 1 << (packet_seq % 8);

        bool is_dup;
        if (bits_duplicate[bit_index] & bit_mask) {
            pkt_duplicate++;
            is_dup = true;
        } else {
            stats.pkt_received++;
            is_dup = false;
        }
        bits_duplicate[bit_index] |= bit_mask;

        const f64 time = to_ms(time_diff(end, start));
        stats.sum_rtt += time;
        stats.sumsq_rtt += time * time;
        if (time > stats.max_rtt) stats.max_rtt = time;
        if (time < stats.min_rtt) stats.min_rtt = time;

        printf("%lu bytes from ", bytes - (ip->ip_hl << 2));

        if (!options.no_dns && dns_lookup_success) {
            printf("%s (%s): ", addrname, src_ip);
        } else {
            printf("%s: ", src_ip);
        }

        printf("icmp_seq=%u ttl=%u time=%.3lf ms", packet_seq, ip->ip_ttl, time);
        if (is_dup) {
            printf(" (DUP!)");
        }
        printf("\n");

    next_ping:
        usleep(1000 * 1000);
    }

    print_stats();
}

static void
invalid_argument(const char* arg) {
    dprintf(STDERR_FILENO, "%s: invalid argument: '%s'\n", progname, arg);
}

static bool
is_valid_ttl(const i32 value) {
    return value > 0 && value < 256;
}

static bool
is_greater_than_zero(const i32 value) {
    return value > 0;
}

static i32
get_flag_value(
    const i32 argc,
    const char* const* argv,
    const i32 index,
    const char* name,
    bool (*is_valid)(const i32)
) {
    i32 result = -1;

    if (index + 1 >= argc) {
        usage();
        exit(EXIT_FAILURE);
    }

    result = atoi(argv[index + 1]);
    if (!is_valid(result)) {
        dprintf(STDERR_FILENO, "%s: invalid %s value: '%d'\n", progname, name, result);
        exit(EXIT_FAILURE);
    }

    return result;
}

static Options
parse_options(const i32 argc, const char* const* argv) {
    if (argc < 2) {
        usage();
        exit(EXIT_FAILURE);
    }

    Options out = { 0 };

    bool next_arg = false;

    for (i32 i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (argv[i][1] == 0 || argv[i][2] != 0) {
                invalid_argument(argv[i]);
                exit(EXIT_FAILURE);
            }

            switch (argv[i][1]) {
                case 'v':
                    out.verbose = true;
                    break;
                case 'h':
                    out.help = true;
                    break;
                case 'n':
                    out.no_dns = true;
                    break;
                case 'm': {
                    out.ttl = true;
                    out.ttl_value = get_flag_value(argc, argv, i, "ttl", &is_valid_ttl);
                    next_arg = true;
                    goto next;
                } break;
                case 't': {
                    out.timeout = true;
                    out.timeout_value =
                        get_flag_value(argc, argv, i, "timeout", &is_greater_than_zero);
                    next_arg = true;
                    goto next;
                } break;
                case 'W': {
                    out.waittime_value =
                        get_flag_value(argc, argv, i, "wait time", &is_greater_than_zero);
                    next_arg = true;
                    goto next;
                } break;
                default:
                    dprintf(STDERR_FILENO, "%s: invalid flag: '%s'\n", progname, argv[i]);
                    exit(EXIT_FAILURE);
                    break;
            }
        } else if (out.dst != NULL) {
            usage();
            exit(EXIT_FAILURE);
        } else {
            out.dst = argv[i];
        }

    next:
        if (next_arg) {
            i++;
        }
        next_arg = false;
    }

    if (out.dst == NULL) {
        dprintf(STDERR_FILENO, "%s: usage error: destination address required\n", progname);
        exit(EXIT_FAILURE);
    }

    return out;
}

int
main(int argc, const char* const* argv) {
    progname = argc > 0 ? argv[0] : "ft_ping";
    options = parse_options(argc, argv);

    if (options.help) {
        usage();
        exit(EXIT_SUCCESS);
    }

    const bool is_root = getuid() == 0;

    if (options.waittime_value == 0) {
        options.waittime_value = 5;
    }

    global_ping.dst = options.dst;
    global_ping.addr = lookup_addr(global_ping.dst);
    inet_ntop(AF_INET, &global_ping.addr.sin_addr.s_addr, global_ping.ip, INET_ADDRSTRLEN);
    dns_lookup(global_ping.addr, global_ping.host, sizeof(global_ping.host));

    global_ping.fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (global_ping.fd < 0) {
        if (!is_root && (errno == EPERM || errno == EACCES)) {
            dprintf(STDERR_FILENO, "%s: lacking priviledge for icmp socket\n", progname);
        } else {
            const char* err = strerror(errno);
            dprintf(STDERR_FILENO, "%s: %s\n", progname, err);
        }
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, int_handler);

    send_ping(&global_ping);

    close(global_ping.fd);
}
