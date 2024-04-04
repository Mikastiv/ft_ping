#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char* progname;

typedef struct {
    const char* dst;
    char ip[32];
    char host[NI_MAXHOST];
    struct sockaddr_in addr;
} PingData;

void
print_error(const char* restrict fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vdprintf(STDERR_FILENO, fmt, args);
    va_end(args);
}

void
usage() {
    print_error("usage: %s [options] <destination>\n", progname);
}

bool
is_ipv4(const char* str) {
    size_t dots = 0;
    for (size_t i = 0; str[i]; i++) {
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

struct sockaddr_in
lookup_addr(const char* dst) {
    struct sockaddr_in out;

    if (is_ipv4(dst)) {
        switch (inet_pton(AF_INET, dst, &out.sin_addr.s_addr)) {
            case 0: {
                print_error("not in presentation format\n");
                exit(EXIT_FAILURE);
                break;
            }
            case -1: {
                const char* err = strerror(errno);
                print_error("%s: %s\n", progname, err);
                exit(EXIT_FAILURE);
                break;
            }
            default:
                break;
        }
    } else {
        struct addrinfo hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_RAW,
            .ai_protocol = IPPROTO_ICMP,
        };
        struct addrinfo* result = NULL;

        const int res = getaddrinfo(dst, NULL, &hints, &result);
        if (res != 0) {
            const char* err = gai_strerror(res);
            print_error("%s: %s\n", progname, err);
            exit(EXIT_FAILURE);
        }

        out = *(struct sockaddr_in*)result->ai_addr;
        freeaddrinfo(result);
    }

    return out;
}

void
lookup_hostname(struct sockaddr_in addr, char* buffer, const size_t buffer_size) {
    const size_t addrlen = sizeof(struct sockaddr_in);
    const int res = getnameinfo((struct sockaddr*)&addr, addrlen, buffer, buffer_size, NULL, 0, NI_NAMEREQD);
    if (res != 0) {
        const char* err = gai_strerror(res);
        print_error("%s: %s\n", progname, err);
        exit(EXIT_FAILURE);
    }
}

int
main(int argc, char* const* argv) {
    progname = argc > 0 ? argv[0] : "ft_ping";
    if (argc < 2) {
        usage();
        exit(EXIT_FAILURE);
    }

    PingData ping = {
        .dst = argv[argc - 1],
    };

    ping.addr = lookup_addr(ping.dst);
    lookup_hostname(ping.addr, ping.host, sizeof(ping.host));
    inet_ntop(AF_INET, &ping.addr.sin_addr.s_addr, ping.ip, INET_ADDRSTRLEN);

    printf("host: %s\n", ping.host);
    printf("ip: %s\n", ping.ip);
}
