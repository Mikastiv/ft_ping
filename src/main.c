#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define IPSIZE 16

static const char* progname;

typedef struct {
    const char* dst;
    char ip[IPSIZE];
    char host[NI_MAXHOST];
    struct sockaddr_in addr;
} PingData;

static void
print_error(const char* restrict fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vdprintf(STDERR_FILENO, fmt, args);
    va_end(args);
}

static void
usage(void) {
    print_error("usage: %s [options] <destination>\n", progname);
}

static bool
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

static struct sockaddr_in
lookup_addr(const char* dst) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_RAW,
        .ai_protocol = IPPROTO_ICMP,
    };
    struct addrinfo* result = NULL;

    const int res = getaddrinfo(dst, NULL, &hints, &result);
    if (res != 0) {
        const char* err = gai_strerror(res);
        print_error("%s: %s: %s\n", progname, dst, err);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in out = *(struct sockaddr_in*)result->ai_addr;
    freeaddrinfo(result);

    return out;
}

static void
lookup_hostname(PingData* ping) {
    const size_t addrlen = sizeof(struct sockaddr_in);
    const int res =
        getnameinfo((struct sockaddr*)&ping->addr, addrlen, ping->host, sizeof(ping->host), NULL, 0, NI_NAMEREQD);
    if (res != 0) {
        if (res == EAI_NONAME) return;
        const char* err = gai_strerror(res);
        print_error("%s: %s: %s\n", progname, ping->dst, err);
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
    if (!is_ipv4(ping.dst)) {
        lookup_hostname(&ping);
    }
    inet_ntop(AF_INET, &ping.addr.sin_addr.s_addr, ping.ip, INET_ADDRSTRLEN);

    printf("PING %s (%s)\n", ping.dst, ping.ip);
}
