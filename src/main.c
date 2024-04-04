#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char* progname;

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

int
main(int argc, char* const* argv) {
    if (argc > 0) progname = argv[0];
    if (argc < 2) {
        usage();
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = 0;

    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_RAW,
        .ai_protocol = IPPROTO_ICMP,
    };
    struct addrinfo* result = NULL;

    int res = getaddrinfo(argv[1], NULL, &hints, &result);
    if (res != 0) {
        const char* err = gai_strerror(res);
        print_error("%s: %s\n", progname, err);
        exit(EXIT_FAILURE);
    }

    char host[NI_MAXHOST];

    res = getnameinfo(result->ai_addr, sizeof(struct sockaddr_in), host, sizeof(host), NULL, 0, NI_NAMEREQD);

    struct sockaddr_in addr = *(struct sockaddr_in*)result->ai_addr;
    char ip[NI_MAXSERV];
    const char* ip_presentable = inet_ntop(AF_INET, &addr.sin_addr.s_addr, ip, INET_ADDRSTRLEN);
    printf("host: %s\n", host);
    printf("ip: %s\n", ip_presentable);

    switch (inet_pton(AF_INET, argv[1], &dst.sin_addr.s_addr)) {
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
}
