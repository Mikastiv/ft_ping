#pragma once

#include "types.h"

#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>

#define PKTSIZE 64
#define MIN_ICMPSIZE 8

typedef enum {
    Icmp_EchoReply = 0,
    Icmp_EchoRequest = 8,
    Icmp_TimeExceeded = 11,
} IcmpType;

typedef struct {
    u8 type;
    u8 code;
    u16 cksum;
    u16 id;
    u16 seq;
} IcmpEchoHeader;

typedef struct {
    IcmpEchoHeader header;
    u8 msg[PKTSIZE - sizeof(IcmpEchoHeader)];
} Packet;

typedef struct {
    i32 fd;
    const char* dst;
    char ip[INET_ADDRSTRLEN];
    char host[NI_MAXHOST];
    struct sockaddr_in addr;
    bool is_ip_format;
} PingData;

typedef struct {
    const char* dst;
    bool help;
    bool verbose;
    bool no_dns;
    bool ttl;
    bool timeout;
    i32 ttl_value;
    i32 timeout_value;
    i32 waittime_value;
} Options;
