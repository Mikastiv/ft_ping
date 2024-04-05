#include "types.h"

typedef enum {
    Icmp_EchoReply = 0,
    Icmp_EchoRequest = 8,
} IcmpType;

typedef struct {
    u8 type;
    u8 code;
    u16 cksum;
    u16 id;
    u16 seq;
} IcmpEchoHeader;
