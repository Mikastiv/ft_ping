#include "utils.h"

void
ft_strcpy(u8* dst, const u8* src) {
    u64 i = 0;
    while (src[i]) {
        dst[i] = src[i];
        i++;
    }
}

struct timeval
time_diff(struct timeval a, struct timeval b) {
    struct timeval out = a;

    out.tv_usec -= b.tv_usec;
    if (out.tv_usec < 0) {
        out.tv_sec--;
        out.tv_usec += 1000000;
    }
    out.tv_sec -= b.tv_sec;

    return out;
}

double
to_ms(struct timeval t) {
    const u64 us = t.tv_usec + t.tv_sec * 1000000;
    const double out = us;
    return out / 1000.0f;
}

bool
is_digit(const u8 c) {
    return c >= '0' && c <= '9';
}

bool
is_ipv4(const u8* str) {
    u32 dots = 0;
    for (u32 i = 0; str[i]; i++) {
        if (!is_digit(str[i]) && str[i] != '.') {
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
