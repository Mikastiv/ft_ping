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
    double out = us;
    return out / 1000.0f;
}
