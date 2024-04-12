#include "utils.h"

void
ft_strcpy(char* dst, const char* src) {
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
is_digit(const char c) {
    return c >= '0' && c <= '9';
}

bool
is_space(const char c) {
    return (c >= '\t' && c <= '\r') || c == ' ';
}

bool
is_ipv4(const char* str) {
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

static bool
wrapped(int32_t n, int32_t old, int32_t sign) {
    if (sign > 0) {
        if (n < old)
            return (true);
        else
            return (false);
    } else {
        if (n > old)
            return (true);
        else
            return (false);
    }
}

i32
ft_atoi(const char* str) {
    i32 result;
    i32 sign;
    i64 old;

    sign = 1;
    result = 0;
    while (is_space(*str)) ++str;
    if (*str == '-') {
        sign = -1;
        ++str;
    } else if (*str == '+')
        ++str;
    while (is_digit(*str)) {
        old = result;
        result = (result * 10) + ((*str - '0') * sign);
        if (wrapped(result, old, sign)) return (-1);
        str++;
    }
    return (result);
}
