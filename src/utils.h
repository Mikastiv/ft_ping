#pragma once

#include "types.h"

#include <stdbool.h>
#include <sys/time.h>

void
ft_strcpy(u8* dst, const u8* src);

struct timeval
time_diff(struct timeval a, struct timeval b);

double
to_ms(struct timeval t);

bool
is_digit(const u8 c);

bool
is_ipv4(const u8* str);
