#pragma once

#include "types.h"

#include <stdbool.h>
#include <sys/time.h>

void
ft_strcpy(char* dst, const char* src);

struct timeval
time_diff(struct timeval a, struct timeval b);

double
to_ms(struct timeval t);

bool
is_digit(const char c);

bool
is_ipv4(const char* str);
