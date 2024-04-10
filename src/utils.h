#pragma once

#include "types.h"

#include <sys/time.h>

void
ft_strcpy(u8* dst, const u8* src);

struct timeval
time_diff(struct timeval a, struct timeval b);

double
to_ms(struct timeval t);
