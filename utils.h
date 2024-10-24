#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "log.h"

#define u_nop() do {} while (0)

#ifdef __GNUC__
#define u_likely(expr) (__builtin_expect(!!(expr), 1))
#define u_unlikely(expr) (__builtin_expect(!!(expr), 0))
#else
#define u_likely(expr) (expr)
#define u_unlikely(expr) (expr)
#endif

#define u_assert_se(expr) do { \
	if (u_unlikely(!(expr))) { \
		u_log(ERR, "assertion failed: %s", #expr); \
		abort(); \
	} \
} while (0)

#ifdef NDEBUG
#define u_assert(expr) u_nop()
#else
#define u_assert(expr) u_assert_se(expr)
#endif

#define u_assert_not_reached() do { \
	u_log(ERR, "reached location marked as unreachable"); \
	abort(); \
} while (0)

#define u_build_assert(expr) ((void)sizeof(char[1 - 2*!(expr)]))

#define u_notnull(expr, action) do { \
	if (u_unlikely((expr) == NULL)) { \
		u_log(ERR, "%s is NULL", #expr); \
		action; \
	} \
} while (0)

#define streq(a, b) (strcmp((a), (b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define startswith(a, b) (strneq((a), (b), strlen((b))))

static inline uint32_t rol32(uint32_t x, size_t n)
{
	n = n % 32;
	if (!n)
		return x;

	return (x << n) | (x >> (32 - n));
}

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define ARRAY_SIZE(x) (sizeof((x))/sizeof(*(x)))

#ifndef TESTING
#define static_testexpose static
#else
#define static_testexpose
#endif

#define must_check __attribute__ ((warn_unused_result))

static inline uint64_t unp64le(const uint8_t *data) {
	return ((uint64_t)data[7] << 56) |
	       ((uint64_t)data[6] << 48) |
	       ((uint64_t)data[5] << 40) |
	       ((uint64_t)data[4] << 32) |
	       ((uint64_t)data[3] << 24) |
	       ((uint64_t)data[2] << 16) |
	       ((uint64_t)data[1] <<  8) |
	       ((uint64_t)data[0] <<  0);
}

static inline uint32_t unp32le(const uint8_t *data)
{
	return ((uint32_t)data[3] << 24) |
	       ((uint32_t)data[2] << 16) |
	       ((uint32_t)data[1] <<  8) |
	       ((uint32_t)data[0] <<  0);
}

static inline void p32le(uint8_t *data, uint32_t v)
{
	data[0] = (v >>  0) & 0xff;
	data[1] = (v >>  8) & 0xff;
	data[2] = (v >> 16) & 0xff;
	data[3] = (v >> 24) & 0xff;
}

must_check int readall(int fd, uint8_t *buf, size_t len);
must_check int preadall(int fd, uint8_t *buf, size_t len, off_t offset);
must_check int writeall(int fd, const uint8_t *buf, size_t len);
must_check int pwriteall(int fd, const uint8_t *buf, size_t len, off_t offset);
void *slurp_file(const char *path, bool text, off_t *size_out);

#define checked(expr, action) do { \
	if ((expr) < 0) { \
		u_log(DEBUG, "checked statement failed"); \
		action; \
	} \
} while (0)

int fd_size(int fd, off_t *size_out);
time_t time_monotonic(void);

int parse_hex(uint8_t *out, const char *in);
void chomp(char *s);
