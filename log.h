#pragma once

#include <stdbool.h>
#include <errno.h>

enum u_loglevel {
	U_LOG_ERR,
	U_LOG_WARN,
	U_LOG_INFO,
	U_LOG_DEBUG,
};

void u_log_init(void);

__attribute__((format(printf, 5, 6)))
void _u_log(enum u_loglevel level, const char *path, const char *func, int line, const char *format, ...);

#define u_log(level, format, ...) _u_log(U_LOG_ ## level, __FILE__, __func__, __LINE__, format, ##__VA_ARGS__)
#define u_log_errno(format, ...) do { \
	if (format) \
		u_log(ERR, format ": %s", ##__VA_ARGS__, strerror(errno)); \
	else \
		u_log(ERR, "%s", strerror(errno)); \
} while (0)

bool check_loglevel(enum u_loglevel level);
