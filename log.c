#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

#include "utils.h"
#include "log.h"

static enum u_loglevel loglevel = U_LOG_INFO;
static bool is_tty;

void u_log_init(void)
{
	const char *s;

	is_tty = isatty(STDERR_FILENO);

	s = getenv("LOGLEVEL");
	if (!s)
		return;

	if (streq(s, "debug"))
		loglevel = U_LOG_DEBUG;
	else if (streq(s, "info"))
		loglevel = U_LOG_INFO;
	else if (streq(s, "warn") || streq(s, "warning"))
		loglevel = U_LOG_WARN;
	else if (streq(s, "err") || streq(s, "error"))
		loglevel = U_LOG_ERR;
	else
		u_log(WARN, "unknown loglevel '%s'", s);
}

#define COLOR_START "\x1b[38;5;%dm"
#define COLOR_END "\x1b[0m"

#define COLOR_GREEN 40
#define COLOR_BLUE 75
#define COLOR_RED 196
#define COLOR_ORANGE 202

bool check_loglevel(enum u_loglevel level)
{
	if (u_likely(level > loglevel))
		return false;

	return true;
}

void _u_log(enum u_loglevel level, const char *path, const char *func, int line, const char *format, ...)
{
	int _;

	if (check_loglevel(level) == false)
		return;

	const char *file = strrchr(path, '/');
	if (file)
		file = file + 1;
	else
		file = path;

	char buf[128];
	if (is_tty) {
		static const int color_map[] = {
			[U_LOG_ERR] = COLOR_RED,
			[U_LOG_WARN] = COLOR_ORANGE,
			[U_LOG_INFO] = COLOR_GREEN,
			[U_LOG_DEBUG] = COLOR_BLUE
		};

		_ = snprintf(buf, sizeof(buf), COLOR_START "%s:%s:%d\t%s" COLOR_END "\n",
		             color_map[level],
		             file, func, line,
		             format);
	} else {
		static const char *level_map[] = {
			[U_LOG_ERR] = "ERR",
			[U_LOG_WARN] = "WRN",
			[U_LOG_INFO] = "INF",
			[U_LOG_DEBUG] = "DBG"
		};

		_ = snprintf(buf, sizeof(buf), "%s %s:%s:%d %s\n",
		             level_map[level],
		             file, func, line,
		             format);
	}

	if (_ < 0) {
		fputs("error formatting log message", stderr);
		return;
	}

	va_list args;
	va_start(args, format);
	vfprintf(stderr, buf, args);
	va_end(args);
}
