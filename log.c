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
		loglevel = U_LOG_INFO;
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
		_ = snprintf(buf, sizeof(buf), "%s:%s:%d %s\n",
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

void hexdump(void *addr, size_t len)
{
	size_t i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf ("  %s\n", buff);

			// Output the offset.
			printf ("  %04zx ", i);
		}

		// Now the hex code for the specific character.
		printf (" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf ("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf ("  %s\n", buff);
}
