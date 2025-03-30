#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#ifdef __APPLE__
#include <sys/disk.h>
#endif

#ifdef __linux__
#include <linux/fs.h>
#endif

#include "utils.h"

static int blockdevice_size(int fd, off_t *size_ptr)
#if defined(__APPLE__)
{
	uint32_t size;
	uint64_t count;

	if (ioctl(fd, DKIOCGETBLOCKSIZE, &size) < 0) {
		u_log_errno("getting device block size failed");
		return -1;
	}

	if (ioctl(fd, DKIOCGETBLOCKCOUNT, &count) < 0) {
		u_log_errno("getting device block count failed");
		return -1;
	}

	*size_ptr = (off_t)(size * count);
	return 0;
}
#elif defined(__linux__)
{
	uint64_t tmp;

	if (ioctl(fd, BLKGETSIZE64, &tmp) < 0) {
		u_log_errno("getting block device size failed");
		return -1;
	}

	*size_ptr = (off_t)tmp;
	return 0;
}
#else
#error "blockdevice_size not implemented for target"
#endif

must_check int readall(int fd, uint8_t *buf, size_t len)
{
	size_t read_bytes = 0;

	while (read_bytes < len) {
		ssize_t ret;

		ret = read(fd, &buf[read_bytes], len - read_bytes);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			u_log_errno("read failed");
			return -1;
		} else if (ret == 0) {
			u_log(ERR, "short read, expected %zu, got %zu", len, read_bytes);
			return -1;
		}

		read_bytes += ret;
	}

	return 0;
}

must_check int preadall(int fd, uint8_t *buf, size_t len, off_t offset)
{
	size_t read_bytes = 0;

	while (read_bytes < len) {
		ssize_t ret;

		ret = pread(fd, &buf[read_bytes], len - read_bytes, offset);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			u_log_errno("read failed");
			return -1;
		} else if (ret == 0) {
			u_log(ERR, "short read, expected %zu, got %zu", len, read_bytes);
			return -1;
		}

		read_bytes += ret;
		offset += ret;
	}

	return 0;
}

must_check int writeall(int fd, const uint8_t *buf, size_t len)
{
	size_t written_bytes = 0;

	while (written_bytes < len) {
		ssize_t ret;

		ret = write(fd, &buf[written_bytes], len - written_bytes);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			u_log_errno("write failed");
			return -1;
		}

		u_assert(ret != 0);

		written_bytes += ret;
	}

	return 0;
}

must_check int pwriteall(int fd, const uint8_t *buf, size_t len, off_t offset)
{
	size_t written_bytes = 0;

	while (written_bytes < len) {
		ssize_t ret;

		ret = pwrite(fd, &buf[written_bytes], len - written_bytes, offset);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			u_log_errno("write failed");
			return -1;
		}

		u_assert(ret != 0);

		written_bytes += ret;
		offset += ret;
	}

	return 0;
}

int fd_size(int fd, off_t *size_out)
{
	u_assert(fd >= 0);
	u_assert(size_out);

	struct stat s;

	if (fstat(fd, &s) < 0) {
		u_log_errno("stat failed");
		return -1;
	}

	if (S_ISREG(s.st_mode)) {
		*size_out = s.st_size;
	} else if (S_ISBLK(s.st_mode)) {
		return blockdevice_size(fd, size_out);
	} else {
		u_log(ERR, "unsupported file type: 0%o", s.st_mode & S_IFMT);
		return -1;
	}

	return 0;
}

void *slurp_file(const char *path, bool text, off_t *size_out)
{
	int fd;
	void *ret = NULL;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		u_log_errno("opening '%s' failed", path);
		return NULL;
	}

	off_t size;
	if (fd_size(fd, &size) < 0) {
		u_log(ERR, "getting file size of '%s' failed", path);
		goto out_fd;
	}

	void *buf;
	buf = malloc(text ? size + 1 : size);
	if (!buf) {
		u_log_errno("could not allocate %zu bytes", (size_t)size);
		goto out_fd;
	}

	if (readall(fd, buf, size) < 0) {
		u_log(ERR, "reading file '%s' failed", path);
		goto out_buf;
	}

	if (text)
		((char*)buf)[size] = 0;

	if (size_out)
		*size_out = size;

	ret = buf;

out_buf:
	if (ret == NULL)
		free(buf);

out_fd:
	close(fd);

	return ret;
}

time_t time_monotonic(void)
{
	struct timespec ts;

	u_assert_se(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

	return ts.tv_sec;
}

static int16_t nibble(char c)
{
	if ('0' <= c && c <= '9')
		return c - '0';

	c |= 0x20;

	if ('a' <= c && c <= 'f')
		return c - 'a' + 10;

	return -1;
}

int parse_hex(uint8_t *out, const char *in)
{
	for (size_t i = 0; in[i]; i++) {
		int16_t n = nibble(in[i]);
		if (n < 0) {
			u_log(ERR, "invalid hex nibble '%c'", in[i]);
			return -1;
		}

		if (i % 2 == 0) {
			*out = (uint8_t)n << 4;
		} else {
			*out |= (uint8_t)n;
			out++;
		}
	}

	return 0;
}

void chomp(char *s)
{
	char *p, *q;

	q = NULL;
	p = s;

	while (*p) {
		if (*p == '\r' || *p == '\n') {
			q = p;

			while (*p == '\r' || *p == '\n')
				p++;
		} else {
			p++;
		}
	}

	if (q)
		*q = 0;
}
