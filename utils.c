#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "utils.h"

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

int pwriteall(int fd, const uint8_t *buf, size_t len, off_t offset)
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
		uint64_t tmp;
		if (ioctl(fd, BLKGETSIZE64, &tmp) < 0) {
			u_log_errno("getting block device size failed");
			return -1;
		}

		*size_out = (off_t)tmp;
	} else {
		u_log(ERR, "unsupported file type: 0%o", s.st_mode & S_IFMT);
		return -1;
	}

	return 0;
}

time_t time_monotonic(void)
{
	struct timespec ts;

	u_assert_se(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

	return ts.tv_sec;
}
