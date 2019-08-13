#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include "pattern.h"
#include "utils.h"

#define MAXIO (256ull*1024*1024)

uint8_t data[MAXIO];
uint8_t data_null[MAXIO];

static void stamp(struct timespec *prev, const char *msg)
{
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);

	double delta =
		(now.tv_sec - prev->tv_sec) +
		((double)now.tv_nsec - prev->tv_nsec) / 10e9;

	u_log(INFO, "timestamp '%s': %f", msg, delta);
}

int pwriteall(int fd, uint8_t *buf, size_t len, off_t offset)
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

static int io_cmp(const void *a, const void *b)
{
	const struct io_op *op_a = (const struct io_op*) a;
	const struct io_op *op_b = (const struct io_op*) b;

	if (op_a->id < op_b->id)
		return -1;

	if (op_a->id > op_b->id)
		return 1;

	if (op_a->start < op_b->start)
		return -1;
	if (op_a->start > op_b->start)
		return 1;

	return 0;
}

static int io_cmp_id(const void *a, const void *b)
{
	const struct io_op *op_a = (const struct io_op*) a;
	const struct io_op *op_b = (const struct io_op*) b;

	if (op_a->id < op_b->id)
		return -1;

	if (op_a->id > op_b->id)
		return 1;

	return 0;
}

static struct io_op *sorted;

static size_t get_id(int src, int id)
{
	struct io_op key = {
		.id = id
	};

	struct io_op *op;
	op = bsearch(&key, sorted, ARRAY_SIZE(io_pattern), sizeof(struct io_op), io_cmp_id);

	int ret;
	ret = preadall(src, data, op->len, op->start);
	if (ret < 0) {
		u_log(ERR, "read failed at offset %zj", (uintmax_t)op->start);
		return -1;
	}

	return 0;
}

static int random_test(int src, int dst, struct timespec *start)
{
	int last_id = -1;
	int ret;

	clock_gettime(CLOCK_REALTIME, start);
	for (size_t i = 0; i < ARRAY_SIZE(io_pattern); i++) {
		struct io_op *op = &io_pattern[i];

		ret = preadall(src, data, op->len, op->start);
		if (ret < 0) {
			u_log(ERR, "read failed at offset %zj", (uintmax_t)op->start);
			return -1;
		}

		struct io_op key = {
			.id = op->id
		};

		// TODO ZERO

		struct io_op *dstop;
		dstop = bsearch(&key, sorted, ARRAY_SIZE(io_pattern), sizeof(struct io_op), io_cmp_id);
		u_assert(dstop);

		if (dstop->start == 0xaffed00f && dstop->len == 0xdeadbeef) {
			u_log(DEBUG, "skipping id %d at %ju, already done", op->id, (uintmax_t)op->start);
			continue;
		}

		while (dstop >= sorted && dstop->id == op->id)
			dstop--;

		dstop++;

		while (dstop->id == op->id) {
			u_log(DEBUG, "replicating id %d to %ju", op->id, (uintmax_t)dstop->start);

			ret = pwriteall(dst, (op->id == IO_ZERO_ID) ? data_null : data, dstop->len, dstop->start);
			if (ret < 0) {
				u_log(ERR, "write failed");
				return -1;
			}

			dstop->start = 0xaffed00f;
			dstop->len = 0xdeadbeef;

			dstop++;
		}
	}

	return 0;
}

static int seq_test(int src, int dst, struct timespec *start)
{
	int last_id = -1;
	int ret;

	clock_gettime(CLOCK_REALTIME, start);
	for (size_t i = 0; i < ARRAY_SIZE(io_pattern); i++) {
		struct io_op *op = &io_pattern[i];

		if (last_id != op->id) {
			if (get_id(src, op->id) < 0)
				return -1;
		}

		last_id = op->id;

		ret = pwriteall(dst, (op->id == IO_ZERO_ID) ? data_null : data, op->len, op->start);
		if (ret < 0) {
			u_log(ERR, "write failed at offset %zj", (uintmax_t)op->start);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: %s source target pattern\n", argv[0]);
		return EXIT_FAILURE;
	}

	u_log_init();

	sorted = malloc(sizeof(io_pattern));
	u_assert(sorted);

	memcpy(sorted, io_pattern, sizeof(io_pattern));
	qsort(sorted, ARRAY_SIZE(io_pattern), sizeof(struct io_op), io_cmp);

	int source_fd;
	source_fd = open(argv[1], O_RDONLY);
	if (source_fd < 0) {
		u_log_errno("opening source failed");
		return EXIT_FAILURE;
	}

	int target_fd;
	target_fd = open(argv[2], O_WRONLY);
	if (target_fd < 0) {
		u_log_errno("opening target failed");
		return EXIT_FAILURE;
	}

	int (*test)(int src, int dst, struct timespec *start);
	if (streq(argv[3], "random")) {
		u_log(INFO, "using random test pattern");
		test = random_test;
	} else if (streq(argv[3], "sequential")) {
		u_log(INFO, "using sequential test pattern");
		test = seq_test;
	}

	struct timespec now;
	test(source_fd, target_fd, &now);
	stamp(&now, "test done");

	fsync(target_fd);
	stamp(&now, "fsync done");

	return EXIT_SUCCESS;
}
