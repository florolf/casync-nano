#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>

ssize_t readall(int fd, uint8_t *buf, size_t len)
{
	ssize_t bytes_read = 0;
	while (len) {
		ssize_t ret;

		ret = read(fd, buf, len);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			perror("read");
			return -1;
		} else if (ret == 0) {
			break;
		}

		buf += ret;
		bytes_read += ret;
		len -= ret;
	}

	return bytes_read;
}

int main(void)
{
	assert(lseek(STDIN_FILENO, 0x40, SEEK_SET) >= 0);

	uint64_t last_offset = 0;
	while (1) {
		uint8_t buf[32];
		ssize_t ret;

		ret = readall(STDIN_FILENO, buf, 8);
		if (ret == 0)
			break;
		if (ret != 8) {
			printf("unexpected return: %zd\n", ret);
			return EXIT_FAILURE;
		}


		uint64_t *u64 = (uint64_t*)buf;
		if (*u64 == 0)
			break;

		printf("% 10"PRIu64" % 10"PRIu64" ", last_offset, *u64-last_offset);
		last_offset = *u64;

		ret = readall(STDIN_FILENO, buf, 32);
		if (ret == 0)
			break;
		if (ret != 32) {
			printf("unexpected return: %zd\n", ret);
			return EXIT_FAILURE;
		}

		/*
		for (int i = 0; i < 2; i++)
			printf("%02x", buf[i]);
		printf("/");
*/
		for (int i = 0; i < 32; i++)
			printf("%02x", buf[i]);

		printf("\n");
	}
}
