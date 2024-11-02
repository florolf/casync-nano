#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <limits.h>

#include "encrypt.h"
#include "chunk.h"
#include "utils.h"

static int chunk_id_from_path(uint8_t id[CHUNK_ID_LEN], const char *path)
{
	const char *basename = path;

	char *p = strrchr(basename, '/');
	if (p)
		basename = p+1;

	size_t name_len = strlen(basename);
	if (name_len != 70 && name_len != 74) {
		u_log(ERR, "chunk basename '%s' has wrong length, expected 70 or 74, got %zu", basename, name_len);
		return -1;
	}

	if (!streq(&basename[name_len-6], ".cacnk") && !streq(&basename[name_len-10], ".cacnk.enc")) {
		u_log(ERR, "chunk basename '%s' does not end with '.cacnk' or '.cacnk.enc'", basename);
		return -1;
	}

	char id_buf[65];
	memcpy(id_buf, basename, 64);
	id_buf[64] = 0;

	return parse_hex(id, id_buf);
}

static int encrypt_one(struct encrypt_ctx *ec, const char *input_path, const char *output_path)
{
	int ret = -1;

	uint8_t chunk_id[CHUNK_ID_LEN];
	if (chunk_id_from_path(chunk_id, input_path) < 0) {
		u_log(ERR, "failed to derive chunk id from path");
		return -1;
	}

	char path_buf[PATH_MAX];
	if (!output_path){
		size_t len = strlen(input_path);
		if (len >= 6 && streq(&input_path[len-6], ".cacnk")) {
			if (len > PATH_MAX - 5) {
				u_log(ERR, "input path too long");
				return -1;
			}

			strcpy(path_buf, input_path);
			strcpy(&path_buf[len], ".enc");
			output_path = path_buf;
		} else if (len >= 10 && streq(&input_path[len-10], ".cacnk.enc")) {
			if (len > PATH_MAX - 1) {
				u_log(ERR, "input path too long");
				return -1;
			}

			strcpy(path_buf, input_path);
			path_buf[len-4] = 0;
			output_path = path_buf;
		} else {
			u_log(ERR, "unsupported input path format");
			return -1;
		}
	}

	if (access(output_path, F_OK) == 0)
		return 0;

	// this uses the first 24 bytes of chunk_id
	if (encrypt_restart(ec, chunk_id) < 0) {
		u_log(ERR, "encrypt_restart failed");
		return -1;
	}

	off_t chunk_size;
	uint8_t *buf = slurp_file(input_path, false, &chunk_size);
	if (!buf) {
		u_log(ERR, "failed to load source chunk");
		return -1;
	}

	if (encrypt_do(ec, buf, buf, chunk_size)) {
		u_log(ERR, "encrypting chunk failed");
		goto out_buf;
	}

	int fd;
	if (streq(output_path, "-")) {
		fd = STDOUT_FILENO;
	} else {
		fd = open(output_path, O_WRONLY | O_TRUNC | O_CREAT, 0444);

		if (fd < 0) {
			u_log_errno("failed to create output file");
			goto out_buf;
		}
	}

	if (writeall(fd, buf, chunk_size) < 0) {
		u_log(ERR, "failed to write to output file");
		goto out_fd;
	}

	ret = 0;

out_fd:
	if (fd != STDOUT_FILENO)
		close(fd);
out_buf:
	free(buf);

	return ret;
}

static int do_crypt(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	if (argc < 2 || argc > 4 ||
	    streq(argv[1], "-h") || streq(argv[1], "--help")) {
		fprintf(stderr, "usage: crypt keyspec [/path/to/input] [/path/to/output]\n");
		return EXIT_FAILURE;
	}

	uint8_t key[32];
	if (encrypt_parse_keyspec(key, argv[1]) < 0) {
		u_log(ERR, "failed to parse keyspec");
		return EXIT_FAILURE;
	}

	struct encrypt_ctx ec;
	if (encrypt_init(&ec, key) < 0) {
		u_log(ERR, "encrypt_init failed");
		return EXIT_FAILURE;
	}

	if (argc == 2) {
		char line[PATH_MAX];
		while ((fgets(line, sizeof(line), stdin))) {
			chomp(line);
			if (encrypt_one(&ec, line, NULL) < 0)
				goto out;
		}

		ret = EXIT_SUCCESS;
	} else {
		char *input_path = argv[2];
		char *output_path = NULL;
		if (argc > 3)
			output_path = argv[3];

		if (encrypt_one(&ec, input_path, output_path) == 0)
			ret = EXIT_SUCCESS;
	}

out:
	encrypt_close(&ec);

	return ret;
}

static struct {
	const char *name, *desc;
	int (*fn)(int argc, char **argv);
} cmds[] = {
	{"crypt", "encrypt/decrypt a single chunk", do_crypt},
	{0}
};

__attribute__((noreturn)) static void usage(const char *prog, bool error)
{
	FILE *f = error ? stderr : stdout;

	fprintf(f, "usage: %s command\n", prog);
	fprintf(f, "available commands:\n");

	for (size_t i = 0; cmds[i].name; i++)
		fprintf(f, " - %s: %s\n", cmds[i].name, cmds[i].desc);

	exit(error ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	u_log_init();

	if (argc < 2)
		usage(argv[0], true);

	if (argc >= 2 && (streq(argv[1], "-h") || streq(argv[1], "--help")))
		usage(argv[0], false);

	for (size_t i = 0; cmds[i].name; i++)
		if (streq(cmds[i].name, argv[1]))
			return cmds[i].fn(argc - 1, argv + 1);

	usage(argv[0], false);
}
