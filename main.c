#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <time.h>
#include <getopt.h>

#include "utils.h"
#include "caibx.h"
#include "chunker.h"
#include "sha.h"
#include "store-local.h"
#include "store-http.h"
#include "target.h"
#include "ui.h"

static struct store *store;
static struct target *target;
static struct chunker_params chunker_params;
static size_t n_entries;
static int index_fd;

static bool interactive = false;

static int entry_cb(uint64_t offset, uint32_t len, uint8_t *id, void *arg)
{
	static bool have_last_id = false;
	static uint8_t last_id[CHUNK_ID_LEN];
	static uint8_t buf[256*1024] __attribute__((aligned(4096)));

	if (!have_last_id || memcmp(last_id, id, CHUNK_ID_LEN) != 0) {
		ssize_t ret = store_get_chunk(store, id, buf, sizeof(buf));
		if (ret < 0 || len != (size_t)ret) {
			u_log(ERR, "result size %zd does not match expected length %"PRIu32, ret, len);
			return -1;
		}

		memcpy(last_id, id, CHUNK_ID_LEN);
		have_last_id = true;
	}

	if (target_write(target, buf, len, offset, id) < 0) {
		u_log(ERR, "failed to store chunk to target");
		return -1;
	}

	// only show progress bar when running interactively and not spamming
	// debug information anyway
	if (interactive && !check_loglevel(U_LOG_DEBUG)) {
		static uint32_t handled_entries = 0;
		static progess_status_t progress_status = PROGRESS_STATUS_INIT;

		show_progress(100 * ++handled_entries / n_entries, &progress_status);
	}

	return 0;
}

static int append_store_from_arg(struct store_chain *sc, char *arg)
{
	struct store *s;

	if (startswith(arg, "http")) {
		s = store_http_new(arg);
		if (!s) {
			u_log(ERR, "creating HTTP store from '%s' failed", arg);
			return -1;
		}
	} else {
		char *p = strchr(arg, ':');
		if (p) {
			*p = 0;
			p++;
		}

		s = store_local_new(arg, p, &chunker_params);
		if (!s) {
			u_log(ERR, "creating local store from '%s' failed", arg);
			return -1;
		}
	}

	if (store_chain_append(sc, s) < 0) {
		u_log(ERR, "appending store '%s' to store chain failed", arg);
		return -1;
	}

	return 0;
}

static int csn(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: %s input.caibx target store [store ...]\n", argv[0]);
		return -1;
	}

	const char *env;

	if ((env = getenv("CSN_KCAPI_DRIVER")) != NULL) {
		if (sha_kcapi_init(env) < 0) {
			u_log(ERR, "kcapi init failed");
			return -1;
		}

		u_log(DEBUG, "kcapi enabled with driver '%s'", env);
	}

	index_fd = open(argv[1], O_RDONLY);
	if (index_fd < 0) {
		u_log_errno("opening index '%s' failed", argv[1]);
		return -1;
	}

	if (caibx_load_header(index_fd, &chunker_params, &n_entries) < 0) {
		u_log(ERR, "loading caibx header failed");
		return -1;
	}

	target = target_new(argv[2]);
	if (!target) {
		u_log(ERR, "creating target failed");
		return -1;
	}

	struct store_chain *sc = store_chain_new(argc - 3 + 1);
	if (!sc) {
		u_log(ERR, "creating storechain failed");
		return -1;
	}

	if (store_chain_append(sc, target_as_store(target)) < 0) {
		u_log(ERR, "appending target to store chain failed");
		return -1;
	}

	for (int i = 3; i < argc; i++) {
		if (append_store_from_arg(sc, argv[i]) < 0)
			return -1;
	}

	store = store_chain_to_store(sc);

	return 0;
}

static void casync_help(void)
{
	fprintf(stderr,
	        "casync [OPTIONS...] extract BLOB_INDEX PATH\n"
	        "\n"
	        "note: This is casync-nano, which only supports extracting blob indices\n"
	        "      and just implements enough command line parsing to work with RAUC.\n"
	        "\n"
	        "supported options:\n"
	        "  --store      add a chunk store (HTTP(S) only)\n"
	        "  --seed       add seed (block device or file)\n");
}

static int casync(int argc, char **argv)
{
	enum {
		ARG_STORE = 0x100,
		ARG_SEED,
		ARG_SEED_OUTPUT
	};

	static const struct option options[] = {
		{ "help",              no_argument,       NULL, 'h'                   },
		{ "store",             required_argument, NULL, ARG_STORE             },
		{ "seed",              required_argument, NULL, ARG_SEED              },
		{ "seed-output",       required_argument, NULL, ARG_SEED_OUTPUT       },
		{}
	};

	if (argc < 3) {
		casync_help();
		exit(EXIT_FAILURE);
	}

	index_fd = open(argv[argc-2], O_RDONLY);
	if (index_fd < 0) {
		u_log_errno("opening index '%s' failed", argv[argc-2]);
		return -1;
	}

	if (caibx_load_header(index_fd, &chunker_params, &n_entries) < 0) {
		u_log(ERR, "loading caibx header failed");
		return -1;
	}

	target = target_new(argv[argc-1]);
	if (!target) {
		u_log(ERR, "creating target failed");
		return -1;
	}

	// allocate (more than) enough store chain slots
	struct store_chain *sc = store_chain_new((argc - 4) / 2 + 1);
	if (!sc) {
		u_log(ERR, "creating storechain failed");
		return -1;
	}

	if (store_chain_append(sc, target_as_store(target)) < 0) {
		u_log(ERR, "appending target to store chain failed");
		return -1;
	}

	int c;
	while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
		switch (c) {
			case 'h':
				casync_help();
				return 0;
			case ARG_STORE:
			case ARG_SEED:
				if (append_store_from_arg(sc, optarg) < 0)
					return -1;

				break;
			case ARG_SEED_OUTPUT:
				// ignored to silence unknown option warning
				// with rauc
				break;
			default:
				casync_help();
				exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 3 || !streq(argv[0], "extract")) {
		casync_help();
		exit(EXIT_FAILURE);
	}

	store = store_chain_to_store(sc);

	return 0;
}

int main(int argc, char **argv)
{
	u_log_init();

	int ret;

	if (isatty(STDOUT_FILENO))
		interactive = true;

	time_t now;

	now = time_monotonic();
	time_t start = now;

	const char *appname = basename(argv[0]);
	if (streq(appname, "csn")) {
		ret = csn(argc, argv);
	} else if (streq(appname, "casync")) {
		ret = casync(argc, argv);
	} else {
		u_log(ERR, "unimplemented app variant '%s'", appname);
		return EXIT_FAILURE;
	}

	if (ret) {
		u_log(ERR, "initializing synchronization process failed");
		return EXIT_FAILURE;
	}

	now = time_monotonic();
	u_log(INFO, "init finished after %u seconds", (unsigned int)(now - start));
	start = now;

	u_log(INFO, "starting synchronization");

	if (caibx_iterate_entries(index_fd, &chunker_params, n_entries, entry_cb, NULL) < 0) {
		u_log(ERR, "iterating entries failed");
		return EXIT_FAILURE;
	}

	now = time_monotonic();
	u_log(INFO, "synchronization finished after %u seconds", (unsigned int)(now - start));

	store_free(store);

	return EXIT_SUCCESS;
}
