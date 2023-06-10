#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>

#include "chunker.h"
#include "utils.h"
#include "test/xorshift32.h"

static uint64_t time_delta_ms(struct timespec *start, struct timespec *end)
{
	uint64_t ret = end->tv_sec - start->tv_sec;
	ret *= 1000ull;
	ret += ((int32_t)end->tv_nsec - (int32_t)start->tv_nsec) / 1000000;

	return ret;
}

static int bench_hash(int argc, char **argv)
{
	const char *env;

	if ((env = getenv("CSN_KCAPI_DRIVER")) != NULL) {
		if (sha_kcapi_init(env) < 0) {
			u_log(ERR, "kcapi init failed");
			return EXIT_FAILURE;
		}

		u_log(INFO, "kcapi enabled with driver '%s'", env);
	}

	size_t buf_sz = CHUNKER_SIZE_AVG_DEFAULT * 4;
	uint8_t *buf;

	if (posix_memalign((void**)&buf, 4096, buf_sz)) {
		u_log(ERR, "failed to allocate buffer");
		return EXIT_FAILURE;
	}

	// touch all memory to ensure we don't fault later
	memset(buf, 0, buf_sz);

	struct xorshift32_state rng = XORSHIFT32_INIT(0xdeadbeef);

	struct timespec start, end;
	for (size_t i = 0; i < 3; i++) {
		uint8_t hash_out[CHUNK_ID_LEN];

		size_t count = 0;
		printf("hashing %zu byte blocks for about 10 seconds... ", buf_sz);
		fflush(stdout);

		u_assert_se(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
		while (1) {
			for (size_t inner = 0; inner < 100; inner++) {
				xorshift32_fill(&rng, buf, buf_sz);
				sha_once(buf, buf_sz, hash_out);
			}
			count += 100;

			u_assert_se(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
			if (end.tv_sec - start.tv_sec >= 10)
				break;
		}

		uint64_t delta = time_delta_ms(&start, &end);
		double rate = (double)count * buf_sz / (delta / 1000.0) / 1024.0 / 1024.0;
		printf("%zu iterations in %"PRIu64" ms -> %.2f MiB/s\n", count, delta, rate);

		buf_sz /= 4;
	}

	return EXIT_SUCCESS;
}

static int bench_chunker(int argc, char **argv)
{
	size_t buf_sz = 1024*1024;
	uint8_t *buf = malloc(buf_sz);

	// touch all memory to ensure we don't fault later
	memset(buf, 0, buf_sz);

	struct xorshift32_state rng = XORSHIFT32_INIT(0xdeadbeef);
	xorshift32_fill(&rng, buf, buf_sz);

	struct chunker_params cp;
	chunker_params_set(&cp,
	                   CHUNKER_SIZE_AVG_DEFAULT / 4,
	                   CHUNKER_SIZE_AVG_DEFAULT,
	                   CHUNKER_SIZE_AVG_DEFAULT * 4);

	struct chunker c;
	chunker_init(&c, &cp);

	struct timespec start, end;
	printf("chunking %zu bytes for about 10 seconds... ", buf_sz);
	fflush(stdout);

	size_t count = 0;
	u_assert_se(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
	while (1) {
		xorshift32_fill(&rng, buf, buf_sz);

		size_t buf_fill = buf_sz;
		while (buf_fill) {
			size_t chunker_ret;

			chunker_ret = chunker_scan(&c, buf, buf_fill);
			if (chunker_ret == (size_t)-1)
				break;

			uint8_t chunk_id[CHUNK_ID_LEN];
			chunker_get_id(&c, chunk_id);

			chunker_reset(&c);
			memmove(buf, &buf[chunker_ret], buf_fill - chunker_ret);
			buf_fill -= chunker_ret;
		}

		count++;

		u_assert_se(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
		if (end.tv_sec - start.tv_sec >= 10)
			break;
	}

	uint64_t delta = time_delta_ms(&start, &end);
	double rate = (double)count * buf_sz / (delta / 1000.0) / 1024.0 / 1024.0;
	printf("%zu iterations in %"PRIu64" ms -> %.2f MiB/s\n", count, delta, rate);

	return EXIT_SUCCESS;
}

static struct {
	const char *name, *desc;
	int (*fn)(int argc, char **argv);
} benchmarks[] = {
	{"hash", "Benchmark chunk hashing operations", bench_hash},
	{"chunker", "Benchmark chunking operations", bench_chunker},
	{0}
};

__attribute__((noreturn)) static void usage(const char *prog, bool error)
{
	FILE *f = error ? stderr : stdout;

	fprintf(f, "usage: %s benchmark\n", prog);
	fprintf(f, "available benchmarks:\n");

	for (size_t i = 0; benchmarks[i].name; i++)
		fprintf(f, " - %s: %s\n", benchmarks[i].name, benchmarks[i].desc);

	exit(error ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	u_log_init();

	if (argc < 2)
		usage(argv[0], true);

	if (argc >= 2 && (streq(argv[1], "-h") || streq(argv[1], "--help")))
		usage(argv[0], false);

	for (size_t i = 0; benchmarks[i].name; i++)
		if (streq(benchmarks[i].name, argv[1]))
			return benchmarks[i].fn(argc - 1, argv + 1);

	usage(argv[0], false);
}
