#pragma once

#include <stddef.h>
#include <stdint.h>

#include "chunk.h"

#include <openssl/sha.h>

#define CHUNKER_SIZE_AVG_DEFAULT ((size_t) (64U*1024U))
#define CHUNKER_WINDOW_SIZE 48

struct chunker_params {
	uint32_t min_size, avg_size, max_size;
};

struct chunker {
	struct chunker_params params;
	size_t discriminator; // XXX: why size_t?

	uint32_t h;
	size_t chunk_size;

	size_t window_fill;
	uint8_t window[CHUNKER_WINDOW_SIZE];

	SHA256_CTX sha_ctx;
};

int chunker_params_set(struct chunker_params *params, uint64_t min_size, uint64_t avg_size, uint64_t max_size);

int chunker_init(struct chunker *c, struct chunker_params *params);
size_t chunker_scan(struct chunker *c, uint8_t *buf, size_t len);
void chunker_reset(struct chunker *c);
void chunker_get_id(struct chunker *c, uint8_t *id_out);

int chunker_scan_fd(int fd, struct chunker_params *params,
                    int (*cb)(uint64_t offset, uint32_t len, uint8_t *id, void *arg), void *arg);
