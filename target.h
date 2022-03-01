#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "store.h"
#include "index.h"

struct target {
	struct store s;

	struct index idx;
	int fd;
	bool queryable;
};

struct target *target_new(const char *path);

int target_write(struct target *t, const uint8_t *data, size_t len, off_t offset, const uint8_t *id);

int target_check_chunk(struct target *t, uint8_t *tmp, size_t len, off_t offset, const uint8_t *id);

static inline struct store *target_as_store(struct target *t)
{
	t->queryable = true;
	return &t->s;
}
