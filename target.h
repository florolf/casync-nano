#pragma once

#include <stdint.h>

#include "store.h"
#include "index.h"

struct target {
	struct store s;

	struct index idx;
	int fd;
};

struct target *target_new(const char *path);

int target_write(struct target *t, uint8_t *data, size_t len, off_t offset, uint8_t *id);

static inline struct store *target_as_store(struct target *t)
{
	return &t->s;
}
