#pragma once

#include <stddef.h>
#include <stdbool.h>

#include "chunker.h"

struct index_entry {
	uint64_t start;
	uint32_t len;
	uint32_t flags;
	uint8_t id[CHUNK_ID_LEN];
};

struct index {
	bool sorted;

	size_t n_entries, space_avail;
	struct index_entry *entries;
};

int index_init(struct index *idx, size_t expected_size);
void index_cleanup(struct index *idx);

struct index_entry *index_insert(struct index *idx, uint64_t offset, uint32_t len, const uint8_t *id);
struct index_entry *index_query(struct index *idx, const uint8_t *id);
