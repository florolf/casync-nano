#include <stdlib.h>
#include <stdint.h>

#include "utils.h"
#include "index.h"

int index_init(struct index *idx, size_t expected_size)
{
	u_assert(idx);
	u_assert(expected_size > 0);

	idx->entries = calloc(expected_size, sizeof(*idx->entries));
	u_notnull(idx->entries, return -1);

	idx->sorted = false;
	idx->n_entries = 0;
	idx->space_avail = expected_size;

	return 0;
}

void index_cleanup(struct index *idx)
{
	u_assert(idx);

	free(idx->entries);
}

struct index_entry *index_insert(struct index *idx, uint64_t offset, uint32_t len, const uint8_t *id)
{
	u_assert(idx);
	u_assert(len != 0);
	u_assert(id);

	u_assert(idx->entries);

	if (idx->n_entries >= idx->space_avail) {
		size_t new_size;
		void *new_entries;

		u_log(DEBUG, "index %p exceeded designated space of %zu entries",
		      idx, idx->space_avail);

		new_size = (idx->space_avail * 12ull) / 10 + 1;
		new_entries = realloc(idx->entries, new_size * sizeof(*idx->entries));
		if (!new_entries) {
			u_log_errno("increasing size of entries array of index %p to %zu entries failed",
			            idx, idx->space_avail);

			return NULL;
		}

		idx->space_avail = new_size;
		idx->entries = new_entries;
	}

	struct index_entry *e = &idx->entries[idx->n_entries];
	e->start = offset;
	e->len = len;
	e->flags = 0;
	memcpy(e->id, id, CHUNK_ID_LEN);

	idx->sorted = false;
	idx->n_entries++;

	return e;
}

static int index_entry_compare(const void *a, const void *b)
{
	const struct index_entry *ie_a = (const struct index_entry*)a;
	const struct index_entry *ie_b = (const struct index_entry*)b;

	return memcmp(ie_a->id, ie_b->id, CHUNK_ID_LEN);
}

static void index_sort(struct index *idx)
{
	u_assert(idx);

	qsort(idx->entries, idx->n_entries, sizeof(*idx->entries),
	      index_entry_compare);

	idx->sorted = true;
}

struct index_entry *index_query(struct index *idx, const uint8_t *id)
{
	u_assert(idx);
	u_assert(id);

	if (!idx->sorted)
		index_sort(idx);

	struct index_entry key;
	memcpy(key.id, id, CHUNK_ID_LEN);

	return bsearch(&key, idx->entries, idx->n_entries, sizeof(*idx->entries),
	               index_entry_compare);
}
