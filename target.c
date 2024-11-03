#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "utils.h"
#include "chunker.h"
#include "index.h"

#include "target.h"

static void target_add_chunk(struct target *t, size_t len, off_t offset, const uint8_t *id)
{
	if (!t->queryable)
		return;

	struct index_entry *e;
	e = index_query(&t->idx, id);
	if (!e) {
		e = index_insert(&t->idx, offset, len, id);
		if (!e)
			u_log(WARN, "inserting chunk into index failed");
	}
}

int target_check_chunk(struct target *t, uint8_t *tmp, size_t len, off_t offset, const uint8_t *id)
{
	uint8_t calculated_id[CHUNK_ID_LEN];

	if (!t->seekable) {
		u_log(WARN, "cannot check non-seekable target");
		return -1;
	}

	if (preadall(t->fd, tmp, len, offset) < 0) {
		u_log(WARN, "reading chunk failed");
		return -1;
	}

	chunk_calculate_id(tmp, len, calculated_id);
	if (memcmp(calculated_id, id, CHUNK_ID_LEN))
		return 0;

	target_add_chunk(t, len, offset, id);

	return 1;
}

static ssize_t target_get_chunk(struct store *s, uint8_t *id, uint8_t *out, size_t out_max)
{
	struct target *t = (struct target*) s;

	if (!t->queryable)
		return 0;

	struct index_entry *e;
	e = index_query(&t->idx, id);

	if (!e)
		return 0;

	if (e->len > out_max) {
		u_log(ERR, "output buffer to small (%zu) to contain cunk of size %"PRIu32,
		      out_max, e->len);
		return -1;
	}

	if (preadall(t->fd, out, e->len, e->start) < 0) {
		u_log(ERR, "reading chunk failed");
		return -1;
	}

	return e->len;
}

int target_write(struct target *t, const uint8_t *data, size_t len, off_t offset, const uint8_t *id)
{
	u_assert(t);
	u_assert(id);

	int ret;
	if (t->seekable) {
		ret = pwriteall(t->fd, data, len, offset);
		if (ret < 0) {
			u_log_errno("writing %zu bytes to target failed", len);
			return -1;
		}

		target_add_chunk(t, len, offset, id);
	} else {
		if (offset != t->offset) {
			u_log(ERR, "tried to write to offset %llu in non-seekable target currently at offset %llu",
					(unsigned long long)offset,
					(unsigned long long)t->offset);
			return -1;
		}

		ret = writeall(t->fd, data, len);
		if (ret < 0) {
			u_log_errno("writing %zu bytes to target failed", len);
			return -1;
		}

		t->offset += len;
	}

	return 0;
}

struct target *target_new(const char *path)
{
	u_assert(path);

	struct target *t;
	t = calloc(1, sizeof(*t));
	u_notnull(t, return NULL);

	if (streq(path, "-")) {
		t->fd = STDOUT_FILENO;
	} else {
		t->fd = open(path, O_RDWR);
		if (t->fd < 0) {
			u_log_errno("opening target '%s' failed", path);
			goto err_target;
		}
	}

	t->seekable = true;
	t->offset = 0;
	if (lseek(t->fd, t->offset, SEEK_SET) < 0)
		t->seekable = false;

	snprintf(t->s.name, sizeof(t->s.name), "target:%s", path);
	t->s.get_chunk = target_get_chunk;

	/* Targets have a lifetime that is decoupled from the store they
	 * represent. Don't free them when the store falls out of use.
	 *
	 * Conversely, this means that a target must not be destroyed while the
	 * store is still in use.
	 */
	t->s.free = NULL;

	return t;

err_target:
	free(t);

	return NULL;
}

struct store *target_as_store(struct target *t, size_t chunk_estimate)
{
	if (t->queryable)
		return &t->s;

	if (!t->seekable) {
		u_log(WARN, "cannot use non-seekable target as store");
		return NULL;
	}

	u_log(DEBUG, "initializing index with an estimated %zu chunks", chunk_estimate);
	if (index_init(&t->idx, chunk_estimate) < 0) {
		u_log(ERR, "initializing index failed");
		return NULL;
	}

	t->queryable = true;
	return &t->s;
}
