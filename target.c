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
	ret = pwriteall(t->fd, data, len, offset);
	if (ret < 0) {
		u_log_errno("writing %zu bytes to target failed", len);
		return -1;
	}

	if (!t->queryable)
		return 0;

	struct index_entry *e;
	e = index_query(&t->idx, id);
	if (!e) {
		e = index_insert(&t->idx, offset, len, id);
		if (!e)
			u_log(WARN, "inserting chunk into index failed");
	}

	return 0;
}

struct target *target_new(const char *path)
{
	u_assert(path);

	struct target *t;
	t = calloc(1, sizeof(*t));
	u_notnull(t, return NULL);

	t->fd = open(path, O_RDWR);
	if (t->fd < 0) {
		u_log_errno("opening target '%s' failed", path);
		goto err_target;
	}

	snprintf(t->s.name, sizeof(t->s.name), "target:%s", path);
	t->s.get_chunk = target_get_chunk;

	/* Targets have a lifetime that is decoupled from the store they
	 * represent. Don't free them when the store falls out of use.
	 *
	 * Conversely, this means that a target must not be destroyed while the
	 * store is still in use.
	 */
	t->s.free = NULL;

	off_t size;
	checked(fd_size(t->fd, &size), goto err_fd);

	/* We don't want to pollute the API with chunker parameters here. Let's
	 * just use the default as a reasonable estimate.
	 */
	size_t chunk_estimate = (12ull * size/CHUNKER_SIZE_AVG_DEFAULT) / 10;
	u_log(DEBUG, "initializing index with an estimated %zu chunks", chunk_estimate);
	if (index_init(&t->idx, chunk_estimate) < 0) {
		u_log(ERR, "initializing index failed");
		goto err_fd;
	}

	return t;

err_fd:
	close(t->fd);

err_target:
	free(t);

	return NULL;
}
