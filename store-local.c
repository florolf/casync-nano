#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>

#include "utils.h"
#include "store-local.h"
#include "caibx.h"
#include "chunk.h"
#include "chunker.h"
#include "index.h"

struct store_local {
	struct store s;

	int fd;
	struct index idx;

	struct chunker_params chunker_params;
};

#define INDEX_FLAG_VALIDATED (1<<0)

struct insert_ctx {
	struct index *idx;
	uint32_t flags;
};

static int store_insert_index(uint64_t offset, uint32_t len, uint8_t *id, void *arg)
{
	struct insert_ctx *ctx = (struct insert_ctx*) arg;

	struct index_entry *e;
	e = index_insert(ctx->idx, offset, len, id);
	if (!e) {
		u_log(ERR, "inserting chunk at offset %"PRIu64" failed", offset);
		return -1;
	}

	e->flags |= ctx->flags;

	return 0;
}

static int store_sideload_index(struct store_local *ls, const char *index)
{
	int index_fd;
	int ret = -1;

	index_fd = open(index, O_RDONLY);
	if (index_fd < 0) {
		u_log_errno("opening index for sideloading failed");
		return -1;
	}

	size_t n_entries;
	struct chunker_params caibx_params;
	if (caibx_load_header(index_fd, &caibx_params, &n_entries) < 0) {
		u_log(ERR, "parsing caibx header failed");
		goto out_fd;
	}

	if (caibx_params.min_size != ls->chunker_params.min_size ||
	    caibx_params.avg_size != ls->chunker_params.avg_size ||
	    caibx_params.max_size != ls->chunker_params.max_size) {
		u_log(ERR, "chunker parameter mismatch between sideload index (%"PRIu32" / %"PRIu32" / %"PRIu32")"
		           "and chosen parameters (%"PRIu32" / %"PRIu32" / %"PRIu32")",
		           caibx_params.min_size, caibx_params.avg_size, caibx_params.max_size,
		           ls->chunker_params.min_size, ls->chunker_params.avg_size, ls->chunker_params.max_size);

		goto out_fd;
	}

	if (index_init(&ls->idx, n_entries) < 0) {
		u_log(ERR, "initializing index failed");
		goto out_fd;
	}

	struct insert_ctx ctx = {
		.idx = &ls->idx,
		.flags = 0
	};

	if (caibx_iterate_entries(index_fd, &caibx_params, n_entries, store_insert_index, &ctx) < 0) {
		u_log(ERR, "sideload iteration aborted");

		index_cleanup(&ls->idx);
		goto out_fd;
	}

	ret = 0;

out_fd:
	close(index_fd);

	return ret;
}

static int store_scan(struct store_local *ls)
{
	off_t size;

	checked(fd_size(ls->fd, &size), return -1);
	size_t chunk_estimate = (12ull * size/ls->chunker_params.avg_size) / 10;

	u_log(DEBUG, "initializing index with an estimated %zu chunks", chunk_estimate);
	if (index_init(&ls->idx, chunk_estimate) < 0) {
		u_log(ERR, "initializing index failed");
		return -1;
	}

	struct insert_ctx ctx = {
		.idx = &ls->idx,

		// as this entry is the result of scanning the store ourselves, we
		// consider it in sync with the data within the store
		.flags = INDEX_FLAG_VALIDATED
	};

	if (chunker_scan_fd(ls->fd, &ls->chunker_params, store_insert_index, &ctx) < 0)
		return -1;

	return 0;
}

static ssize_t store_local_get_chunk(struct store *s, uint8_t *id, uint8_t *out, size_t out_max)
{
	struct store_local *ls = (struct store_local*) s;

	struct index_entry *e;
restart:
	e = index_query(&ls->idx, id);

	if (!e)
		return 0;

	if (e->len > out_max) {
		u_log(ERR, "output buffer to small (%zu) to contain cunk of size %"PRIu32,
		      out_max, e->len);
		return -1;
	}

	if (preadall(ls->fd, out, e->len, e->start) < 0) {
		u_log(ERR, "reading chunk failed");
		return -1;
	}

	if (e->flags & INDEX_FLAG_VALIDATED)
		return e->len;

	// if the entry has not been validated, check its contents
	uint8_t actual_chunk_id[CHUNK_ID_LEN];
	chunk_calculate_id(out, e->len, actual_chunk_id);

	if (memcmp(id, actual_chunk_id, CHUNK_ID_LEN) == 0) {
		e->flags |= INDEX_FLAG_VALIDATED;
		return e->len;
	}

	u_log(ERR, "chunk validation failure rescanning store");
	index_cleanup(&ls->idx);
	if (store_scan(ls) < 0) {
		u_log(ERR, "rescanning store failed");
		return -1;
	}

	goto restart;
}

static void store_local_free(struct store *s)
{
	struct store_local *ls = (struct store_local*) s;

	index_cleanup(&ls->idx);
	free(ls);
}

struct store *store_local_new(const char *path, const char *index,
                              struct chunker_params *chunker_params)
{
	u_assert(path);

	struct store_local *ls;
	ls = calloc(1, sizeof(*ls));
	u_notnull(ls, return NULL);

	ls->fd = open(path, O_RDONLY);
	if (ls->fd < 0) {
		u_log_errno("opening store at '%s' failed", path);
		goto err_ls;
	}

	memcpy(&ls->chunker_params, chunker_params, sizeof(*chunker_params));

	snprintf(ls->s.name, sizeof(ls->s.name), "%s", path);
	ls->s.get_chunk = store_local_get_chunk;
	ls->s.free = store_local_free;

	if (index) {
		u_log(INFO, "trying to sideload index '%s' for store '%s'", index, path);

		if (store_sideload_index(ls, index) == 0) {
			u_log(WARN, "sideloading succeeded");
			return (struct store*)ls;
		}

		u_log(WARN, "sideloading index failed, falling back to scanning");
	}

	u_log(INFO, "scanning store '%s'", path);
	if (store_scan(ls) < 0) {
		u_log(ERR, "scanning store '%s' failed", path);
		goto err_ls;
	}
	u_log(INFO, "scanning store finished");

	return (struct store*)ls;

err_ls:
	free(ls);
	return NULL;
}
