#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include "utils.h"
#include "chunk.h"

#include "store.h"

struct substore {
	struct store *s;
	bool active;
	uint32_t hits;
};

struct store_chain {
	struct store s;

	struct substore *stores;
	size_t n_stores, stores_space;

	uint32_t queries;
};

static ssize_t store_chain_get_chunk(struct store *s, uint8_t *id, uint8_t *out, size_t out_max)
{
	struct store_chain *sc = (struct store_chain*) s;

	char chunk_name[CHUNK_ID_STRLEN];
	if (check_loglevel(U_LOG_DEBUG))
		chunk_format_id(chunk_name, id);

	sc->queries++;

	for (size_t i = 0; i < sc->n_stores; i++) {
		struct substore *substore = &sc->stores[i];

		if (!substore->active)
			continue;

		ssize_t ret;
		ret = store_get_chunk(substore->s, id, out, out_max);
		if (ret < 0) {
			u_log(DEBUG, "store '%s' has failed, deactivating it",
			      store_get_name(substore->s));

			substore->active = false;
			continue;
		} else if (ret > 0) {
			substore->hits++;

			u_log(DEBUG, "chunk %s found in store '%s'",
			      chunk_name, store_get_name(substore->s));

			return ret;
		}
	}

	u_log(WARN, "chunk %s not found in any store", chunk_name);

	return 0;
}

static void store_chain_free(struct store *s)
{
	struct store_chain *sc = (struct store_chain*) s;

	u_log(INFO, "%"PRIu32" queries recieved by %s",
	      sc->queries, store_get_name(s));
	for (size_t i = 0; i < sc->n_stores; i++)
		u_log(INFO, "    %"PRIu32" answered by store %s",
		      sc->stores[i].hits,
		      store_get_name(sc->stores[i].s));


	for (size_t i = 0; i < sc->n_stores; i++)
		store_free(sc->stores[i].s);

	free(sc->stores);
	free(sc);
}

struct store_chain *store_chain_new(size_t size)
{
	static int chain_ctr = 0;

	struct store_chain *sc;
	sc = calloc(1, sizeof(*sc));
	u_notnull(sc, return NULL);

	sc->stores = calloc(size, sizeof(*sc->stores));
	u_notnull(sc->stores, goto err_sc);

	sc->n_stores = 0;
	sc->stores_space = size;

	snprintf(sc->s.name, sizeof(sc->s.name), "chain%d", chain_ctr);
	sc->s.get_chunk = store_chain_get_chunk;
	sc->s.free = store_chain_free;

	chain_ctr++;
	return sc;

err_sc:
	free(sc);

	return NULL;
}

int store_chain_append(struct store_chain *sc, struct store *s)
{
	u_assert(sc->n_stores < sc->stores_space);

	struct substore *substore = &sc->stores[sc->n_stores];
	substore->s = s;
	substore->active = true;

	sc->n_stores++;

	return 0;
}
