#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define STORE_NAME_MAX 128

struct store {
	char name[STORE_NAME_MAX];

	void (*free)(struct store *s);
	ssize_t (*get_chunk)(struct store *s, uint8_t *id, uint8_t *out, size_t out_max);
};


static inline ssize_t store_get_chunk(struct store *s, uint8_t *id, uint8_t *out, size_t out_max)
{
	return s->get_chunk(s, id, out, out_max);
}

static inline void store_free(struct store *s)
{
	if (s->free)
		s->free(s);
}

static inline const char *store_get_name(struct store *s)
{
	return s->name;
}

void store_free(struct store *s);

struct store_chain *store_chain_new(size_t size_hint);
int store_chain_append(struct store_chain *sc, struct store *s);

static inline struct store *store_chain_to_store(struct store_chain *sc)
{
	return (struct store*)sc;
}
