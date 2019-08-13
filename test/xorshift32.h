#pragma once

#include <stdint.h>
#include <stddef.h>

struct xorshift32_state {
	uint32_t a;
};

#define XORSHIFT32_INIT(seed) (struct xorshift32_state) { \
	.a = (seed) \
}

uint32_t xorshift32(struct xorshift32_state *state);
void xorshift32_fill(struct xorshift32_state *state, void *buf, size_t len);
