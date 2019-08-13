#include <stdint.h>
#include <assert.h>

#include "xorshift32.h"

uint32_t xorshift32(struct xorshift32_state *state)
{
	/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
	uint32_t x = state->a;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return state->a = x;
}

void xorshift32_fill(struct xorshift32_state *state, void *buf, size_t len)
{
	assert(len % 4 == 0);

	uint32_t *buf32 = (uint32_t*)buf;
	while (len) {
		*buf32++ = xorshift32(state);
		len -= 4;
	}
}
