#pragma once

#include <stdint.h>
#include <stddef.h>

struct encrypt_ctx {
	uint8_t key[32];

	void *cipher;
};

int encrypt_init(struct encrypt_ctx *ctx, const uint8_t key[static 32]);
void encrypt_close(struct encrypt_ctx *ctx);

int encrypt_restart(struct encrypt_ctx *ctx, const uint8_t nonce[static 24]);
int encrypt_do(struct encrypt_ctx *ctx, uint8_t *out, const uint8_t *in, size_t len);

#ifdef TESTING
void hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t in[16]);
#endif
