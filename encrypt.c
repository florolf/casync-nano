#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <openssl/evp.h>

#include "utils.h"

#include "encrypt.h"

/* HChaCha20 implementation adapted from Monocypher v4.0.1
 * (https://monocypher.org), licensed CC0-1.0 / BSD-2-Clause. */

#define WIPE_BUFFER(buffer) crypto_wipe(buffer, sizeof(buffer))

static void unp32le_buf(uint32_t *dst, const uint8_t *src, size_t size)
{
	for (size_t i = 0; i < size; i++)
		dst[i] = unp32le(src + i*4);
}

static void p32le_buf(uint8_t *dst, const uint32_t *src, size_t size)
{
	for (size_t i = 0; i < size; i++)
		p32le(dst + i*4, src[i]);
}

static void crypto_wipe(void *secret, size_t size)
{
	volatile uint8_t *v_secret = (uint8_t*)secret;

	for (size_t i = 0; i < size; i++)
		v_secret[i] = 0;
}

#define QUARTERROUND(a, b, c, d)	\
	a += b;  d = rol32(d ^ a, 16); \
	c += d;  b = rol32(b ^ c, 12); \
	a += b;  d = rol32(d ^ a,  8); \
	c += d;  b = rol32(b ^ c,  7)

static void chacha20_rounds(uint32_t out[16], const uint32_t in[16])
{
	// The temporary variables make Chacha20 10% faster.
	uint32_t t0  = in[ 0];  uint32_t t1  = in[ 1];  uint32_t t2  = in[ 2];  uint32_t t3  = in[ 3];
	uint32_t t4  = in[ 4];  uint32_t t5  = in[ 5];  uint32_t t6  = in[ 6];  uint32_t t7  = in[ 7];
	uint32_t t8  = in[ 8];  uint32_t t9  = in[ 9];  uint32_t t10 = in[10];  uint32_t t11 = in[11];
	uint32_t t12 = in[12];  uint32_t t13 = in[13];  uint32_t t14 = in[14];  uint32_t t15 = in[15];

	for (size_t i = 0; i < 10; i++) { // 20 rounds, 2 rounds per loop.
		QUARTERROUND(t0, t4, t8 , t12); // column 0
		QUARTERROUND(t1, t5, t9 , t13); // column 1
		QUARTERROUND(t2, t6, t10, t14); // column 2
		QUARTERROUND(t3, t7, t11, t15); // column 3
		QUARTERROUND(t0, t5, t10, t15); // diagonal 0
		QUARTERROUND(t1, t6, t11, t12); // diagonal 1
		QUARTERROUND(t2, t7, t8 , t13); // diagonal 2
		QUARTERROUND(t3, t4, t9 , t14); // diagonal 3
	}
	out[ 0] = t0;   out[ 1] = t1;   out[ 2] = t2;   out[ 3] = t3;
	out[ 4] = t4;   out[ 5] = t5;   out[ 6] = t6;   out[ 7] = t7;
	out[ 8] = t8;   out[ 9] = t9;   out[10] = t10;  out[11] = t11;
	out[12] = t12;  out[13] = t13;  out[14] = t14;  out[15] = t15;
}

static_testexpose void hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t in[16])
{
	static const uint8_t *chacha20_constant = (const uint8_t*)"expand 32-byte k"; // 16 bytes

	uint32_t block[16];
	unp32le_buf(block     , chacha20_constant, 4);
	unp32le_buf(block +  4, key              , 8);
	unp32le_buf(block + 12, in               , 4);

	chacha20_rounds(block, block);

	// prevent reversal of the rounds by revealing only half of the buffer.
	p32le_buf(out   , block   , 4); // constant
	p32le_buf(out+16, block+12, 4); // counter and nonce
	WIPE_BUFFER(block);
}

/* End of Monocypher-based code. */

int encrypt_init(struct encrypt_ctx *ctx, const uint8_t key[static 32])
{
	ctx->cipher = EVP_CIPHER_CTX_new();
	if (!ctx->cipher) {
		u_log(ERR, "failed to create EVP_CIPHER_CTX");
		return -1;
	}

	memcpy(ctx->key, key, 32);

	return 0;
}

int encrypt_restart(struct encrypt_ctx *ctx, const uint8_t nonce[static 24])
{
	int ret = -1;

	uint8_t subkey[32];
	hchacha20(subkey, ctx->key, &nonce[0]);

	uint8_t ctr_nonce[16];
	memset(&ctr_nonce[0], 0, 8);
	memcpy(&ctr_nonce[8], &nonce[16], 8);

	if (!EVP_CIPHER_CTX_reset((EVP_CIPHER_CTX*)ctx->cipher)) {
		u_log(ERR, "EVP_CIPHER_CTX_reset failed");
		goto out;
	}

	if (!EVP_CipherInit((EVP_CIPHER_CTX*)ctx->cipher, EVP_chacha20(), subkey, ctr_nonce, 1)) {
		u_log(ERR, "EVP_CipherInit failed");
		goto out;
	}

	ret = 0;

out:
	WIPE_BUFFER(subkey);
	WIPE_BUFFER(ctr_nonce);

	return ret;
}

void encrypt_close(struct encrypt_ctx *ctx)
{
	EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ctx->cipher);

	crypto_wipe(ctx, sizeof(*ctx));
}

int encrypt_do(struct encrypt_ctx *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
	if (!EVP_Cipher((EVP_CIPHER_CTX*)ctx->cipher, out, in, len))
		return -1;

	return 0;
}

int encrypt_parse_keyspec(uint8_t key_out[static 32], const char *keyspec)
{
	int ret = -1;

	const char *key_str;
	bool do_free = false;

	if (startswith(keyspec, "key:")) {
		key_str = &keyspec[4];
	} else if (startswith(keyspec, "env:")) {
		key_str = getenv(&keyspec[4]);
		if (!key_str) {
			u_log(ERR, "could not retrieve environment variable '%s'", &keyspec[4]);
			return -1;
		}
	} else if(startswith(keyspec, "file:")) {
		char *slurped = slurp_file(&keyspec[5], true, NULL);
		if (!slurped)
			return -1;

		chomp(slurped);

		key_str = slurped;
		do_free = true;
	} else {
		u_log(ERR, "unknown keyspec used in '%s'", keyspec);
		return -1;
	}

	if (strlen(key_str) != 64) {
		u_log(ERR, "encryption key must be exactly 64 hex characters, but is %zu long", strlen(key_str));
		goto out;
	}

	if (parse_hex(key_out, key_str) < 0) {
		u_log(ERR, "decoding encryption key failed");

		crypto_wipe(key_out, 32);
		goto out;
	}

	ret = 0;

out:
	if (do_free) {
		crypto_wipe((void*)key_str, strlen(key_str));
		free((void*)key_str);
	}

	return ret;
}
