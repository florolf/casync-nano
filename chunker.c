#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include "utils.h"

#include "chunker.h"

static const uint32_t buzhash_table[] = {
	0x458be752, 0xc10748cc, 0xfbbcdbb8, 0x6ded5b68,
	0xb10a82b5, 0x20d75648, 0xdfc5665f, 0xa8428801,
	0x7ebf5191, 0x841135c7, 0x65cc53b3, 0x280a597c,
	0x16f60255, 0xc78cbc3e, 0x294415f5, 0xb938d494,
	0xec85c4e6, 0xb7d33edc, 0xe549b544, 0xfdeda5aa,
	0x882bf287, 0x3116737c, 0x05569956, 0xe8cc1f68,
	0x0806ac5e, 0x22a14443, 0x15297e10, 0x50d090e7,
	0x4ba60f6f, 0xefd9f1a7, 0x5c5c885c, 0x82482f93,
	0x9bfd7c64, 0x0b3e7276, 0xf2688e77, 0x8fad8abc,
	0xb0509568, 0xf1ada29f, 0xa53efdfe, 0xcb2b1d00,
	0xf2a9e986, 0x6463432b, 0x95094051, 0x5a223ad2,
	0x9be8401b, 0x61e579cb, 0x1a556a14, 0x5840fdc2,
	0x9261ddf6, 0xcde002bb, 0x52432bb0, 0xbf17373e,
	0x7b7c222f, 0x2955ed16, 0x9f10ca59, 0xe840c4c9,
	0xccabd806, 0x14543f34, 0x1462417a, 0x0d4a1f9c,
	0x087ed925, 0xd7f8f24c, 0x7338c425, 0xcf86c8f5,
	0xb19165cd, 0x9891c393, 0x325384ac, 0x0308459d,
	0x86141d7e, 0xc922116a, 0xe2ffa6b6, 0x53f52aed,
	0x2cd86197, 0xf5b9f498, 0xbf319c8f, 0xe0411fae,
	0x977eb18c, 0xd8770976, 0x9833466a, 0xc674df7f,
	0x8c297d45, 0x8ca48d26, 0xc49ed8e2, 0x7344f874,
	0x556f79c7, 0x6b25eaed, 0xa03e2b42, 0xf68f66a4,
	0x8e8b09a2, 0xf2e0e62a, 0x0d3a9806, 0x9729e493,
	0x8c72b0fc, 0x160b94f6, 0x450e4d3d, 0x7a320e85,
	0xbef8f0e1, 0x21d73653, 0x4e3d977a, 0x1e7b3929,
	0x1cc6c719, 0xbe478d53, 0x8d752809, 0xe6d8c2c6,
	0x275f0892, 0xc8acc273, 0x4cc21580, 0xecc4a617,
	0xf5f7be70, 0xe795248a, 0x375a2fe9, 0x425570b6,
	0x8898dcf8, 0xdc2d97c4, 0x0106114b, 0x364dc22f,
	0x1e0cad1f, 0xbe63803c, 0x5f69fac2, 0x4d5afa6f,
	0x1bc0dfb5, 0xfb273589, 0x0ea47f7b, 0x3c1c2b50,
	0x21b2a932, 0x6b1223fd, 0x2fe706a8, 0xf9bd6ce2,
	0xa268e64e, 0xe987f486, 0x3eacf563, 0x1ca2018c,
	0x65e18228, 0x2207360a, 0x57cf1715, 0x34c37d2b,
	0x1f8f3cde, 0x93b657cf, 0x31a019fd, 0xe69eb729,
	0x8bca7b9b, 0x4c9d5bed, 0x277ebeaf, 0xe0d8f8ae,
	0xd150821c, 0x31381871, 0xafc3f1b0, 0x927db328,
	0xe95effac, 0x305a47bd, 0x426ba35b, 0x1233af3f,
	0x686a5b83, 0x50e072e5, 0xd9d3bb2a, 0x8befc475,
	0x487f0de6, 0xc88dff89, 0xbd664d5e, 0x971b5d18,
	0x63b14847, 0xd7d3c1ce, 0x7f583cf3, 0x72cbcb09,
	0xc0d0a81c, 0x7fa3429b, 0xe9158a1b, 0x225ea19a,
	0xd8ca9ea3, 0xc763b282, 0xbb0c6341, 0x020b8293,
	0xd4cd299d, 0x58cfa7f8, 0x91b4ee53, 0x37e4d140,
	0x95ec764c, 0x30f76b06, 0x5ee68d24, 0x679c8661,
	0xa41979c2, 0xf2b61284, 0x4fac1475, 0x0adb49f9,
	0x19727a23, 0x15a7e374, 0xc43a18d5, 0x3fb1aa73,
	0x342fc615, 0x924c0793, 0xbee2d7f0, 0x8a279de9,
	0x4aa2d70c, 0xe24dd37f, 0xbe862c0b, 0x177c22c2,
	0x5388e5ee, 0xcd8a7510, 0xf901b4fd, 0xdbc13dbc,
	0x6c0bae5b, 0x64efe8c7, 0x48b02079, 0x80331a49,
	0xca3d8ae6, 0xf3546190, 0xfed7108b, 0xc49b941b,
	0x32baf4a9, 0xeb833a4a, 0x88a3f1a5, 0x3a91ce0a,
	0x3cc27da1, 0x7112e684, 0x4a3096b1, 0x3794574c,
	0xa3c8b6f3, 0x1d213941, 0x6e0a2e00, 0x233479f1,
	0x0f4cd82f, 0x6093edd2, 0x5d7d209e, 0x464fe319,
	0xd4dcac9e, 0x0db845cb, 0xfb5e4bc3, 0xe0256ce1,
	0x09fb4ed1, 0x0914be1e, 0xa5bdb2c3, 0xc6eb57bb,
	0x30320350, 0x3f397e91, 0xa67791bc, 0x86bc0e2c,
	0xefa0a7e2, 0xe9ff7543, 0xe733612c, 0xd185897b,
	0x329e5388, 0x91dd236b, 0x2ecb0d93, 0xf4d82a3d,
	0x35b5c03f, 0xe4e606f0, 0x05b21843, 0x37b45964,
	0x5eff22f4, 0x6027f4cc, 0x77178b3c, 0xae507131,
	0x7bf7cabc, 0xf9c18d66, 0x593ade65, 0xd95ddf11,
};

int chunker_params_set(struct chunker_params *params, uint64_t min_size, uint64_t avg_size, uint64_t max_size)
{
	// FIXME: support fixed-size chunks
	if (!(min_size < avg_size && avg_size < max_size)) {
		u_log(ERR, "non-monotonic chunk size parameters: %"PRIu64" / %"PRIu64" / %"PRIu64,
		      min_size, avg_size, max_size);
		return -1;
	}

	if ((min_size > UINT32_MAX) ||
	    (avg_size > UINT32_MAX) ||
	    (max_size > UINT32_MAX)) {
		u_log(ERR, "unreasonably large chunk size parameters: %"PRIu64" / %"PRIu64" / %"PRIu64,
		      min_size, avg_size, max_size);
		return -1;
	}

	params->min_size = (uint32_t) min_size;
	params->avg_size = (uint32_t) avg_size;
	params->max_size = (uint32_t) max_size;
	return 0;
}

void chunker_reset(struct chunker *c)
{
	c->h = 0;
	c->chunk_size = 0;
	c->window_fill = 0;

	SHA256_Init(&c->sha_ctx);
}

#define CA_CHUNKER_DISCRIMINATOR_FROM_AVG(avg) ((size_t) (avg / (-1.42888852e-7 * avg + 1.33237515)))
int chunker_init(struct chunker *c, struct chunker_params *params)
{
	u_assert(c);

	memcpy(&c->params, params, sizeof(*params));

	// make sure we match casync's results here
	u_build_assert(CA_CHUNKER_DISCRIMINATOR_FROM_AVG(64 * 1024) == 0xc17f);
	c->discriminator = CA_CHUNKER_DISCRIMINATOR_FROM_AVG(c->params.avg_size);

	chunker_reset(c);

	return 0;
}

static bool chunker_shall_break(struct chunker *c)
{
	if (c->chunk_size >= c->params.max_size)
		return true;

	if (c->chunk_size < c->params.min_size)
		return false;

	// special case the common case to allow for compile-time optimization
	if (c->params.avg_size == CHUNKER_SIZE_AVG_DEFAULT) {
		size_t default_discriminator;

		default_discriminator = CA_CHUNKER_DISCRIMINATOR_FROM_AVG(CHUNKER_SIZE_AVG_DEFAULT);
		return (c->h % default_discriminator) == (default_discriminator - 1);
	} else {
		return (c->h % c->discriminator) == (c->discriminator - 1);
	}
}

size_t chunker_scan(struct chunker *c, uint8_t *buf, size_t len)
{
	u_assert(c);
	u_assert(buf);

	size_t consumed = 0;

	if (c->window_fill < CHUNKER_WINDOW_SIZE) {
		size_t to_copy;

		to_copy = MIN(len, CHUNKER_WINDOW_SIZE - c->window_fill);
		memcpy(&c->window[c->window_fill], buf, to_copy);
		SHA256_Update(&c->sha_ctx, buf, to_copy);

		c->window_fill += to_copy;
		c->chunk_size += to_copy;

		buf += to_copy;
		consumed = to_copy;
		len -= to_copy;

		if (c->window_fill < CHUNKER_WINDOW_SIZE)
			return (size_t)-1;

		// window is full now, do initial hashing
		for (size_t i = 0; i < CHUNKER_WINDOW_SIZE; i++)
			c->h ^= rol32(buzhash_table[c->window[i]], CHUNKER_WINDOW_SIZE-i-1);
	}

	if (chunker_shall_break(c))
		return consumed;

	size_t window_leave_idx = c->chunk_size % CHUNKER_WINDOW_SIZE;
	uint8_t *p = buf;
	while (len) {
		c->h = rol32(c->h, 1) ^
		       rol32(buzhash_table[c->window[window_leave_idx]], CHUNKER_WINDOW_SIZE) ^
		       buzhash_table[*p];

		c->chunk_size++;
		consumed++;

		c->window[window_leave_idx] = *p;

		window_leave_idx++;
		if (window_leave_idx == CHUNKER_WINDOW_SIZE)
			window_leave_idx = 0;

		p++;
		len--;

		if (chunker_shall_break(c)) {
			SHA256_Update(&c->sha_ctx, buf, (size_t)(p - buf));
			return consumed;
		}
	}

	SHA256_Update(&c->sha_ctx, buf, (size_t)(p - buf));

	return (size_t)-1;
}

void chunker_get_id(struct chunker *c, uint8_t *id_out)
{
	u_assert(c);
	u_assert(id_out);

	SHA256_Final(id_out, &c->sha_ctx);
}

int chunker_scan_fd(int fd, struct chunker_params *params,
                    int (*cb)(uint64_t offset, uint32_t len, uint8_t *id, void *arg), void *arg)
{
	u_assert(fd >= 0);
	u_assert(cb);

	struct chunker c;
	uint8_t buf[BUFSIZ];

	if (chunker_init(&c, params) < 0) {
		u_log(ERR, "initializing chunker failed");
		return -1;
	}

	uint64_t offset = 0;
	uint64_t last_boundary = 0;

	checked(lseek(fd, 0, SEEK_SET), return -1);

	uint8_t chunk_id[CHUNK_ID_LEN];
	while (1) {
		ssize_t bytes_read;

		bytes_read = read(fd, buf, sizeof(buf));
		if (bytes_read < 0) {
			if (errno == EINTR)
				continue;

			u_log_errno("error at offset %"PRIu64" while chunking", offset);
			return -1;
		} else if (bytes_read == 0)
			break;

		while (bytes_read) {
			size_t chunker_ret;

			chunker_ret = chunker_scan(&c, buf, bytes_read);
			if (chunker_ret == (size_t)-1) {
				// no chunk boundary here

				offset += bytes_read;
				break;
			}

			offset += chunker_ret;

			chunker_get_id(&c, chunk_id);
			if (cb(last_boundary, offset - last_boundary, chunk_id, arg) < 0)
				return -1;

			last_boundary = offset;

			chunker_reset(&c);
			memmove(buf, &buf[chunker_ret], bytes_read - chunker_ret);
			bytes_read -= chunker_ret;
		}
	}

	// do we have a leftover chunk?
	if (offset != last_boundary) {
		chunker_get_id(&c, chunk_id);
		if (cb(last_boundary, offset - last_boundary, chunk_id, arg) < 0)
			return -1;
	}

	return 0;
}
