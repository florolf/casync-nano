#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <curl/curl.h>
#include <zstd.h>

#include "utils.h"
#include "chunker.h"
#include "chunk.h"

#include "store-http.h"

#define ERROR_MAX 10u
#define CONNECT_TRIES 10

struct store_http {
	struct store s;

	const char *baseurl;
	char *url_buf;

	CURL *curl;
	char curl_err_buf[CURL_ERROR_SIZE];

	ZSTD_DStream *zstd;
	uint8_t *decode_buffer;
	size_t decode_buffer_size, decode_buffer_fill;

	unsigned int error_count;
};

#define curl_checked_setopt(curl, opt, val, err) do { \
	CURLcode curl_ret; \
\
	curl_ret = curl_easy_setopt((curl), (opt), (val)); \
	if (curl_ret != CURLE_OK) { \
		u_log(ERR, "setting up curl option %d failed: %s", (opt), curl_easy_strerror(curl_ret)); \
		err; \
	} \
} while (0)

enum http_request_state {
	HTTP_REQUEST_STARTED,
	HTTP_REQUEST_STREAMING,
	HTTP_REQUEST_FAILED
};

struct http_request_ctx {
	struct store_http *hs;

	uint8_t *outbuf;
	size_t outbuf_size;
	size_t outbuf_written;

	enum http_request_state state;
};

static int decode_buffer_absorb(struct store_http *hs, uint8_t *data, size_t len)
{
	if (hs->decode_buffer_size - hs->decode_buffer_fill < len) {
		void *new_buf;
		size_t new_size;

		new_size = hs->decode_buffer_size + len;
		if (new_size < hs->decode_buffer_size)
			return -1;

		new_buf = realloc(hs->decode_buffer, new_size);
		if (!new_buf) {
			u_log(ERR, "increasing decode buffer to %zu bytes failed", new_size);
			return -1;
		} else {
			u_log(DEBUG, "increased decode buffer to %zu bytes", new_size);
		}

		hs->decode_buffer = new_buf;
		hs->decode_buffer_size = new_size;
	}

	memcpy(&hs->decode_buffer[hs->decode_buffer_fill], data, len);
	hs->decode_buffer_fill += len;

	return 0;
}

#define ZSTD_MAGIC "\x28\xb5\x2f\xfd"

static ssize_t handle_data(struct http_request_ctx *ctx, uint8_t *data, size_t len)
{
	if (ctx->state == HTTP_REQUEST_STARTED) {
		if (len < 4)
			return 0;

		if (memcmp(data, ZSTD_MAGIC, 4) == 0) {
			ctx->state = HTTP_REQUEST_STREAMING;
		} else {
			u_log(WARN, "data does not have zstd magic number");
			return -1;
		}
	}

	u_assert(ctx->state == HTTP_REQUEST_STREAMING);

	ZSTD_inBuffer zstd_in = {
		.src = data,
		.size = len,
		.pos = 0
	};

	ZSTD_outBuffer zstd_out = {
		.dst = ctx->outbuf,
		.size = ctx->outbuf_size,
		.pos = ctx->outbuf_written
	};

	size_t ret;
	ret = ZSTD_decompressStream(ctx->hs->zstd, &zstd_out, &zstd_in);
	if (ZSTD_isError(ret)) {
		u_log(ERR, "zstd decompression failed with error: %s", ZSTD_getErrorName(ret));
		return -1;
	}

	u_log(DEBUG, "decompression consumed %zu out of %zu available bytes and produced %zu",
	      zstd_in.pos, zstd_in.size, zstd_out.pos);

	ctx->outbuf_written = zstd_out.pos;

	return zstd_in.pos;
}

static long get_response_code(CURL *handle)
{
	long http_code;

	CURLcode ret = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);
	if (ret != CURLE_OK) {
		u_log(ERR, "getting response code failed: %s", curl_easy_strerror(ret));
		return -1;
	}

	return http_code;
}

static size_t store_http_data_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	u_assert(size == 1);

	struct http_request_ctx *ctx = (struct http_request_ctx*) userdata;

	if (ctx->state == HTTP_REQUEST_STARTED) {
		long http_code = get_response_code(ctx->hs->curl);
		if (http_code != 200) {
			u_log(DEBUG, "got response code %ld, failing request", http_code);
			goto fail;
		}
	}

	if (ctx->state == HTTP_REQUEST_FAILED)
		return 0;

	ssize_t ret;
	if (ctx->hs->decode_buffer_fill) {
		decode_buffer_absorb(ctx->hs, (uint8_t*)ptr, nmemb);

		ret = handle_data(ctx, ctx->hs->decode_buffer, ctx->hs->decode_buffer_fill);
		if (ret < 0)
			goto fail;

		// XXX: clang-analyzer flags this, why?
		memmove(ctx->hs->decode_buffer, &ctx->hs->decode_buffer[ret], ctx->hs->decode_buffer_fill - ret);
		ctx->hs->decode_buffer_fill -= ret;
	} else {
		ret = handle_data(ctx, (uint8_t*)ptr, nmemb);
		if (ret < 0) {
			goto fail;
		} else if ((size_t)ret < nmemb) {
			// if we haven't used up all the data we were given, push it
			// into the buffer for the next time around
			decode_buffer_absorb(ctx->hs, (uint8_t*)&ptr[ret], nmemb - ret);
		}
	}

	return nmemb;

fail:
	ctx->state = HTTP_REQUEST_FAILED;
	return 0;
}

static int set_url(struct store_http *hs, uint8_t *id)
{
	int ret;

	ret = sprintf(hs->url_buf, "%s/%02x%02x/", hs->baseurl, id[0], id[1]);
	u_assert(ret > 0);

	chunk_format_id(&hs->url_buf[ret], id);
	strncat(hs->url_buf, ".cacnk", 7);

	curl_checked_setopt(hs->curl, CURLOPT_URL, hs->url_buf, return -1);

	return 0;
}

static bool curl_is_transient_error(CURLcode code)
{
	return code == CURLE_COULDNT_CONNECT ||
	       code == CURLE_COULDNT_RESOLVE_HOST ||
	       code == CURLE_OPERATION_TIMEDOUT;
}

static CURLcode retried_curl_easy_perform(struct store_http *hs)
{
	CURLcode ret;
	int remaining = CONNECT_TRIES;
	useconds_t wait_us = 200 * 1000;

	do {
		ret = curl_easy_perform(hs->curl);

		if (!curl_is_transient_error(ret))
			break;

		remaining--;
		u_log(WARN, "connection failed (%s%s%s), retrying %d more times",
		      curl_easy_strerror(ret),
		      hs->curl_err_buf[0] ? ": " : "", hs->curl_err_buf,
		      remaining);

		usleep(wait_us);
		wait_us = MIN(2*wait_us, 10ul*1000*1000);
	} while (remaining);

	return ret;
}

static ssize_t increase_error_counter(struct store_http *hs)
{
	hs->error_count++;
	u_log(WARN, "increasing error counter to %d", hs->error_count);

	if (hs->error_count > ERROR_MAX) {
		u_log(ERR, "error counter exceeded %d, killing store", ERROR_MAX);
		return -1;
	}

	return 0;
}

static ssize_t store_http_get_chunk(struct store *s, uint8_t *id, uint8_t *out, size_t out_max)
{
	struct store_http *hs = (struct store_http*) s;

	hs->decode_buffer_fill = 0;

	ZSTD_initDStream(hs->zstd);

	if (set_url(hs, id) < 0) {
		u_log(ERR, "setting request URL failed");
		return -1;
	}

	struct http_request_ctx ctx = {
		.hs = hs,
		.outbuf = out,
		.outbuf_size = out_max,
		.outbuf_written = 0,
		.state = HTTP_REQUEST_STARTED
	};
	curl_checked_setopt(hs->curl, CURLOPT_WRITEDATA, &ctx, return -1);

	u_log(DEBUG, "trying to fetch chunk from '%s'", hs->url_buf);

	CURLcode curl_ret;
	curl_ret = retried_curl_easy_perform(hs);

	if (curl_is_transient_error(curl_ret)) {
		u_log(WARN, "transient transfer failure, increasing error counter");
		return increase_error_counter(hs);
	}

	/* Write errors are fine, they are used by the write function to abort
	 * the request if it decides that it would never be happy with it.
	 *
	 * We'll handle this below.
	 */
	if (curl_ret != CURLE_OK && curl_ret != CURLE_WRITE_ERROR) {
		u_log(ERR, "curl_easy_perform failed: %s", hs->curl_err_buf);
		return -1;
	}

	long http_code;
	http_code = get_response_code(hs->curl);
	if (http_code < 0) {
		u_log(ERR, "getting response code failed");
		return -1;
	}

	if (http_code == 404 || http_code == 410) {
		u_log(DEBUG, "got %ld from server", http_code);
		return 0;
	}

	if (http_code >= 400) {
		u_log(WARN, "got unexpected HTTP response code %ld, increasing error counter", http_code);
		return increase_error_counter(hs);
	}

	/* If we get here and have not started processing data or failed to do
	 * so, the HTTP request went through fine, but something went wrong
	 * when decompressing the data.
	 *
	 * Not good, but could be a fluke, return 0.
	 */
	if (ctx.state == HTTP_REQUEST_STARTED || ctx.state == HTTP_REQUEST_FAILED) {
		u_log(WARN, "request for '%s' was successful, but response data was invalid",
		      hs->url_buf);

		return 0;
	}

	if (hs->decode_buffer_fill) {
		u_log(WARN, "decode buffer still contains %zu bytes at end of request",
		      hs->decode_buffer_fill);
	}

	// everything went fine: reset the error counter
	hs->error_count = 0;

	uint8_t actual_id[CHUNK_ID_LEN];
	chunk_calculate_id(out, ctx.outbuf_written, actual_id);

	if (memcmp(actual_id, id, CHUNK_ID_LEN) != 0) {
		char id_str[CHUNK_ID_STRLEN], actual_id_str[CHUNK_ID_STRLEN];

		chunk_format_id(id_str, id);
		chunk_format_id(actual_id_str, actual_id);

		u_log(WARN, "chunk id mismatch (expected %s, got %s)",
		      id_str, actual_id_str);

		return 0;
	}

	return ctx.outbuf_written;
}

static void store_http_free(struct store *s)
{
	struct store_http *hs = (struct store_http*) s;

	free((void*)hs->baseurl);
	free(hs->url_buf);
	free(hs->decode_buffer);

	ZSTD_freeDStream(hs->zstd);
	curl_easy_cleanup(hs->curl);

	free(hs);
}

#define CHUNK_SUFFIX_LEN (strlen("/8a39/8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90.cacnk"))

struct store *store_http_new(const char *baseurl)
{
	u_assert(baseurl);

	if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
		u_log(ERR, "initializing curl failed");
		return NULL;
	}

	struct store_http *hs;
	hs = calloc(1, sizeof(*hs));
	u_notnull(hs, return NULL);

	char *tmp = strdup(baseurl);
	u_notnull(tmp, goto err_hs);

	char *p;
	if ((p = strrchr(tmp, '/')) && *(p+1) == 0)
		*p = 0;

	hs->baseurl = tmp;

	hs->url_buf = malloc(strlen(hs->baseurl) + CHUNK_SUFFIX_LEN + 1);
	u_notnull(hs->url_buf, goto err_baseurl);

	snprintf(hs->s.name, sizeof(hs->s.name), "%s", baseurl);
	hs->s.free = store_http_free;
	hs->s.get_chunk = store_http_get_chunk;

	hs->curl = curl_easy_init();
	u_notnull(hs->curl, goto err_url_buf);

	curl_checked_setopt(hs->curl, CURLOPT_WRITEFUNCTION,
	                    store_http_data_cb, goto err_curl);

	curl_checked_setopt(hs->curl, CURLOPT_ERRORBUFFER,
	                    hs->curl_err_buf, goto err_curl);

	curl_checked_setopt(hs->curl, CURLOPT_FOLLOWLOCATION,
	                    (long)1, goto err_curl);

	curl_checked_setopt(hs->curl, CURLOPT_LOW_SPEED_TIME,
	                    (long)15, goto err_curl);

	curl_checked_setopt(hs->curl, CURLOPT_LOW_SPEED_LIMIT,
	                    (long)10, goto err_curl);

	hs->zstd = ZSTD_createDStream();
	u_notnull(hs->zstd, goto err_curl);

	return (struct store*)hs;

err_curl:
	curl_easy_cleanup(hs->curl);

err_url_buf:
	free((void*)hs->url_buf);

err_baseurl:
	free((void*)hs->baseurl);

err_hs:
	free(hs);

	return NULL;
}
