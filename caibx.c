#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#include "utils.h"
#include "chunker.h"
#include "caibx.h"

enum {
	CA_FORMAT_INDEX                 = UINT64_C(0x96824d9c7b129ff9),
	CA_FORMAT_TABLE                 = UINT64_C(0xe75b9e112f17417d),
	CA_FORMAT_TABLE_TAIL_MARKER     = UINT64_C(0x4b4f050e5549ecd1),
};

#define CA_HEADER_LEN 0x30
#define CA_TABLE_HEADER_LEN 16
#define CA_TABLE_ENTRY_LEN 40
#define CA_TABLE_MIN_LEN (CA_TABLE_HEADER_LEN + CA_TABLE_ENTRY_LEN)

static int load_section_header(int fd, uint64_t *magic_out, uint64_t *len_out)
{
	u_assert(fd >= 0);
	u_assert(magic_out);
	u_assert(len_out);

	uint8_t buf[40];
	checked(readall(fd, buf, 16), return -1);

	*len_out = unp64le(&buf[0]);
	*magic_out = unp64le(&buf[8]);

	return 0;
}

static int load_index_header(int fd, struct chunker_params *params_out)
{
	u_assert(fd >= 0);

	uint64_t header_magic, header_len;
	checked(load_section_header(fd, &header_magic, &header_len), return -1);

	if (header_magic != CA_FORMAT_INDEX) {
		u_log(ERR, "unexpected magic: %"PRIx64, header_magic);
		return -1;
	}

	if (header_len > CA_HEADER_LEN) {
		u_log(WARN, "unexpected index header length %"PRIu64, header_len);
	} else if (header_len < CA_HEADER_LEN) {
		u_log(ERR, "index header length %"PRIu64 "is too short", header_len);
		return -1;
	}

	uint8_t buf[40];
	checked(readall(fd, buf, 32), return -1);
	uint64_t flags;

	flags = unp64le(&buf[0]);
	if (flags & ~UINT64_C(0xd000000000000000)) {
		u_log(ERR, "unsupported feature set: 0x%016"PRIx64, flags);
		return -1;
	}

	uint64_t min_size = unp64le(&buf[8]);
	uint64_t avg_size = unp64le(&buf[16]);
	uint64_t max_size = unp64le(&buf[24]);

	if (params_out) {
		if (chunker_params_set(params_out, min_size, avg_size, max_size) < 0) {
			u_log(ERR, "incompatible chunker params given in file");
			return -1;
		}
	}

	return 0;
}

static int validate_table_header(int fd)
{
	u_assert(fd >= 0);

	uint64_t table_len, table_magic;

	checked(load_section_header(fd, &table_magic, &table_len), return -1);

	if (table_magic != CA_FORMAT_TABLE) {
		u_log(ERR, "invalid table magic, expected %016"PRIx64", got %016"PRIx64,
		      CA_FORMAT_TABLE, table_magic);
		return -1;
	}

	if (table_len != ~(uint64_t)0)
		u_log(WARN, "unexpected table size: %"PRIu64, table_len);

	return 0;
}

static int validate_table_footer(int fd, size_t n_entries)
{
	u_assert(fd >= 0);

	if (lseek(fd, CA_HEADER_LEN + CA_TABLE_HEADER_LEN +
	          n_entries * CA_TABLE_ENTRY_LEN, SEEK_SET) < 0) {
		u_log_errno("failed to seek to end of chunk table");
		return -1;
	}

	uint8_t buf[CA_TABLE_ENTRY_LEN];
	checked(readall(fd, buf, CA_TABLE_ENTRY_LEN), return -1);

	uint64_t tmp64;
	if ((tmp64 = unp64le(&buf[0])) != 0) {
		u_log(ERR, "chunk table footer has invalid zero fill: 0x%"PRIx64, tmp64);
		return -1;
	}

	if ((tmp64 = unp64le(&buf[8])) != 0) {
		u_log(ERR, "chunk table footer has invalid zero fill: 0x%"PRIx64, tmp64);
		return -1;
	}

	if ((tmp64 = unp64le(&buf[16])) != CA_HEADER_LEN) {
		u_log(ERR, "invalid index offset in footer, expected 0x%x, got 0x%"PRIx64,
		      CA_HEADER_LEN, tmp64);
		return -1;
	}

	tmp64 = unp64le(&buf[24]);
	uint64_t expected_len = CA_TABLE_HEADER_LEN + (n_entries+1) * CA_TABLE_ENTRY_LEN;
	if (tmp64 != expected_len) {
		u_log(ERR, "invalid size in footer, expected %"PRIu64", got %"PRIu64,
		      expected_len, tmp64);
		return -1;
	}

	if ((tmp64 = unp64le(&buf[32])) != CA_FORMAT_TABLE_TAIL_MARKER) {
		u_log(ERR, "invalid magic in footer, expected 0x%"PRIx64", got 0x%"PRIx64,
		      CA_FORMAT_TABLE_TAIL_MARKER, tmp64);
		return -1;
	}

	return 0;
}

int caibx_load_header(int fd, struct chunker_params *params_out, size_t *n_entries_out)
{
	u_assert(fd >= 0);
	u_assert(params_out);
	u_assert(n_entries_out);

	off_t file_size;
	checked(fd_size(fd, &file_size), return -1);

	if (file_size < CA_HEADER_LEN + CA_TABLE_MIN_LEN) {
		u_log(ERR, "input index is too short (%jd bytes)", (intmax_t)file_size);
		return -1;
	}

	if ((file_size - CA_HEADER_LEN - CA_TABLE_MIN_LEN) % CA_TABLE_ENTRY_LEN) {
		u_log(ERR, "got a fractional number of table entries");
		return -1;
	}

	*n_entries_out = (file_size - CA_HEADER_LEN - CA_TABLE_MIN_LEN) / CA_TABLE_ENTRY_LEN;

	checked(lseek(fd, 0, SEEK_SET), return -1);

	checked(load_index_header(fd, params_out), return -1);
	checked(validate_table_header(fd), return -1);
	checked(validate_table_footer(fd, *n_entries_out), return -1);

	u_log(DEBUG, "index has sizes %"PRIu32" / %"PRIu32" / %"PRIu32" and %zu entries",
	      params_out->min_size, params_out->avg_size, params_out->max_size,
	      *n_entries_out);

	return 0;
}

int caibx_iterate_entries(int fd, struct chunker_params *params, size_t n_entries,
                          int (*cb)(uint64_t offset, uint32_t len, uint8_t *id, void *arg), void *arg)
{
	u_assert(fd >= 0);
	u_assert(params);
	u_assert(cb);

	uint64_t last_offset = 0;

	// seek to the start of table entries
	checked(lseek(fd, CA_HEADER_LEN + CA_TABLE_HEADER_LEN, SEEK_SET), return -1);

	for (size_t i = 0; i < n_entries; i++) {
		uint8_t buf[CA_TABLE_ENTRY_LEN];

		if (readall(fd, buf, CA_TABLE_ENTRY_LEN) < 0) {
			u_log(ERR, "reading entry %zu failed", i);
			return -1;
		}

		uint64_t offset = unp64le(&buf[0]);
		uint64_t len = offset - last_offset;

		char chunk_id[CHUNK_ID_STRLEN];

		// chunks other than the last one should not be shorter than
		// the minimum size
		if (len < params->min_size && (i+1) < n_entries) {
			chunk_format_id(chunk_id, &buf[8]);
			u_log(WARN, "chunk %s is too short: %"PRIu64" < %"PRIu32,
			      chunk_id, len, params->min_size);
		} else if (len > params->max_size) {
			chunk_format_id(chunk_id, &buf[8]);
			u_log(WARN, "chunk %s is too big : %"PRIu64" > %"PRIu32,
			      chunk_id, len, params->max_size);

			/* From a correctness perspecitve, we should skip all
			 * of the chunks that do not fit within the declared
			 * size bounds, as such chunks should not be produced
			 * by a conforming encoder. But if the chunk ID still
			 * matches in the end we should be fine. Only skip
			 * chunks that we cannot represent at all.
			 */
			if (len > UINT32_MAX) {
				u_log(WARN, "skipping chunk %s", chunk_id);
				continue;
			}
		}

		if (cb(last_offset, (uint32_t)len, &buf[8], arg) < 0)
			return -1;

		last_offset = offset;
	}

	return 0;
}
