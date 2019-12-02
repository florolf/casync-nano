#pragma once

#include <stdint.h>
#include <stddef.h>

#include "sha.h"
#include "utils.h"

#define CHUNK_ID_LEN 32
#define CHUNK_ID_STRLEN (2 * (CHUNK_ID_LEN) + 1)

void chunk_format_id(char *id_str, uint8_t *id);

static inline void chunk_calculate_id(uint8_t *data, size_t len, uint8_t *id_out)
{
	u_assert(sha_once(data, len, id_out) == 0);
}
