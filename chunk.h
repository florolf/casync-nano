#pragma once

#include <stdint.h>
#include <stddef.h>

#define CHUNK_ID_LEN 32
#define CHUNK_ID_STRLEN (2 * (CHUNK_ID_LEN) + 1)

void chunk_format_id(char *id_str, uint8_t *id);
void chunk_calculate_id(uint8_t *data, size_t len, uint8_t *id_out);
