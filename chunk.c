#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <openssl/sha.h>
#include "utils.h"

#include "chunk.h"

void chunk_format_id(char *id_str, uint8_t *id)
{
	for (size_t i = 0; i < CHUNK_ID_LEN; i++)
		u_assert_se(sprintf(&id_str[2*i], "%02x", id[i]) == 2);
}

void chunk_calculate_id(uint8_t *data, size_t len, uint8_t *id_out)
{
	SHA256(data, len, id_out);
}
