#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "utils.h"

#include "chunk.h"

void chunk_format_id(char *id_str, const uint8_t *id)
{
	for (size_t i = 0; i < CHUNK_ID_LEN; i++)
		u_assert_se(sprintf(&id_str[2*i], "%02x", id[i]) == 2);
}
