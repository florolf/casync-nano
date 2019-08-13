#pragma once

#include <stdint.h>
#include <stddef.h>

#include "chunker.h"

int caibx_load_header(int fd, struct chunker_params *params_out, size_t *n_entries_out);

int caibx_iterate_entries(int fd, struct chunker_params *params, size_t n_entries,
                          int (*cb)(uint64_t offset, uint32_t len, uint8_t *id, void *arg), void *arg);
