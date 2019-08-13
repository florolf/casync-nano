#pragma once

#include <stdint.h>

#include "store.h"
#include "chunker.h"

struct store *store_local_new(const char *path, const char *index, struct chunker_params *params);
