#pragma once

#include <stdint.h>

#define PROGRESS_STATUS_INIT ((progess_status_t)0)
typedef uint32_t progess_status_t;
void show_progress(uint8_t percent, progess_status_t *status);
