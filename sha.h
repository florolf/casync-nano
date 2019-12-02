#pragma once

#include <stdint.h>
#include <stddef.h>

#define SHA_LEN 32

int sha_kcapi_init(const char *driver);
void sha_kcapi_deinit(void);
int sha_once(const uint8_t *data, size_t len, uint8_t *out);
