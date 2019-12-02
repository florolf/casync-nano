#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "sha.h"
#include "utils.h"
#include "xorshift32.h"

static int kcapi_create(void **state)
{
	(void) state;

	assert_int_equal(sha_kcapi_init(NULL), 0);

	return 0;
}

static int kcapi_destroy(void **state)
{
	(void) state;

	sha_kcapi_deinit();

	return 0;
}

static void test_empty(void **state)
{
	(void) state;

	uint8_t md[SHA_LEN];
	assert_int_equal(sha_once(md /*dummy*/, 0, md), 0);

	uint8_t md_target[SHA_LEN] = {
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
	};

	assert_memory_equal(md, md_target, SHA_LEN);
}

static void test_short(void **state)
{
	(void) state;

	const char *input = "hello, world";

	uint8_t md[SHA_LEN];
	assert_int_equal(sha_once((const uint8_t*)input, strlen(input), md), 0);

	uint8_t md_target[SHA_LEN] = {
		0x09, 0xca, 0x7e, 0x4e, 0xaa, 0x6e, 0x8a, 0xe9,
		0xc7, 0xd2, 0x61, 0x16, 0x71, 0x29, 0x18, 0x48,
		0x83, 0x64, 0x4d, 0x07, 0xdf, 0xba, 0x7c, 0xbf,
		0xbc, 0x4c, 0x8a, 0x2e, 0x08, 0x36, 0x0d, 0x5b,
	};

	assert_memory_equal(md, md_target, SHA_LEN);
}

static void test_multi(void **state)
{
	(void) state;

	const char *input = "hello, world";

	uint8_t md[SHA_LEN];
	assert_int_equal(sha_once((const uint8_t*)input, strlen(input), md), 0);

	uint8_t md_target[SHA_LEN] = {
		0x09, 0xca, 0x7e, 0x4e, 0xaa, 0x6e, 0x8a, 0xe9,
		0xc7, 0xd2, 0x61, 0x16, 0x71, 0x29, 0x18, 0x48,
		0x83, 0x64, 0x4d, 0x07, 0xdf, 0xba, 0x7c, 0xbf,
		0xbc, 0x4c, 0x8a, 0x2e, 0x08, 0x36, 0x0d, 0x5b,
	};

	assert_memory_equal(md, md_target, SHA_LEN);

	const char *input2 = "another test string with the same kcapi context";
	assert_int_equal(sha_once((const uint8_t*)input2, strlen(input2), md), 0);

	uint8_t md_target2[SHA_LEN] = {
		0xa7, 0x75, 0xb2, 0x86, 0x71, 0xcc, 0x31, 0x6a,
		0xa8, 0xf2, 0x11, 0x58, 0xcb, 0x4d, 0x5e, 0xec,
		0xdc, 0x49, 0xe4, 0x5f, 0xf3, 0xd3, 0xd7, 0x15,
		0x2e, 0xf1, 0x95, 0x0c, 0xef, 0xde, 0xae, 0x80,
	};

	assert_memory_equal(md, md_target2, SHA_LEN);
}

static void test_long(void **state)
{
	(void) state;

	static uint8_t input[128 * 1024];
	struct xorshift32_state rng = XORSHIFT32_INIT(0xaffed00f);
	xorshift32_fill(&rng, input, sizeof(input));

	uint8_t md[SHA_LEN];
	assert_int_equal(sha_once((const uint8_t*)input, sizeof(input), md), 0);

	uint8_t md_target[SHA_LEN] = {
		0xb3, 0x6a, 0x30, 0xca, 0x5b, 0x22, 0xf4, 0x30,
		0x1a, 0x0e, 0x95, 0xf9, 0xe4, 0x13, 0x10, 0x98,
		0x7e, 0xa3, 0xb0, 0xa6, 0xd2, 0x66, 0xee, 0x61,
		0x13, 0x80, 0x19, 0xd0, 0x31, 0xff, 0x2b, 0xd3
	};

	assert_memory_equal(md, md_target, SHA_LEN);
}

int main(void)
{
	const struct CMUnitTest openssl_tests[] = {
		// test userspace crypto mode by not initializing kcapi
		cmocka_unit_test(test_empty),
	};

	const struct CMUnitTest kcapi_tests[] = {
		cmocka_unit_test_setup_teardown(test_empty, kcapi_create, kcapi_destroy),
		cmocka_unit_test_setup_teardown(test_short, kcapi_create, kcapi_destroy),
		cmocka_unit_test_setup_teardown(test_multi, kcapi_create, kcapi_destroy),
		cmocka_unit_test_setup_teardown(test_long, kcapi_create, kcapi_destroy),
	};

	u_log_init();

	int ret;
	ret = cmocka_run_group_tests_name("openssl", openssl_tests, NULL, NULL);
	if (ret)
		return ret;

	ret = cmocka_run_group_tests_name("kcapi", kcapi_tests, NULL, NULL);
	if (ret)
		return ret;
}
