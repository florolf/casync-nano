#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <errno.h>

#include <openssl/sha.h>
#include "utils.h"

#include "sha.h"

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

static int kcapi_fd = -1;

int sha_kcapi_init(const char *driver)
{
	int alg_fd;

	alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (alg_fd < 0) {
		u_log_errno("creating AF_ALG socket failed");
		return -1;
	}

	if (!driver)
		driver = "sha256";

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};

	if (strlen(driver) >= sizeof(sa.salg_name)) {
		u_log(ERR, "driver name too long");
		goto err_algfd;
	}

	// Use strncpy to silence warnings. We've already checked that the
	// string will fit.
	strncpy((char*)sa.salg_name, driver, sizeof(sa.salg_name));

	if (bind(alg_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		u_log_errno("binding to AF_ALG socket failed");
		goto err_algfd;
	}

	int fd;
	fd = accept(alg_fd, NULL, 0);
	if (fd < 0) {
		u_log_errno("accepting hash instance socket failed");
		goto err_algfd;
	}

	kcapi_fd = fd;
	close(alg_fd);

	return 0;

err_algfd:
	close(alg_fd);
	return -1;
}

void sha_kcapi_deinit(void)
{
	if (kcapi_fd < 0)
		return;

	close(kcapi_fd);
	kcapi_fd = -1;
}

int sha_once(const uint8_t *data, size_t len, uint8_t *out)
{
	if (kcapi_fd < 0)
		return (SHA256(data, len, out) != NULL) ? 0 : -1;

	while (len) {
		ssize_t ret;

		ret = send(kcapi_fd, data, len, MSG_MORE);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			u_log_errno("send to kcapi failed");
			goto disable;
		}

		data += ret;
		len -= ret;
	}

	ssize_t ret;
retry:
	ret = recv(kcapi_fd, out, SHA_LEN, 0);
	if (ret < 0) {
		if (errno == EINTR)
			goto retry;

		u_log_errno("recv from kcapi failed");
		goto disable;
	} else if (ret != SHA_LEN) {
		u_log(ERR, "received unexpected number of bytes: %zd", ret);
		goto disable;
	}

	return 0;

disable:
	u_log(ERR, "kcapi operation failed, disabling");
	sha_kcapi_deinit();

	// fall back to openssl
	return (SHA256(data, len, out) != NULL) ? 0 : -1;
}
