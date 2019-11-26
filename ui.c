#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "utils.h"

#include "ui.h"

void show_progress(uint8_t percent, progess_status_t *status)
{
	static const char spinner[] = "-\\|//";

	u_assert(status);

	printf("\033[0G[%c] %3d%%", spinner[(*status)++ % strlen(spinner)], percent);

	if (percent == 100)
		putchar('\n');

	fflush(stdout);
}
