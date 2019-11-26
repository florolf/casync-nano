#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "utils.h"

#include "ui.h"

#define PROGRESS_BAR_LEN 60

void show_progress(uint8_t percent, progess_status_t *status)
{
	static const char spinner[] = "-\\|//";
	char bar[PROGRESS_BAR_LEN + 1];

	u_assert(status);

	size_t tip = percent * PROGRESS_BAR_LEN / 100;
	for (size_t i = 0; i < PROGRESS_BAR_LEN; i++)
		bar[i] = (i < tip) ? '=' : ' ';

	bar[PROGRESS_BAR_LEN] = 0;

	printf("\033[0G[%c] |%s| %3d%%", spinner[(*status)++ % strlen(spinner)], bar, percent);

	if (percent == 100)
		putchar('\n');

	fflush(stdout);
}
