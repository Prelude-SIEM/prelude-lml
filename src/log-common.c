#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "log-common.h"

log_container_t *log_container_new(char *log, char *from, struct tm *time)
{
	log_container_t *lc = malloc(sizeof(*lc));
	assert(lc);

	lc->source = strdup(from);
	lc->log = strdup(log);
	memcpy(&lc->time_received, time, sizeof(struct tm));
	return lc;
}

void log_container_delete(log_container_t * lc)
{
	free(lc->source);
	free(lc->log);
	free(lc);
}
