#ifndef LOG_COMMON_H
#define LOG_COMMON_H

#include <time.h>

typedef struct {
	char *source;
	struct tm time_received;
	char *log;
} log_container_t;

log_container_t *log_container_new(char *log, char *from, struct tm *time);
void log_container_delete(log_container_t * lc);

#endif				/* LOG_COMMON_H */
