#ifndef LOG_COMMON_H
#define LOG_COMMON_H

typedef struct {
        char *log;
	char *source;
        
        struct timeval tv;
        
        char *target_program;
        char *target_hostname;
} log_container_t;

log_container_t *log_container_new(const char *log, const char *from);
void log_container_delete(log_container_t * lc);

#endif				/* LOG_COMMON_H */
