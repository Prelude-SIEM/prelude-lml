#ifndef LOG_COMMON_H
#define LOG_COMMON_H


typedef struct log_file_s log_file_t;


typedef struct {
        char *log;
	char *source;
        
        struct timeval tv;
        
        char *target_program;
        char *target_hostname;
} log_container_t;



log_container_t *log_container_new(void);

int log_container_set_log(log_file_t *lf, log_container_t *lc, const char *entry);

int log_container_set_source(log_container_t *lc, const char *source);

void log_container_delete(log_container_t * lc);


log_file_t *log_file_new(void);

const char *log_file_get_format(log_file_t *lf);

const char *log_file_get_filename(log_file_t *lf);


int log_file_set_filename(log_file_t *lf, const char *filename);

int log_file_set_log_fmt(log_file_t *lf, const char *fmt);

int log_file_set_timestamp_fmt(log_file_t *lf, const char *fmt);

#endif
