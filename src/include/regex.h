#ifndef REGEX_H
#define REGEX_H

#include <limits.h>
#include <pcre.h>

#define MAX_NAME_LEN     _POSIX_PATH_MAX
#define MAX_LINE_LEN     _POSIX2_LINE_MAX
#define MAX_OPTIONS_LEN  32

typedef struct regex_entry regex_entry_t;
typedef struct list_head regex_list_t;

regex_list_t *regex_init(char *filename);
void regex_destroy(regex_list_t * conf);
int regex_exec(regex_list_t *list, const char *str,
               void (*cb)(const char *name, void *data), void *data);

#endif				/* REGEX_H */
