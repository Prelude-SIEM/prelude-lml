#ifndef REGEX_H
#define REGEX_H

#include <limits.h>
#include <pcre.h>

typedef prelude_list_t regex_list_t;

regex_list_t *regex_init(const char *logfile);

void regex_destroy(regex_list_t *conf);

int regex_exec(regex_list_t *list,
               void (*cb)(void *plugin, void *data), void *data,
               const char *str, size_t len);

#endif				/* REGEX_H */
