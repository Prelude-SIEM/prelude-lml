#ifndef REGEX_H
#define REGEX_H

#include <limits.h>
#include <pcre.h>

typedef prelude_list_t regex_list_t;

regex_list_t *regex_init(char *filename);

void regex_destroy(regex_list_t *conf);

int regex_exec(regex_list_t *list, const char *str,
               void (*cb)(void *plugin, void *data), void *data);

#endif				/* REGEX_H */
