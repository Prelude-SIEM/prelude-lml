#ifndef COMMON_H
#define COMMON_H

#include "regex.h"
#include "log-common.h"

void lml_dispatch_log(regex_list_t *list, log_source_t *ls, const char *str, size_t size);


#ifdef DEBUG
#define dprint(args...)		fprintf( stderr, args )
#else				/* DEBUG */
#define dprint(args...)
#endif				/* DEBUG */

#endif				/* COMMON_H */
