#ifndef COMMON_H
#define COMMON_H

#include "regex.h"
#include "queue.h"

void lml_dispatch_log(regex_list_t *list, lml_queue_t *queue, const char *str, const char *from);


#ifdef DEBUG
#define dprint(args...)		fprintf( stderr, args )
#else				/* DEBUG */
#define dprint(args...)
#endif				/* DEBUG */

#endif				/* COMMON_H */
