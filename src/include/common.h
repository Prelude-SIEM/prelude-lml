#ifndef COMMON_H
#define COMMON_H

#ifdef DEBUG
#define dprint(args...)		fprintf( stderr, args )
#else				/* DEBUG */
#define dprint(args...)
#endif				/* DEBUG */

#endif				/* COMMON_H */
