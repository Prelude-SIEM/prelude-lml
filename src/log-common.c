#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <libprelude/prelude-log.h>
#include "log-common.h"



static int format_syslog_header(const char *buf, struct timeval *tv, char host[256], char tag[33]) 
{
        int ret, i;
        char month[4];
        int day, hour, minute, second;
        struct {
                const char *month;
                int value;
        } mtbl[] = {
                { "Jan", 1  },
                { "Feb", 2  },
                { "Mar", 3  },
                { "Apr", 4  },
                { "May", 5  },
                { "Jun", 6  },
                { "Jul", 7  },
                { "Aug", 8  },
                { "Sep", 9  },
                { "Oct", 10 },
                { "Nov", 11 },
                { "Dec", 12 },
        };
        
        ret = sscanf(buf, "%.3s %d %d:%d:%d %.255s %.32s", month, &day, &hour, &minute, &second, host, tag);
        if ( ret != 7 )
                /*
                 * Not syslog format.
                 */
                return -1;
        
        for ( i = 0; i < strlen(tag); i++ ) {
                
                if ( ! isalnum(tag[i]) ) {
                        tag[i] = '\0';
                        break;
                }
        }
        
        (*tv).tv_usec =  0;
        (*tv).tv_sec  =  day * (24 * 60 * 60);
        (*tv).tv_sec  += hour * (60 * 60);
        (*tv).tv_sec  += minute * 60;

        return 0;
}



log_container_t *log_container_new(const char *log, const char *from)
{
        int ret;
	log_container_t *lc;
        char host[256], tag[33];
        
        lc = malloc(sizeof(*lc));
	if ( ! lc ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        lc->log = strdup(log);
	lc->source = strdup(from);
        
        ret = format_syslog_header(log, &lc->tv, host, tag);
        if ( ret == 0 ) {
                lc->target_program = strdup(tag);
                lc->target_hostname = strdup(host);
        } else {
                lc->target_program = NULL;
                lc->target_hostname = NULL;
                gettimeofday(&lc->tv, NULL);
        }

	return lc;
}



void log_container_delete(log_container_t *lc)
{
        if ( lc->target_hostname )
                free(lc->target_hostname);

        if ( lc->target_program )
                free(lc->target_program);

        if ( lc->source )
                free(lc->source);
        
        free(lc->log);
	free(lc);
}
