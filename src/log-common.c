#define _XOPEN_SOURCE 600

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
        char *log;
        int ret, i;
        time_t now;
        struct tm localtime;

        /*
         * We first get the localtime from this system,
         * so that all the struct tm member are filled.
         *
         * As syslog header doesn't contain a complete timestamp, this
         * avoid us some computation error.
         */
        now = time(NULL);
        if ( ! localtime_r(&now, &localtime) ) {
                log(LOG_ERR, "couldn't get local time.\n");
                return -1;
        }

        /*
         * Now, let's format the timestamp provided in the syslog message.
         * strptime() return a pointer to the first non matched character.
         */
        log = strptime(buf, "%b %d %H:%M:%S", &localtime);
        if ( ! log ) {
                log(LOG_ERR, "there was an error trying to parse syslog date.\n");
                return -1;
        }
        
        ret = sscanf(log, "%255s %32s", host, tag);
        if ( ret != 2 ) {
                log(LOG_ERR, "unknown format : \"%s\".\n", log);
                return -1;
        }

        /*
         * the tag end as soon as we meet a non alpha numeric character.
         */
        for ( i = 0; i < strlen(tag); i++ ) {
                
                if ( ! isalnum(tag[i]) ) {
                        tag[i] = '\0';
                        break;
                }
        }

        /*
         * convert back to a timeval.
         */
        (*tv).tv_usec = 0;
        (*tv).tv_sec = mktime(&localtime);

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
