/*****
*
* Copyright (C) 2003, 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
* All Rights Reserved
*
* This file is part of the Prelude program.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by 
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * glibc2 won't define strptime()
 * unless _XOPEN_SOURCE is defined.
 */
#include <time.h>


#include <libprelude/prelude-log.h>
#include "log-common.h"


/*
 * default log fmt.
 */
#define SYSLOG_TS_FMT "%b %d %H:%M:%S"
#define SYSLOG_LOG_FMT "%ltime %thost %tprog:"


static unsigned int global_id = 0;


struct log_source_s {
        
        unsigned int id;
        
        char *name;
        char *ts_fmt;
        char *log_fmt;
};



static int format_tstamp(log_source_t *ls, const char *log, char delim, void **out) 
{
        time_t now;
        struct tm *lt;
        const char *end;
        struct timeval *tv = *out;
        
        /*
         * We first get the localtime from this system,
         * so that all the struct tm member are filled.
         *
         * As syslog header doesn't contain a complete timestamp, this
         * avoid us some computation error.
         */
        now = time(NULL);
        
        lt = localtime(&now);
        if ( ! lt )
                goto err;

        /*
         * strptime() return a pointer to the first non matched character.
         */
        
        end = strptime(log, ls->ts_fmt, lt);
        if ( ! end ) 
                goto err;

        end = strchr(end, delim);
        if ( ! end ) {
                log(LOG_ERR, "couldn't find '%c' in %s\n", delim, end);
                return -1;
        }
        
        /*
         * convert back to a timeval.
         */
        tv->tv_usec = 0;
        tv->tv_sec = mktime(lt);
        
        return end - log;

 err:
        log(LOG_INFO, "couldn't format \"%s\" using \"%s\".\n", log, ls->ts_fmt);
        return -1;
}




static int format_common(log_source_t *ls, const char *log, char delim, void **out) 
{
        char *ptr, tmp;
                
        ptr = strchr(log, delim);        
        if ( ! ptr ) {
                log(LOG_ERR, "couldn't find '%c' in %s\n", delim, log);
                return -1;
        }

        tmp = *ptr;
        *ptr = '\0';
                
        if ( *out )
                free(*out);

        *out = strdup(log);
        *ptr = tmp;
        
        return ptr - log;
}




static int handle_escaped(log_entry_t *lc, const char *fmt, const char **log)
{
        int i, ret, len;
        void *tv = &lc->tv;
        struct {
                const char *name;
                int (*cb)(log_source_t *ls, const char *log, char delim, void **out);
                void **ptr;
        } tbl[] = {
                { "tprog", format_common, (void **) &lc->target_program  },
                { "thost", format_common, (void **) &lc->target_hostname },
                { "tuser", format_common, (void **) &lc->target_user     },
                { "ltime", format_tstamp, (void **) &tv                  },
                { NULL, NULL                                             },
        };

        for ( i = 0; tbl[i].name != NULL; i++ ) {
                len = strlen(tbl[i].name);
                
                ret = strncmp(fmt, tbl[i].name, len);
                if ( ret != 0 )
                        continue;

                ret = tbl[i].cb(lc->source, *log, fmt[len], tbl[i].ptr);
                if ( ret < 0 )
                        return -1;
                
                *log += ret;
                return len + 1;
        }

        log(LOG_ERR, "unknown tag: %%%s.\n", fmt);
        
        return -1;
} 





static int format_header(log_entry_t *lc, const char *log)
{
        int ret = 0;
        const char *fmt = lc->source->log_fmt;
        
        while ( *fmt ) {
                
                if ( *fmt == '%' && ((*fmt + 1) != '%' || *(fmt + 1) != '\0') ) {
                        ret = handle_escaped(lc, fmt + 1, &log);
                        if ( ret < 0 )
                                return -1;

                        fmt += ret;
                }
                
                else if ( *fmt != *log ) {
                        log(LOG_ERR, "couldn't match %s != %s.\n", fmt, log);
                        break;                
                }

                else {
                        fmt++;
                        log++;
                }
        }
        

        return ret;
}



static int format_log(log_entry_t *lc)
{
        int ret;
        char *entry = lc->log;

        ret = format_header(lc, entry);
        /*
         * don't return on error, a syslog header might not have a tag.
         */

        return 0;
}




static char *get_hostname(void) 
{
        int ret;
        char out[256];
                
        ret = gethostname(out, sizeof(out));
        if ( ret < 0 )
                return NULL;
        
        return strdup(out);
}




log_entry_t *log_entry_new(log_source_t *source)
{
        log_entry_t *lc;

        lc = calloc(1, sizeof(*lc));
        if ( ! lc ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        lc->source = source;
        gettimeofday(&lc->tv, NULL);

        /*
         * default hostname is our.
         */
        lc->target_hostname = get_hostname();
        
        return lc;
}




int log_entry_set_log(log_entry_t *lc, const char *entry) 
{
        int ret;
        
        lc->log = strdup(entry);
        if ( ! lc->log ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        ret = format_log(lc);
        if ( ret < 0 ) {
                gettimeofday(&lc->tv, NULL);
                return 0;
        }
                
        return 0;
}




void log_entry_delete(log_entry_t *lc)
{
        if ( lc->target_hostname )
                free(lc->target_hostname);

        if ( lc->target_program )
                free(lc->target_program);

        if ( lc->target_user )
                free(lc->target_user);

        if ( lc->log )
                free(lc->log);
        
	free(lc);
}




int log_source_set_name(log_source_t *ls, const char *name) 
{
        if ( ls->name )
                free(ls->name);
        
        ls->name = strdup(name);
        if ( ! ls->name ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        ls->id = global_id++;
        
        return 0;
}



log_source_t *log_source_new(void)
{
        log_source_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->ts_fmt = strdup(SYSLOG_TS_FMT);
        new->log_fmt = strdup(SYSLOG_LOG_FMT);
        
        return new;
}




const char *log_source_get_name(log_source_t *ls)
{        
        return ls->name;
}



int log_source_set_log_fmt(log_source_t *ls, const char *fmt)
{       
        if ( ls->log_fmt )
                free(ls->log_fmt);
        
        ls->log_fmt = strdup(fmt);
        if ( ! ls->log_fmt ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        return 0;
}




int log_source_set_timestamp_fmt(log_source_t *ls, const char *fmt)
{        
        if ( ls->ts_fmt )
                free(ls->ts_fmt);
        
        ls->ts_fmt = strdup(fmt);
        if ( ! ls->ts_fmt ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        return 0;
}



void log_source_destroy(log_source_t *source)
{
        if ( source->name )
                free(source->name);
        
        if ( source->ts_fmt )
                free(source->ts_fmt);
        
        if ( source->log_fmt )
                free(source->log_fmt);
        
        free(source);
}
