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

#include <pcre.h>

#include <libprelude/prelude-log.h>
#include "log-common.h"


/*
 * default log fmt.
 */
#define SYSLOG_TS_FMT "%b %d %H:%M:%S"
#define SYSLOG_PREFIX_REGEX "^(?P<timestamp>.{15}) (?P<hostname>\\S+) (?:((?P<process>\\S+)(\\[(?P<pid>[0-9]+)\\])?)?: )?"



struct log_source_s {
        unsigned int id;
        
        char *name;
        char *ts_fmt;
        pcre *prefix_regex;
        pcre_extra *prefix_regex_extra;
};


static unsigned int global_id = 0;




static int parse_ts(log_source_t *ls, const char *string, void **out) 
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
        
        end = strptime(string, ls->ts_fmt, lt);
        if ( ! end ) 
                goto err;

        /*
         * convert back to a timeval.
         */
        tv->tv_usec = 0;
        tv->tv_sec = mktime(lt);

        return 0;

 err:
        log(LOG_INFO, "couldn't format \"%s\" using \"%s\".\n", string, ls->ts_fmt);
        return -1;
}



static int parse_prefix(log_entry_t *log_entry)
{
        char *string;
        int ovector[5 * 3];
        int i, ret, matches = 0;
        void *tv = &log_entry->tv;
        struct {
                const char *field;
                int (*cb)(log_source_t *ls, const char *log, void **out);
                void **ptr;
        } tbl[] = {
                { "hostname",  NULL,     (void **) &log_entry->target_hostname    },
                { "process",   NULL,     (void **) &log_entry->target_process     },
                { "pid",       NULL,     (void **) &log_entry->target_process_pid },
                { "timestamp", parse_ts, (void **) &tv                            },
                { NULL, NULL, NULL                                                },
        };

        matches = pcre_exec(log_entry->source->prefix_regex, log_entry->source->prefix_regex_extra,
                            log_entry->log, log_entry->log_len, 0, 0, ovector, sizeof(ovector) / sizeof(int));
        
        if ( matches < 0 ) {
                log(LOG_ERR, "couldn't match log_prefix_regex against log entry: %s.\n", log_entry->log);
                return -1;
        }

        for ( i = 0; tbl[i].field != NULL; i++ ) {
                ret = pcre_get_named_substring(log_entry->source->prefix_regex, log_entry->log,
                                               ovector, matches, tbl[i].field, (const char **) &string);
                
                if ( ret == PCRE_ERROR_NOSUBSTRING )
                        continue;

                else if ( ret < 0 ) {
                        log(LOG_ERR, "could not get referenced string: %d.\n", ret);
                        return -1;
                }
                
                if ( ! tbl[i].cb )
                        *tbl[i].ptr = string;
                
                else {
                        ret = tbl[i].cb(log_entry->source, string, tbl[i].ptr);
                        free(string);
                        
                        if ( ret < 0 ) {
                                log(LOG_ERR, "failed to parse prefix field: %s.\n", tbl[i].field);
                                return -1;
                        }
                }
        }

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
        log_entry_t *log_entry;

        log_entry = calloc(1, sizeof(*log_entry));
        if ( ! log_entry ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        log_entry->source = source;
        gettimeofday(&log_entry->tv, NULL);
        
        return log_entry;
}




int log_entry_set_log(log_entry_t *log_entry, const char *entry, size_t size) 
{
        int ret;
        
        log_entry->log_len = size;
        
        log_entry->log = strdup(entry);
        if ( ! log_entry->log ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        ret = parse_prefix(log_entry);
        
        if ( ! log_entry->target_hostname )
                log_entry->target_hostname = get_hostname();
        
        if ( ret < 0 ) {
                log(LOG_ERR, "failed to parse log message prefix.\n");
                gettimeofday(&log_entry->tv, NULL);
                return -1;
        }
        
        return 0;
}




void log_entry_delete(log_entry_t *log_entry)
{
        if ( log_entry->target_hostname )
                free(log_entry->target_hostname);

        if ( log_entry->target_process )
                free(log_entry->target_process);

        if ( log_entry->target_process_pid )
                free(log_entry->target_process_pid);

        if ( log_entry->log )
                free(log_entry->log);
        
        free(log_entry);
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

        if ( log_source_set_ts_fmt(new, SYSLOG_TS_FMT) < 0 ) {
                log(LOG_ERR, "failed to set log timestamp format.\n");
                return NULL;
        }

        if ( log_source_set_prefix_regex(new, SYSLOG_PREFIX_REGEX) < 0 ) {
                log(LOG_ERR, "failed to set log message prefix.\n");
                return NULL;
        }

        return new;
}




const char *log_source_get_name(log_source_t *ls)
{        
        return ls->name;
}



int log_source_set_prefix_regex(log_source_t *ls, const char *regex)
{       
        int erroffset;
        const char *errptr;

        if ( ls->prefix_regex )
                free(ls->prefix_regex);
        
        ls->prefix_regex = pcre_compile(regex, 0, &errptr, &erroffset, NULL);
        if ( ! ls->prefix_regex ) {
                log(LOG_ERR, "Unable to compile regex: %s : %s.\n", regex, errptr);
                return -1;
        }

        ls->prefix_regex_extra = pcre_study(ls->prefix_regex, 0, &errptr);
        if ( ! ls->prefix_regex_extra && errptr ) {
                log(LOG_ERR, "Unable to study regex: %s : %s.\n", regex, errptr);
                return -1;
        }

        return 0;
}




int log_source_set_ts_fmt(log_source_t *ls, const char *fmt)
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
        
        if ( source->prefix_regex)
                free(source->prefix_regex);

        if ( source->prefix_regex_extra)
                free(source->prefix_regex_extra);
        
        free(source);
}
