/*****
*
* Copyright (C) 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-LML program.
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

#include "prelude-lml.h"
#include "log-entry.h"
#include "prelude-lml.h"

/*
 * default log fmt.
 */
#define SYSLOG_TS_FMT "%b %d %H:%M:%S"
#define SYSLOG_PREFIX_REGEX "^(?P<timestamp>.{15}) (?P<hostname>\\S+) (?:((?P<process>\\S+)(\\[(?P<pid>[0-9]+)\\])?)?: )?"



struct lml_log_entry {
        char *original_log;
        size_t original_log_len;
        
        char *message;
        size_t message_len;

        struct timeval tv;

        char *target_hostname;
        char *target_process;
        char *target_process_pid;
};


static int parse_ts(lml_log_source_t *ls, const char *string, void **out) 
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
        
        end = strptime(string, lml_log_source_get_timestamp_format(ls), lt);
        if ( ! end ) 
                goto err;

        /*
         * convert back to a timeval.
         */
        tv->tv_usec = 0;
        tv->tv_sec = mktime(lt);

        return 0;

 err:
        prelude_log(PRELUDE_LOG_WARN, "couldn't format \"%s\" using \"%s\".\n",
                    string, lml_log_source_get_timestamp_format(ls));
        return -1;
}



static int parse_prefix(lml_log_source_t *ls, lml_log_entry_t *log_entry)
{
        char *string;
        int ovector[5 * 3];
        int i, ret, matches = 0;
        void *tv = &log_entry->tv;
        struct {
                const char *field;
                int (*cb)(lml_log_source_t *ls, const char *log, void **out);
                void **ptr;
        } tbl[] = {
                { "hostname",  NULL,     (void **) &log_entry->target_hostname    },
                { "process",   NULL,     (void **) &log_entry->target_process     },
                { "pid",       NULL,     (void **) &log_entry->target_process_pid },
                { "timestamp", parse_ts, (void **) &tv                            },
                { NULL, NULL, NULL                                                },
        };

        matches = pcre_exec(lml_log_source_get_prefix_regex(ls), lml_log_source_get_prefix_regex_extra(ls),
                            log_entry->original_log, log_entry->original_log_len, 0, 0, ovector,
                            sizeof(ovector) / sizeof(int));
        
        if ( matches < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "couldn't match log_prefix_regex against log entry: %s.\n",
                            log_entry->original_log);
                return -1;
        }

        for ( i = 0; tbl[i].field != NULL; i++ ) {
                ret = pcre_get_named_substring(lml_log_source_get_prefix_regex(ls), log_entry->original_log,
                                               ovector, matches, tbl[i].field, (const char **) &string);
                
                if ( ret == PCRE_ERROR_NOSUBSTRING )
                        continue;

                else if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_WARN, "could not get referenced string: %d.\n", ret);
                        return -1;
                }
                
                if ( ! tbl[i].cb )
                        *tbl[i].ptr = string;
                
                else {
                        ret = tbl[i].cb(ls, string, tbl[i].ptr);
                        free(string);
                        
                        if ( ret < 0 ) {
                                prelude_log(PRELUDE_LOG_WARN, "failed to parse prefix field: %s.\n", tbl[i].field);
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



const struct timeval *lml_log_entry_get_timeval(const lml_log_entry_t *log_entry)
{
        return &log_entry->tv;
}



const char *lml_log_entry_get_original_log(const lml_log_entry_t *log_entry)
{
        return log_entry->original_log;
}


size_t lml_log_entry_get_original_log_len(const lml_log_entry_t *log_entry)
{
        return log_entry->original_log_len;
}


const char *lml_log_entry_get_message(const lml_log_entry_t *log_entry)
{
        return log_entry->message;
}


size_t lml_log_entry_get_message_len(const lml_log_entry_t *log_entry)
{
        return log_entry->message_len;
}


const char *lml_log_entry_get_target_process(const lml_log_entry_t *log_entry)
{
        return log_entry->target_process;
}


const char *lml_log_entry_get_target_process_pid(const lml_log_entry_t *log_entry)
{
        return log_entry->target_process_pid;
}


const char *lml_log_entry_get_target_hostname(const lml_log_entry_t *log_entry)
{
        return log_entry->target_hostname;
}


lml_log_entry_t *lml_log_entry_new(void)
{
        lml_log_entry_t *log_entry;

        log_entry = calloc(1, sizeof(*log_entry));
        if ( ! log_entry ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        gettimeofday(&log_entry->tv, NULL);
        
        return log_entry;
}




int lml_log_entry_set_log(lml_log_entry_t *log_entry, lml_log_source_t *ls, const char *entry, size_t size) 
{
        int ret;
        
        log_entry->original_log_len = size;
        
        log_entry->original_log = strdup(entry);
        if ( ! log_entry->original_log ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        log_entry->message = log_entry->original_log;
        log_entry->message_len = log_entry->original_log_len;
        
        ret = parse_prefix(ls, log_entry);
        
        if ( ! log_entry->target_hostname )
                log_entry->target_hostname = get_hostname();
        
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "failed to parse log message prefix.\n");
                gettimeofday(&log_entry->tv, NULL);
                return -1;
        }
        
        return 0;
}




void lml_log_entry_destroy(lml_log_entry_t *log_entry)
{
        if ( log_entry->target_hostname )
                free(log_entry->target_hostname);

        if ( log_entry->target_process )
                free(log_entry->target_process);

        if ( log_entry->target_process_pid )
                free(log_entry->target_process_pid);

        if ( log_entry->original_log )
                free(log_entry->original_log);
        
        free(log_entry);
}
