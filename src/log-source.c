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

#include "prelude-lml.h"
#include "log-source.h"


/*
 * default log fmt.
 */
#define SYSLOG_TS_FMT "%b %d %H:%M:%S"
#define SYSLOG_PREFIX_REGEX "^(?P<timestamp>.{15}) (?P<hostname>\\S+) (?:((?P<process>\\S+)(\\[(?P<pid>[0-9]+)\\])?)?: )?"




struct lml_log_source {        
        char *name;
        char *ts_fmt;
        pcre *prefix_regex;
        pcre_extra *prefix_regex_extra;
};



int lml_log_source_set_name(lml_log_source_t *ls, const char *name) 
{
        if ( ls->name )
                free(ls->name);
        
        ls->name = strdup(name);
        if ( ! ls->name ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        return 0;
}



lml_log_source_t *lml_log_source_new(void)
{
        lml_log_source_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        if ( lml_log_source_set_ts_fmt(new, SYSLOG_TS_FMT) < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "failed to set log timestamp format.\n");
                return NULL;
        }

        if ( lml_log_source_set_prefix_regex(new, SYSLOG_PREFIX_REGEX) < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "failed to set log message prefix.\n");
                return NULL;
        }

        return new;
}




const char *lml_log_source_get_name(const lml_log_source_t *ls)
{        
        return ls->name;
}



int lml_log_source_set_prefix_regex(lml_log_source_t *ls, const char *regex)
{       
        int erroffset;
        const char *errptr;

        if ( ls->prefix_regex )
                free(ls->prefix_regex);
        
        ls->prefix_regex = pcre_compile(regex, 0, &errptr, &erroffset, NULL);
        if ( ! ls->prefix_regex ) {
                prelude_log(PRELUDE_LOG_WARN, "Unable to compile regex: %s : %s.\n", regex, errptr);
                return -1;
        }

        ls->prefix_regex_extra = pcre_study(ls->prefix_regex, 0, &errptr);
        if ( ! ls->prefix_regex_extra && errptr ) {
                prelude_log(PRELUDE_LOG_WARN, "Unable to study regex: %s : %s.\n", regex, errptr);
                return -1;
        }

        return 0;
}




int lml_log_source_set_ts_fmt(lml_log_source_t *ls, const char *fmt)
{        
        if ( ls->ts_fmt )
                free(ls->ts_fmt);
        
        ls->ts_fmt = strdup(fmt);
        if ( ! ls->ts_fmt ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        return 0;
}



void lml_log_source_destroy(lml_log_source_t *source)
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



const char *lml_log_source_get_timestamp_format(const lml_log_source_t *source)
{
        return source->ts_fmt;
}



const pcre *lml_log_source_get_prefix_regex(const lml_log_source_t *source)
{
        return source->prefix_regex;
}


const pcre_extra *lml_log_source_get_prefix_regex_extra(const lml_log_source_t *source)
{
        return source->prefix_regex_extra;
}
