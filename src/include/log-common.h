/*****
*
* Copyright (C) 2002 - 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#ifndef LOG_COMMON_H
#define LOG_COMMON_H

#include <sys/time.h>

typedef struct log_source_s log_source_t;


typedef struct {
        char *original_log;
        size_t original_log_len;
        
        char *message;
        size_t message_len;

        struct timeval tv;

        char *target_hostname;
        char *target_process;
        char *target_process_pid;

        log_source_t *source;
} log_entry_t;



log_entry_t *log_entry_new(log_source_t *source);

int log_entry_set_log(log_entry_t *lc, const char *entry, size_t size);

void log_entry_delete(log_entry_t *lc);


log_source_t *log_source_new(void);

void log_source_destroy(log_source_t *source);

const char *log_source_get_format(log_source_t *ls);

const char *log_source_get_source(log_source_t *ls);

const char *log_source_get_name(log_source_t *ls);

int log_source_set_name(log_source_t *ls, const char *name);

int log_source_set_prefix_regex(log_source_t *ls, const char *regex);

int log_source_set_ts_fmt(log_source_t *lf, const char *fmt);

#endif
