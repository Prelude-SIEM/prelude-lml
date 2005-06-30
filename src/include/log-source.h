/*****
*
* Copyright (C) 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef LOG_COMMON_H
#define LOG_COMMON_H

#include <pcre.h>
#include <sys/time.h>


lml_log_source_t *lml_log_source_new(void);

void lml_log_source_destroy(lml_log_source_t *source);

const char *lml_log_source_get_format(lml_log_source_t *ls);

const char *lml_log_source_get_source(lml_log_source_t *ls);

const char *lml_log_source_get_name(const lml_log_source_t *ls);

int lml_log_source_set_name(lml_log_source_t *ls, const char *name);

int lml_log_source_set_prefix_regex(lml_log_source_t *ls, const char *regex);

int lml_log_source_set_ts_fmt(lml_log_source_t *lf, const char *fmt);

const char *lml_log_source_get_timestamp_format(const lml_log_source_t *ls);

const pcre *lml_log_source_get_prefix_regex(const lml_log_source_t *ls);

const pcre_extra *lml_log_source_get_prefix_regex_extra(const lml_log_source_t *ls);

void lml_log_source_set_warning_limit(lml_log_source_t *source, int limit);

void lml_log_source_warning(lml_log_source_t *ls, const char *fmt, ...);

#endif
