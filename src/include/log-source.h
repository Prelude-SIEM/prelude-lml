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
#include "regex.h"

typedef struct lml_log_format lml_log_format_t;
typedef struct lml_log_format_container lml_log_format_container_t;

/*
 * format
 */
lml_log_format_t *lml_log_format_container_get_format(lml_log_format_container_t *fc);

lml_log_format_t *lml_log_format_new(const char *name);

const char *lml_log_format_get_name(lml_log_format_t *lf);

int lml_log_format_set_prefix_regex(lml_log_format_t *ls, const char *regex);

const pcre *lml_log_format_get_prefix_regex(const lml_log_format_t *ls);

const pcre_extra *lml_log_format_get_prefix_regex_extra(const lml_log_format_t *ls);

int lml_log_format_set_ts_fmt(lml_log_format_t *lf, const char *fmt);

const char *lml_log_format_get_ts_fmt(const lml_log_format_t *ls);

/*
 *
 */
const char *lml_log_source_get_format(lml_log_source_t *ls);

const char *lml_log_source_get_source(lml_log_source_t *ls);

const char *lml_log_source_get_name(const lml_log_source_t *ls);

regex_list_t *lml_log_source_get_regex_list(lml_log_source_t *ls);

int lml_log_source_new(lml_log_source_t **ls, lml_log_format_t *format, const char *name);

void lml_log_source_destroy(lml_log_source_t *source);

int lml_log_source_set_name(lml_log_source_t *ls, const char *name);

void lml_log_source_warning(lml_log_source_t *ls, const char *fmt, ...);

prelude_list_t *lml_log_source_get_format_list(lml_log_source_t *source);

#endif
