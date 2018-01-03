/*****
*
* Copyright (C) 2003-2018 CS-SI. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#ifndef _LOG_ENTRY_H
#define _LOG_ENTRY_H

#include "prelude-lml.h"
#include "log-source.h"

lml_log_entry_t *lml_log_entry_new(void);

int lml_log_entry_set_log(lml_log_entry_t *lc, lml_log_source_t *ls, char *entry, size_t size);

const lml_log_format_t *lml_log_entry_get_format(const lml_log_entry_t *log);

#endif /* _LOG_ENTRY_H */
