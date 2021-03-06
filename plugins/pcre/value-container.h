/*****
*
* Copyright (C) 2006-2020 CS GROUP - France. All Rights Reserved.
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

#ifndef VALUE_CONTAINER_H
#define VALUE_CONTAINER_H

typedef struct value_container value_container_t;

int value_container_new(value_container_t **vcont, const char *str);

void value_container_destroy(value_container_t *vcont);

void *value_container_get_data(value_container_t *vcont);

void value_container_set_data(value_container_t *vcont, void *data);

prelude_string_t *value_container_resolve(value_container_t *vcont, const pcre_rule_t *rule,
                                          const lml_log_entry_t *lentry, int *ovector, size_t osize);

#endif
