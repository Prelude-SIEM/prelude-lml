/*****
*
* Copyright (C) 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _PRELUDE_LML_H
#define _PRELUDE_LML_H

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>

typedef struct lml_log_entry lml_log_entry_t;
typedef struct lml_log_source lml_log_source_t;


typedef struct {
        PRELUDE_PLUGIN_GENERIC;
        void (*run)(prelude_plugin_instance_t *pi, const lml_log_source_t *ls, lml_log_entry_t *log);
} lml_log_plugin_t;


void lml_log_entry_destroy(lml_log_entry_t *lc);

lml_log_entry_t *lml_log_entry_ref(lml_log_entry_t *log_entry);


const char *lml_log_entry_get_message(const lml_log_entry_t *log_entry);

const char *lml_log_entry_get_original_log(const lml_log_entry_t *log_entry);

size_t lml_log_entry_get_message_len(const lml_log_entry_t *log_entry);

size_t lml_log_entry_get_original_log_len(const lml_log_entry_t *log_entry);

const struct timeval *lml_log_entry_get_timeval(const lml_log_entry_t *log_entry);

const char *lml_log_entry_get_target_hostname(const lml_log_entry_t *log_entry);

const char *lml_log_entry_get_target_process(const lml_log_entry_t *log_entry);

const char *lml_log_entry_get_target_process_pid(const lml_log_entry_t *log_entry);


/*
 * Alert emission
 */
void lml_alert_emit(const lml_log_source_t *ls, const lml_log_entry_t *log, idmef_message_t *msg);

int lml_alert_prepare(idmef_message_t *message, const lml_log_source_t *ls, const lml_log_entry_t *log);

#endif
