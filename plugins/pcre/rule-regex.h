/*****
*
* Copyright (C) 1998-2012 CS-SI. All Rights Reserved.
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

typedef struct rule_regex rule_regex_t;

void rule_regex_destroy(rule_regex_t *ptr);

rule_regex_t *rule_regex_new(const char *regex, prelude_bool_t optionnal);

rule_regex_t *rule_search_new(const char *regex, prelude_bool_t optional);

int rule_regex_match(pcre_plugin_t *plugin, pcre_rule_container_t *rc,
                     const lml_log_source_t *ls, lml_log_entry_t *log_entry, pcre_match_flags_t *match_flags);


int pcre_state_push_idmef(pcre_state_t *state, idmef_message_t *idmef);

int pcre_state_clone(pcre_state_t *state, pcre_state_t **nstate);

pcre_state_t *pcre_state_ref(pcre_state_t *state);

void pcre_state_destroy(pcre_state_t *state);
