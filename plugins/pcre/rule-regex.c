/*****
*
* Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006 PreludeIDS Technologies. All Rights Reserved.
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

#include "config.h"
#include "libmissing.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <pcre.h>
#include <assert.h>

#include <libprelude/prelude-inttypes.h>
#include <libprelude/common.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-linked-object.h>

#include "prelude-lml.h"
#include "pcre-mod.h"
#include "rule-object.h"
#include "rule-regex.h"



#ifndef MIN
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
# define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif


struct rule_regex {
        PRELUDE_LINKED_OBJECT;

        pcre *regex;
        pcre_extra *extra;
        char *regex_string;
        prelude_bool_t optreg;
};


typedef struct {
        idmef_message_t *idmef;
        prelude_bool_t log_added;
} pcre_state_t;



/*
 * In a match where some of the capture are not required, pcre_exec will
 * not always return the _full_ number of captured substring. This function
 * make sure that all not captured substring are set to -1, and then return
 * the total of substring, including the one that were not captured.
 */
static int do_pcre_exec(rule_regex_t *item, int *real_ret,
                        const char *subject, int length, int *ovector, int ovecsize)
{
        int cnt = 0, i;

        *real_ret = pcre_exec(item->regex, item->extra, subject, length, 0, 0, ovector, ovecsize);

        prelude_log_debug(5, "match %s ret %d\n", item->regex_string, *real_ret);

        if ( *real_ret <= 0 && ! item->optreg )
                return *real_ret;

        pcre_fullinfo(item->regex, item->extra, PCRE_INFO_CAPTURECOUNT, &cnt);
        if ( cnt == 0 )
                return *real_ret;

        for ( i = (*real_ret * 2); (i + 2) < (MIN(ovecsize, cnt + 1) * 2); i += 2 )
                ovector[i] = ovector[i + 1] = -1;

        return cnt + 1;
}



static int exec_regex(pcre_rule_t *rule, const lml_log_entry_t *log_entry, int *ovector, size_t size)
{
        rule_regex_t *item;
        prelude_list_t *tmp;
        int tmpovector[size];
        int optional_match = 0, real_ret = 0, ret, retval = 0, i = 0;

        prelude_list_for_each(&rule->regex_list, tmp) {
                item = prelude_linked_object_get_object(tmp);

                ret = do_pcre_exec(item, &real_ret, lml_log_entry_get_message(log_entry),
                                   lml_log_entry_get_message_len(log_entry),
                                   tmpovector, sizeof(tmpovector) / sizeof(int));
                prelude_log_debug(5, "id=%d match=%s ret=%d (real=%d)\n", rule->id, item->regex_string, ret, real_ret);
                if ( ret <= 0 && ! item->optreg )
                        return -1;

                ovector[0] = MIN(tmpovector[0], ovector[0]);
                ovector[1] = MAX(tmpovector[1], ovector[1]);

                if ( item->optreg && real_ret > 0 )
                        optional_match++;

                if ( ret == 1 )
                        continue;

                for ( i = 2; i < (ret * 2); i += 2 ) {
                        prelude_log_debug(10, "assign %d-%d\n", retval * 2 + i, retval * 2 + i + 1);
                        ovector[(retval * 2) + i] = tmpovector[i];
                        ovector[(retval * 2) + i + 1] = tmpovector[i + 1];
                }

                retval += (ret - 1);
        }

        retval++;

        if ( rule->min_optregex_match ) {
                prelude_log_debug(10, "optmatch=%d >= wanted=%d\n", optional_match, rule->min_optregex_match);
                return (optional_match >= rule->min_optregex_match) ? retval : -1;
        }

        return retval;
}



static pcre_context_t *lookup_context(value_container_t *vcont, pcre_plugin_t *plugin,
                                      pcre_rule_t *rule, const lml_log_entry_t *log_entry, int *ovector, size_t osize)
{
        pcre_context_t *ctx;
        prelude_string_t *str;

        str = value_container_resolve(vcont, rule, log_entry, ovector, osize);
        if ( ! str )
                return NULL;

        ctx = pcre_context_search(plugin, prelude_string_get_string(str));
        prelude_string_destroy(str);

        return ctx;
}



static int alert_add_rule_infos(pcre_rule_t *rule, idmef_message_t *idmef)
{
        int ret;
        idmef_alert_t *alert;
        prelude_string_t *str;
        idmef_additional_data_t *ad;

        ret = idmef_message_new_alert(idmef, &alert);
        if ( ret < 0 )
                return ret;

        if ( rule->id ) {
                ret = idmef_alert_new_additional_data(alert, &ad, IDMEF_LIST_APPEND);
                if ( ret < 0 )
                        return ret;

                ret = idmef_additional_data_new_meaning(ad, &str);
                if ( ret < 0 )
                        return ret;

                prelude_string_set_constant(str, "Rule ID");
                idmef_additional_data_set_integer(ad, rule->id);
        }

        if ( rule->revision ) {
                ret = idmef_alert_new_additional_data(alert, &ad, IDMEF_LIST_APPEND);
                if ( ret < 0 )
                        return ret;

                ret = idmef_additional_data_new_meaning(ad, &str);
                if ( ret < 0 )
                        return ret;

                prelude_string_set_constant(str, "Rule Revision");
                idmef_additional_data_set_integer(ad, rule->revision);
        }

        return 0;
}



static int match_rule_single(pcre_plugin_t *plugin, pcre_rule_t *rule, pcre_state_t *state,
                             const lml_log_source_t *ls, const lml_log_entry_t *log_entry, int *ovector, int *osize)
{
        int ret;
        prelude_list_t *tmp;
        pcre_context_t *ctx;
        value_container_t *vcont;

        ovector[0] = 0x7fffffff;
        ovector[1] = 0;

        *osize = exec_regex(rule, log_entry, ovector, (size_t) *osize);
        if ( *osize < 0 )
                return -1;

        prelude_list_for_each(&rule->not_context_list, tmp) {
                vcont = prelude_linked_object_get_object(tmp);
                if ( lookup_context(vcont, plugin, rule, log_entry, ovector, *osize) )
                        return -1;
        }

        if ( rule->required_context ) {
                ctx = lookup_context(rule->required_context, plugin, rule, log_entry, ovector, *osize);
                if ( ! ctx )
                        return -1;

                if ( pcre_context_get_idmef(ctx) )
                        state->idmef = idmef_message_ref(pcre_context_get_idmef(ctx));
        }

        if ( rule->optional_context ) {
                ctx = lookup_context(rule->optional_context, plugin, rule, log_entry, ovector, *osize);
                if ( ctx && pcre_context_get_idmef(ctx) )
                        state->idmef = idmef_message_ref(pcre_context_get_idmef(ctx));
        }

        ret = rule_object_build_message(rule, rule->object_list, &state->idmef, log_entry, ovector, *osize);
        if ( ret < 0 )
                return ret;

        if ( state->idmef && ! state->log_added ) {
                state->log_added = TRUE;
                lml_alert_prepare(state->idmef, ls, log_entry);
                alert_add_rule_infos(rule, state->idmef);
        }

        return ret;
}



static void destroy_idmef_state(pcre_state_t *state)
{
        if ( state->idmef ) {
                idmef_message_destroy(state->idmef);
                state->idmef = NULL;
                state->log_added = FALSE;
        }
}



static void create_context_if_needed(pcre_plugin_t *plugin, pcre_rule_t *rule, pcre_state_t *state,
                                     const lml_log_entry_t *log_entry, int *ovector, int osize)
{
        prelude_list_t *tmp;
        prelude_string_t *str;
        value_container_t *vcont;
        pcre_context_setting_t *pcs;

        prelude_list_for_each(&rule->create_context_list, tmp) {
                vcont = prelude_linked_object_get_object(tmp);

                str = value_container_resolve(vcont, rule, log_entry, ovector, osize);
                if ( ! str )
                        continue;

                pcs = value_container_get_data(vcont);

                pcre_context_new(plugin, prelude_string_get_string(str), state->idmef, pcs);
                prelude_string_destroy(str);
        }
}


static void destroy_context_if_needed(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                      const lml_log_entry_t *log_entry, int *ovector, int osize)
{
        pcre_context_t *ctx;
        prelude_list_t *tmp;
        prelude_string_t *str;
        value_container_t *vcont;

        prelude_list_for_each(&rule->destroy_context_list, tmp) {
                vcont = prelude_linked_object_get_object(tmp);

                str = value_container_resolve(vcont, rule, log_entry, ovector, osize);
                if ( ! str )
                        continue;

                ctx = pcre_context_search(plugin, prelude_string_get_string(str));
                prelude_string_destroy(str);
                if ( ! ctx )
                        continue;

                pcre_context_destroy(ctx);
        }
}



static int match_rule_list(pcre_plugin_t *plugin,
                           pcre_rule_container_t *rc, pcre_state_t *state,
                           const lml_log_source_t *ls, const lml_log_entry_t *log_entry,
                           pcre_match_flags_t *match_flags)
{
        prelude_list_t *tmp;
        int ret, optmatch = 0;
        pcre_match_flags_t gl = 0;
        pcre_rule_t *rule = rc->rule;
        pcre_rule_container_t *child;
        int ovector[MAX_REFERENCE_PER_RULE * 3], osize = sizeof(ovector) / sizeof(int);;

        ret = match_rule_single(plugin, rule, state, ls, log_entry, ovector, &osize);
        if ( ret < 0 )
                return -1;

        prelude_list_for_each(&rule->rule_list, tmp) {
                child = prelude_list_entry(tmp, pcre_rule_container_t, list);

                ret = match_rule_list(plugin, child, state, ls, log_entry, &gl);
                if ( ret < 0 && ! child->optional ) {
                        destroy_idmef_state(state);
                        return -1;
                }

                if ( child->optional )
                        optmatch++;

                *match_flags |= gl;
                if ( gl & PCRE_MATCH_FLAGS_LAST )
                        break;
        }

        if ( optmatch < rule->min_optgoto_match ) {
                destroy_idmef_state(state);
                return -1;
        }

        create_context_if_needed(plugin, rule, state, log_entry, ovector, osize);

        if ( ! (rule->flags & PCRE_RULE_FLAGS_SILENT) && state->idmef ) {
                prelude_log_debug(4, "lml alert emit id=%d (last=%d) %s\n",
                                  rule->id, rule->flags & PCRE_RULE_FLAGS_LAST,
                                  lml_log_entry_get_message(log_entry));

                lml_alert_emit(NULL, NULL, state->idmef);
                destroy_idmef_state(state);

                *match_flags |= PCRE_MATCH_FLAGS_ALERT;
        }

        if ( rule->flags & PCRE_RULE_FLAGS_LAST )
                *match_flags |= PCRE_MATCH_FLAGS_LAST;

        destroy_context_if_needed(plugin, rule, log_entry, ovector, osize);

        return 0;
}



int rule_regex_match(pcre_plugin_t *plugin, pcre_rule_container_t *rc,
                     const lml_log_source_t *ls, const lml_log_entry_t *log_entry, pcre_match_flags_t *match_flags)
{
        int ret;
        pcre_state_t state;

        memset(&state, 0, sizeof(state));

        ret = match_rule_list(plugin, rc, &state, ls, log_entry, match_flags);

        if ( state.idmef )
                idmef_message_destroy(state.idmef);

        return ret;
}



rule_regex_t *rule_regex_new(const char *regex, prelude_bool_t optional)
{
        int err_offset;
        rule_regex_t *new;
        const char *err_ptr;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->regex = pcre_compile(regex, 0, &err_ptr, &err_offset, NULL);
        if ( ! new->regex ) {
                prelude_log(PRELUDE_LOG_WARN, "unable to compile regex[offset:%d]: %s.\n", err_offset, err_ptr);
                free(new);
                return NULL;
        }

        new->regex_string = strdup(regex);
        if ( ! new->regex_string ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                free(new->regex);
                free(new);
                return NULL;
        }

        new->optreg = optional;
        new->extra = pcre_study(new->regex, 0, &err_ptr);

        return new;
}



void rule_regex_destroy(rule_regex_t *ptr)
{
        if ( ptr->regex_string )
                free(ptr->regex_string);

        if ( ptr->regex )
                pcre_free(ptr->regex);

        if ( ptr->extra )
                pcre_free(ptr->extra);

        prelude_linked_object_del((prelude_linked_object_t *) ptr);
        free(ptr);
}
