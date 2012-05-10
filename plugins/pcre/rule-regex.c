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
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"

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

        int capture_count;
        char *regex_string;
        prelude_bool_t optreg;
};



#define OVECSIZE MAX_REFERENCE_PER_RULE * 3


static int ovector[OVECSIZE];
static unsigned int ovector_index;



/*
 * This function implement pcre_exec() call in a way that allow the same
 * ovector to be used accross multiple call.
 *
 * This result in a single ovector containing all the reference to
 * all subpatterns.
 */
static int do_pcre_exec(rule_regex_t *item, const char *in, size_t len, int *omin, int *omax)
{
        int *optr, obkp0, obkp1, ret, osize;

        osize = OVECSIZE - ovector_index - 2;
        if ( osize < 3 )
                return -1;

        optr = &ovector[ovector_index - 2];
        obkp0 = optr[0];
        obkp1 = optr[1];

        ret = pcre_exec(item->regex, item->extra, in, len, 0, 0, optr, osize);
        if ( ret < -1 || ret == 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "unexpected PCRE error: %d.\n", ret);
                return -1;
        }

        *omin = optr[0];
        *omax = optr[1];
        optr[0] = obkp0;
        optr[1] = obkp1;

        ovector_index += (item->capture_count * 2);
        if ( ovector_index > OVECSIZE ) {
                prelude_log(PRELUDE_LOG_ERR, "backward references vector is too small: %u entry required.\n", ovector_index);
                return -1;
        }

        return ret;
}


static int exec_regex(pcre_rule_t *rule, const lml_log_entry_t *log_entry)
{
        size_t len;
        rule_regex_t *item;
        prelude_list_t *tmp;
        const char *subject;
        int optional_match = 0, ret, retval = 1, omin, omax;

        len = lml_log_entry_get_message_len(log_entry);
        subject = lml_log_entry_get_message(log_entry);

        prelude_list_for_each(&rule->regex_list, tmp) {
                item = prelude_linked_object_get_object(tmp);

                ret = do_pcre_exec(item, subject, len, &omin, &omax);
                prelude_log_debug(5, "id=%d match=%s pcre_exec=%d\n", rule->id, item->regex_string, ret);

                retval += item->capture_count;
                if ( ret < 0 && ! item->optreg )
                        return -1;

                else {
                        if ( ret > 1 ) {
                                ovector[0] = MIN(ovector[0], omin);
                                ovector[1] = MAX(ovector[1], omax);
                        }

                        if ( item->optreg )
                                optional_match++;
                }
        }

        if ( rule->min_optregex_match ) {
                prelude_log_debug(10, "optmatch=%d >= wanted=%d\n", optional_match, rule->min_optregex_match);
                return (optional_match >= rule->min_optregex_match) ? retval : -1;
        }

        return retval;
}



static pcre_context_t *lookup_context(value_container_t *vcont, pcre_plugin_t *plugin,
                                      pcre_rule_t *rule, const lml_log_entry_t *log_entry)
{
        pcre_context_t *ctx;
        prelude_string_t *str;

        str = value_container_resolve(vcont, rule, log_entry, ovector, ovector_index);
        if ( ! str )
                return NULL;

        ctx = pcre_context_search(plugin, prelude_string_get_string(str));
        prelude_string_destroy(str);

        return ctx;
}


static void pcre_state_init(pcre_state_t *state)
{
        state->le = NULL;
        state->idmef = NULL;
        state->le_added = FALSE;
        prelude_list_init(&state->additional_data_list);
}


static int pcre_state_new(pcre_state_t **state)
{
        *state = malloc(sizeof(**state));
        if ( ! *state )
                return -1;

        pcre_state_init(*state);

        return 0;
}


static int pcre_state_add_rule_infos(pcre_state_t *state, pcre_rule_t *rule, const lml_log_source_t *ls, const lml_log_entry_t *le)
{
        int ret;
        prelude_string_t *str;
        idmef_additional_data_t *ad;

        if ( ! state->le_added ) {
                state->le_added = TRUE;
                lml_additional_data_prepare(&state->additional_data_list, ls, le);
        }

        if ( rule->id ) {
                ret = idmef_additional_data_new(&ad);
                if ( ret < 0 )
                        return ret;

                ret = idmef_additional_data_new_meaning(ad, &str);
                if ( ret < 0 )
                        return ret;

                prelude_string_set_constant(str, "Rule ID");
                idmef_additional_data_set_integer(ad, rule->id);

                prelude_linked_object_add_tail(&state->additional_data_list, (prelude_linked_object_t *) ad);
        }

        if ( rule->revision ) {
                ret = idmef_additional_data_new(&ad);
                if ( ret < 0 )
                        return ret;

                ret = idmef_additional_data_new_meaning(ad, &str);
                if ( ret < 0 )
                        return ret;

                prelude_string_set_constant(str, "Rule Revision");
                idmef_additional_data_set_integer(ad, rule->revision);

                prelude_linked_object_add_tail(&state->additional_data_list, (prelude_linked_object_t *) ad);
        }

        return 0;
}


int pcre_state_push_idmef(pcre_state_t *state, idmef_message_t *idmef)
{
        int ret;
        idmef_alert_t *alert;
        idmef_additional_data_t *ad;
        prelude_list_t *tmp, *bkp;

        ret = idmef_message_new_alert(idmef, &alert);
        if ( ret < 0 )
                return ret;

        prelude_list_for_each_safe(&state->additional_data_list, tmp, bkp) {
                ad = prelude_linked_object_get_object(tmp);
                prelude_linked_object_del((prelude_linked_object_t *)ad);
                idmef_alert_set_additional_data(alert, ad, IDMEF_LIST_APPEND);
        }

        return 0;
}


static void pcre_state_destroy_internal(pcre_state_t *state)
{
        idmef_additional_data_t *ad;
        prelude_list_t *tmp, *bkp;

        state->le_added = FALSE;

        prelude_list_for_each_safe(&state->additional_data_list, tmp, bkp) {
                ad = prelude_linked_object_get_object(tmp);
                prelude_linked_object_del((prelude_linked_object_t *) ad);
                idmef_additional_data_destroy(ad);
        }

        if ( state->idmef ) {
                idmef_message_destroy(state->idmef);
                state->idmef = NULL;
        }
}



void pcre_state_destroy(pcre_state_t *state)
{
        if ( state->le )
                lml_log_entry_destroy(state->le);

        pcre_state_destroy_internal(state);
        free(state);
}


int pcre_state_clone(pcre_state_t *state, pcre_state_t **new)
{
        int ret;
        idmef_additional_data_t *ad;
        prelude_list_t *tmp, *bkp;

        ret = pcre_state_new(new);
        if ( ret < 0 )
                return ret;

        if ( state->idmef ) {
                ret = idmef_message_clone(state->idmef, &(*new)->idmef);
                if ( ret < 0 ) {
                        pcre_state_destroy(*new);
                        return ret;
                }
        }

        prelude_list_for_each_safe(&state->additional_data_list, tmp, bkp) {
                ad = prelude_linked_object_get_object(tmp);

                ret = idmef_additional_data_clone(ad, &ad);
                if ( ret < 0 ) {
                        pcre_state_destroy(*new);
                        return ret;
                }

                prelude_linked_object_add_tail(&(*new)->additional_data_list, (prelude_linked_object_t *) ad);
        }

        if ( state->le )
                (*new)->le = lml_log_entry_ref(state->le);

        return 0;
}


static int match_rule_single(pcre_plugin_t *plugin, pcre_rule_t *rule, pcre_state_t **state, const lml_log_entry_t *log_entry)
{
        int ret;
        prelude_list_t *tmp;
        pcre_context_t *ctx;
        value_container_t *vcont;

        ovector[0] = 0x7fffffff;
        ovector[1] = 0;
        ovector_index = 2;

        ret = exec_regex(rule, log_entry);
        if ( ret < 0 )
                return -1;

        prelude_list_for_each(&rule->not_context_list, tmp) {
                vcont = prelude_linked_object_get_object(tmp);
                if ( lookup_context(vcont, plugin, rule, log_entry) )
                        return -1;
        }

        if ( rule->required_context ) {
                ctx = lookup_context(rule->required_context, plugin, rule, log_entry);
                if ( ! ctx )
                        return -1;

                if ( pcre_context_get_state(ctx) ) {
                        *state = pcre_context_get_state(ctx);
                        (*state)->le_added = FALSE;
                }
        }

        if ( rule->optional_context ) {
                ctx = lookup_context(rule->optional_context, plugin, rule, log_entry);
                if ( ctx && pcre_context_get_state(ctx) ) {
                        *state = pcre_context_get_state(ctx);
                        (*state)->le_added = FALSE;
                }
        }

        ret = rule_object_build_message(rule, rule->object_list, &(*state)->idmef, log_entry, ovector, ovector_index);
        if ( ret < 0 )
                return ret;

        return ret;
}


static void create_context_if_needed(pcre_plugin_t *plugin, pcre_rule_t *rule, pcre_state_t *state, lml_log_entry_t *log_entry)
{
        prelude_list_t *tmp;
        prelude_string_t *str;
        value_container_t *vcont;
        pcre_context_setting_t *pcs;
        lml_log_entry_t *prev = state->le;

        state->le = log_entry;
        prelude_list_for_each(&rule->create_context_list, tmp) {
                vcont = prelude_linked_object_get_object(tmp);

                str = value_container_resolve(vcont, rule, log_entry, ovector, ovector_index);
                if ( ! str )
                        continue;

                pcs = value_container_get_data(vcont);

                pcre_context_new(plugin, prelude_string_get_string(str), state, pcs);
                prelude_string_destroy(str);
        }
        state->le = prev;
}


static void destroy_context_if_needed(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                      const lml_log_entry_t *log_entry)
{
        pcre_context_t *ctx;
        prelude_list_t *tmp;
        prelude_string_t *str;
        value_container_t *vcont;

        prelude_list_for_each(&rule->destroy_context_list, tmp) {
                vcont = prelude_linked_object_get_object(tmp);

                str = value_container_resolve(vcont, rule, log_entry, ovector, ovector_index);
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
                           const lml_log_source_t *ls, lml_log_entry_t *log_entry,
                           pcre_match_flags_t *match_flags)
{
        prelude_list_t *tmp;
        int ret, optmatch = 0;
        pcre_match_flags_t gl = 0;
        pcre_rule_t *rule = rc->rule;
        pcre_rule_container_t *child;

        ret = match_rule_single(plugin, rule, &state, log_entry);
        if ( ret < 0 )
                return -1;

        prelude_list_for_each(&rule->rule_list, tmp) {
                child = prelude_list_entry(tmp, pcre_rule_container_t, list);

                ret = match_rule_list(plugin, child, state, ls, log_entry, &gl);
                if ( ret < 0 && ! child->optional ) {
                        pcre_state_destroy_internal(state);
                        return -1;
                }

                if ( child->optional )
                        optmatch++;

                *match_flags |= gl;
                if ( gl & PCRE_MATCH_FLAGS_LAST )
                        break;
        }

        if ( optmatch < rule->min_optgoto_match ) {
                pcre_state_destroy_internal(state);
                return -1;
        }

        pcre_state_add_rule_infos(state, rule, ls, log_entry);
        create_context_if_needed(plugin, rule, state, log_entry);

        if ( state->idmef ) {
                *match_flags |= PCRE_MATCH_FLAGS_ALERT;

                if ( ! (rule->flags & PCRE_RULE_FLAGS_SILENT) ) {
                        prelude_log_debug(4, "lml alert emit id=%d (last=%d) %s\n",
                                          rule->id, rule->flags & PCRE_RULE_FLAGS_LAST,
                                          lml_log_entry_get_message(log_entry));

                        /*
                         * Move additionalData part, to IDMEF message
                         */
                        pcre_state_push_idmef(state, state->idmef);

                        /*
                         * Set various information, detect_time/analyzer.
                         */
                        lml_alert_set_infos(state->idmef, log_entry);

                        lml_alert_emit(NULL, NULL, state->idmef);
                        pcre_state_destroy_internal(state);
                }

        }

        if ( rule->flags & PCRE_RULE_FLAGS_LAST )
                *match_flags |= PCRE_MATCH_FLAGS_LAST;

        destroy_context_if_needed(plugin, rule, log_entry);

        return 0;
}


int rule_regex_match(pcre_plugin_t *plugin, pcre_rule_container_t *rc,
                     const lml_log_source_t *ls, lml_log_entry_t *log_entry, pcre_match_flags_t *match_flags)
{
        int ret;
        pcre_state_t state;

        pcre_state_init(&state);
        ret = match_rule_list(plugin, rc, &state, ls, log_entry, match_flags);
        pcre_state_destroy_internal(&state);

        return ret;
}


static prelude_bool_t has_utf8(const char *regex)
{
        int support;
        unsigned char c;

        pcre_config(PCRE_CONFIG_UTF8, &support);
        if ( ! support )
                return FALSE;

        while ( (c = (unsigned char) *regex) ) {
                if ( (c >= 0xC2 && c <= 0xDF) ||
                     (c >= 0xE0 && c <= 0xEF) ||
                     (c >= 0xF0 && c <= 0xF4) )
                        return TRUE;

                regex++;
        }

        return FALSE;
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

        new->regex = pcre_compile(regex, has_utf8(regex) ? PCRE_UTF8 : 0, &err_ptr, &err_offset, NULL);
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

        pcre_fullinfo(new->regex, new->extra, PCRE_INFO_CAPTURECOUNT, &new->capture_count);

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
