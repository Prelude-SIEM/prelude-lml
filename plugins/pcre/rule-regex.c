/*****
*
* Copyright (C) 1998 - 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pcre.h>
#include <netdb.h>

#include <libprelude/prelude-inttypes.h>
#include <libprelude/common.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-linked-object.h>

#include "libmissing.h"
#include "log-common.h"
#include "lml-alert.h"
#include "log.h"

#include "rule-object.h"
#include "pcre-mod.h"
#include "rule-regex.h"


#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))


#ifdef DEBUG
 #define dprint(args...) fprintf(stderr, args)
#else
 #define dprint(args...) do { } while(0)
#endif


struct rule_regex {
        PRELUDE_LINKED_OBJECT;
        
        pcre *regex;
        pcre_extra *extra;
        char *regex_string;
        prelude_bool_t optreg;
};


typedef struct {
        int reqmatch;
        int optmatch;
        idmef_message_t *idmef;
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
        if ( *real_ret <= 0 && ! item->optreg )
                return *real_ret;
        
        pcre_fullinfo(item->regex, item->extra, PCRE_INFO_CAPTURECOUNT, &cnt);
        if ( cnt == 0 )
                return *real_ret;
        
        for ( i = (*real_ret * 2); (i + 2) < (MIN(ovecsize, cnt + 1) * 2); i += 2 )
                ovector[i] = ovector[i + 1] = -1;
 
        return cnt + 1;
}



static int exec_regex(pcre_rule_t *rule, const log_entry_t *log_entry, int *ovector, size_t size)
{
        rule_regex_t *item;
        prelude_list_t *tmp;
        int tmpovector[size];
        int optional_match = 0, real_ret = 0, ret, retval = 0, i = 0;

        dprint("\nInput = %s\n", log_entry->message);
        
        prelude_list_for_each(tmp, &rule->regex_list) {
                item = prelude_linked_object_get_object(tmp, rule_regex_t);
                                
                ret = do_pcre_exec(item, &real_ret, log_entry->message, log_entry->message_len,
                                   tmpovector, sizeof(tmpovector) / sizeof(int));
                
                dprint("match=%s ret=%d (real=%d)\n", item->regex_string, ret, real_ret);
                if ( ret <= 0 && ! item->optreg )
                        return -1;
                
                ovector[0] = MIN(tmpovector[0], ovector[0]);
                ovector[1] = MAX(tmpovector[1], ovector[1]);
                
                if ( item->optreg && real_ret > 0 )
                        optional_match++;
                
                if ( ret == 1 )
                        continue;
                
                for ( i = 2; i < (ret * 2); i += 2 ) {
                        dprint("assign %d-%d\n", retval * 2 + i, retval * 2 + i + 1);
                        ovector[(retval * 2) + i] = tmpovector[i];
                        ovector[(retval * 2) + i + 1] = tmpovector[i + 1];
                }
                
                retval += (ret - 1);
        }
        
        retval++;
         
        if ( rule->min_optregex_match ) {
                dprint("optmatch=%d >= wanted=%d\n", optional_match, rule->min_optregex_match);
                return (optional_match >= rule->min_optregex_match) ? retval : -1;
        }
        
        return retval;
}



static int match_rule_single(pcre_rule_t *rule, pcre_state_t *state, const log_entry_t *log_entry)
{
         int ret;
         int ovector[MAX_REFERENCE_PER_RULE * 3];

         ovector[0] = 0x7fffffff;
         ovector[1] = 0;
         
         ret = exec_regex(rule, log_entry, ovector, sizeof(ovector) / sizeof(int));
         if ( ret < 0 )
                 return -1;
         
         ret = rule_object_build_message(rule->object_list, &state->idmef, log_entry, ovector, ret);         
         if ( ret < 0 )
                 return -1;
         
         return 0;
}


static int match_rule_list(pcre_rule_container_t *rc, pcre_state_t *state, const log_entry_t *log_entry)
{
        int ret;
        prelude_list_t *tmp;
        pcre_rule_t *rule = rc->rule;
        pcre_rule_container_t *child;
                        
        ret = match_rule_single(rule, state, log_entry);
        if ( ret < 0 && ! rc->optional )  
                return -1;
        
        if ( rc->optional )
                state->optmatch++;
        else
                state->reqmatch++;

        prelude_list_for_each(tmp, &rule->rule_list) {
                child = prelude_list_entry(tmp, pcre_rule_container_t, list);
                
                ret = match_rule_list(child, state, log_entry);
                if ( ret < 0 )
                        return -1;
        }
        
        if ( state->reqmatch < rule->required_goto )
                return -1;
        
        if ( state->optmatch < rule->min_optgoto_match ) 
                return -1;
        
        if ( ! rule->silent && state->idmef ) {
                lml_emit_alert(log_entry, state->idmef, PRELUDE_MSG_PRIORITY_MID);
                state->idmef = NULL;
        }

        return 0;
}



int rule_regex_match(pcre_rule_container_t *root, const log_entry_t *log_entry)
{
        int ret;
        pcre_state_t state;
        
        memset(&state, 0, sizeof(state));
        
        ret = match_rule_list(root, &state, log_entry);
        if ( ret < 0 )
                return -1;
        
        if ( state.idmef )
                idmef_message_destroy(state.idmef);

        return 0;
}



rule_regex_t *rule_regex_new(const char *regex, prelude_bool_t optional) 
{
        int err_offset;
        rule_regex_t *new;
        const char *err_ptr;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->regex = pcre_compile(regex, 0, &err_ptr, &err_offset, NULL);
        if ( ! new->regex ) {
                log(LOG_INFO, "unable to compile regex: %s.\n", err_ptr);
                return NULL;
        }

        new->regex_string = strdup(regex);
        if ( ! new->regex_string ) {
                log(LOG_ERR, "memory exhausted.\n");
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

        prelude_list_del(&ptr->list);
        free(ptr);
}
