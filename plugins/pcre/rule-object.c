/*****
*
* Copyright (C) 1998 - 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
* Copyright (C) 2003 Nicolas Delon <delon.nicolas@wanadoo.fr>
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
#include <libprelude/prelude-string.h>

#include "libmissing.h"
#include "log-common.h"
#include "lml-alert.h"
#include "log.h"

#include "rule-object.h"
#include "pcre-mod.h"


struct rule_object_list {
        prelude_list_t rule_object_list;
        prelude_list_t referenced_value_list;
};


/*
 * List of IDMEF object set by a given rule.
 */
typedef struct {
        prelude_list_t list;
        
        idmef_object_t *object;
        prelude_list_t rule_object_value_list;
} rule_object_t;




/*
 * List of fixed and dynamic value for a given IDMEF object.
 */
typedef struct rule_object_value {
        prelude_list_t list;      
        char *value;
} rule_object_value_t;



typedef struct {
        prelude_list_t list;

        int refno;
        char **value;
} rule_referenced_value_t;



static int strrncmp(const char *s1, const char *s2)
{
        size_t s1_len;
        size_t s2_len;

        s1_len = strlen(s1);
        s2_len = strlen(s2);

        if ( s1_len < s2_len )
                return 1;

        return strncmp(s1 + s1_len - s2_len, s2, s2_len);
}




static int referenced_value_add(rule_object_list_t *olist, unsigned int reference, char **value)
{
        rule_referenced_value_t *reference_value;

        if ( reference >= MAX_REFERENCE_PER_RULE ) {
                log(LOG_ERR, "reference number %d is too high.\n", reference);
                return -1;
        }

        reference_value = malloc(sizeof(*reference_value));
        if ( ! reference_value ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        reference_value->value = value;
        reference_value->refno = reference;
        
        prelude_list_add_tail(&reference_value->list, &olist->referenced_value_list);

        return 0;
}



static int add_dynamic_object_value(rule_object_list_t *olist, rule_object_t *rule_object, unsigned int reference)
{
        rule_object_value_t *rovalue;

        rovalue = calloc(1, sizeof(*rovalue));
        if ( ! rovalue ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        if ( referenced_value_add(olist, reference, &rovalue->value) < 0 ) {
                free(rovalue);
                return -1;
        }

        prelude_list_add_tail(&rovalue->list, &rule_object->rule_object_value_list);

        return 0;                
}



static int add_fixed_object_value(rule_object_t *rule_object, prelude_string_t *strbuf)
{
        rule_object_value_t *rovalue;

        rovalue = calloc(1, sizeof(*rovalue));
        if ( ! rovalue ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        rovalue->value = prelude_string_get_string_released(strbuf);

        prelude_list_add_tail(&rovalue->list, &rule_object->rule_object_value_list);

        return 0;
}



static int parse_rule_object_value(rule_object_list_t *olist, rule_object_t *rule_object, const char *line)
{
        int i;
        char num[10];
        const char *str;
        prelude_string_t *strbuf;

        str = line;

        while ( *str ) {
                if ( *str == '$' && *(str + 1) != '$' ) {

                        i = 0;
                        str++;
                        
                        while ( isdigit((int) *str) && i < sizeof(num) )
                                num[i++] = *str++;

                        if ( ! i )
                                return -1;

                        num[i] = 0;

                        if ( add_dynamic_object_value(olist, rule_object, atoi(num)) < 0 )
                                return -1;

                        continue;
                }

                strbuf = prelude_string_new();
                if ( ! strbuf )
                        return -1;

                while ( *str ) {
                        if ( *str == '$' ) {
                                if ( *(str + 1) == '$' )
                                        str++;
                                else
                                        break;
                        }

                        if ( prelude_string_ncat(strbuf, str, 1) < 0 )
                                return -1;
                        str++;
                }

                if ( add_fixed_object_value(rule_object, strbuf) < 0 )
                        return -1;

                prelude_string_destroy(strbuf);
        }

        return 0;
}



static void free_rule_object_value_list(rule_object_t *object)
{
        prelude_list_t *tmp, *bkp;
        rule_object_value_t *rovalue;
        
        prelude_list_for_each_safe(tmp, bkp, &object->rule_object_value_list) {
                rovalue = prelude_list_entry(tmp, rule_object_value_t, list);

                prelude_list_del(&rovalue->list);
                free(rovalue);
        }
}



static idmef_value_t *build_message_object_value(rule_object_t *rule_object)
{
        const char *str;
        prelude_list_t *tmp;
        idmef_value_t *value;
        struct servent *service;
        prelude_string_t *strbuf;
        rule_object_value_t *rovalue;
                 
        strbuf = prelude_string_new();
        if ( ! strbuf )
                return NULL;

        prelude_list_for_each(tmp, &rule_object->rule_object_value_list) {
                rovalue = prelude_list_entry(tmp, rule_object_value_t, list);

                if ( ! rovalue->value )
                        continue;

                if ( prelude_string_cat(strbuf, rovalue->value) < 0 ) {
                        prelude_string_destroy(strbuf);
                        return NULL;
                }
        }

        if ( prelude_string_is_empty(strbuf) ) {
                prelude_string_destroy(strbuf);
                return NULL;
        }
        
        str = prelude_string_get_string(strbuf);

        if ( strrncmp(idmef_object_get_name(rule_object->object), ".port") == 0 && ! isdigit((int) *str) ) {
                service = getservbyname(str, NULL);
                if ( ! service ) {
                        log(LOG_ERR, "Service name '%s' could not be found in /etc/services.\n", str);
                        return NULL;
                }

                value = idmef_value_new_uint16(ntohs(service->s_port));

        }
        else
            value = idmef_value_new_for_object(rule_object->object, str);

        prelude_string_destroy(strbuf);
        
        return value;
}




static void resolve_referenced_value(rule_object_list_t *olist,
                                     const log_entry_t *log_entry, int *ovector, size_t osize) 
{
         int ret;
         prelude_list_t *tmp;
         char buf[1024] = { 0 };
         rule_referenced_value_t *rval;
         
         prelude_list_for_each(tmp, &olist->referenced_value_list) {
                 
                 rval = prelude_list_entry(tmp, rule_referenced_value_t, list);
                 
                 ret = pcre_copy_substring(log_entry->log, ovector, osize, rval->refno, buf, sizeof(buf));
                 if ( ret < 0 ) {
                         if ( ret == PCRE_ERROR_NOMEMORY ) 
                                 log(LOG_ERR, "not enough memory to get backward reference %d.\n",
                                     rval->refno);
                         
                         else if ( ret == PCRE_ERROR_NOSUBSTRING )
                                 log(LOG_ERR, "backward reference %d does not exist.\n",
                                     rval->refno);
                         
                         else
                                 log(LOG_ERR, "unknown PCRE error while getting backward reference %d.\n",
                                     rval->refno);

                         continue;
                 }

                 *rval->value = (buf[0]) ? strdup(buf) : NULL;
        }
}



static void referenced_value_destroy_content(rule_object_list_t *olist)
{
        prelude_list_t *tmp;
        rule_referenced_value_t *rvalue;
        
        prelude_list_for_each(tmp, &olist->referenced_value_list) {
                rvalue = prelude_list_entry(tmp, rule_referenced_value_t, list);

                if ( *rvalue->value ) {
                        free(*rvalue->value);
                        *rvalue->value = NULL;
                }
        }
}



int rule_object_build_message(rule_object_list_t *olist, idmef_message_t **message,
                              const log_entry_t *log_entry, int *ovector, size_t osize)
{
        int ret;
        prelude_list_t *tmp;
        idmef_value_t *value;
        rule_object_t *rule_object;
        
        if ( ! *message ) {
                *message = idmef_message_new();
                if ( ! *message )
                        return -1;
        }
        
        resolve_referenced_value(olist, log_entry, ovector, osize);
        
        prelude_list_for_each(tmp, &olist->rule_object_list) {
                rule_object = prelude_list_entry(tmp, rule_object_t, list);

                value = build_message_object_value(rule_object);
                if ( ! value )
                        continue;
                
                ret = idmef_object_set(*message, rule_object->object, value);
                idmef_value_destroy(value);

                if ( ret < 0 ) {
                        log(LOG_ERR, "idmef_object_set failed for %s: %d.\n",
                            idmef_object_get_name(rule_object->object), ret);
                        idmef_message_destroy(*message);
                        referenced_value_destroy_content(olist);
                        return -1;
                }
        }

        referenced_value_destroy_content(olist);
        
        return 0;
}



int rule_object_add(rule_object_list_t *olist,
                    const char *filename, int line,
                    const char *object_name, const char *value)
{
        idmef_object_t *object;
        rule_object_t *rule_object;

        object = idmef_object_new("alert.%s", object_name);
        if ( ! object ) {
                log(LOG_ERR, "%s:%d: could not create 'alert.%s' object.\n", filename, line, object_name);
                return -1;
        }

        if ( idmef_object_is_ambiguous(object) == 0 ) {
                log(LOG_ERR, "%s:%d: invalid object '%s', some list index are missing.\n",
                    filename, line, idmef_object_get_name(object));
                idmef_object_destroy(object);
                return -1;
        }

        rule_object = malloc(sizeof(*rule_object));
        if ( ! rule_object ) {
                log(LOG_ERR, "memory exhausted.\n");
                idmef_object_destroy(object);
                return -1;
        }

        PRELUDE_INIT_LIST_HEAD(&rule_object->rule_object_value_list);
        rule_object->object = object;

        if ( parse_rule_object_value(olist, rule_object, value) < 0 ) {
                idmef_object_destroy(object);
                free(rule_object);
                return -1;
        }

        prelude_list_add_tail(&rule_object->list, &olist->rule_object_list);

        return 0;
}




rule_object_list_t *rule_object_list_new(void)
{
        rule_object_list_t *olist;

        olist = malloc(sizeof(*olist));
        if ( ! olist ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        PRELUDE_INIT_LIST_HEAD(&olist->rule_object_list);
        PRELUDE_INIT_LIST_HEAD(&olist->referenced_value_list);

        return olist;
}



void rule_object_list_destroy(rule_object_list_t *olist)
{
        rule_object_t *robject;
        prelude_list_t *tmp, *bkp;
        rule_referenced_value_t *rvalue;

        prelude_list_for_each_safe(tmp, bkp, &olist->rule_object_list) {
                robject = prelude_list_entry(tmp, rule_object_t, list);

                idmef_object_destroy(robject->object);
                free_rule_object_value_list(robject);

                prelude_list_del(&robject->list);
                free(robject);
        }
        
        prelude_list_for_each_safe(tmp, bkp, &olist->referenced_value_list) {
                rvalue = prelude_list_entry(tmp, rule_referenced_value_t, list);
                
                free(*rvalue->value);
                *rvalue->value = NULL;
                
                prelude_list_del(&rvalue->list);
                free(rvalue);
        }

        free(olist);
}




int rule_object_list_empty(rule_object_list_t *olist)
{
        return prelude_list_empty(&olist->rule_object_list);
}
