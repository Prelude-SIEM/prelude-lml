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

#include <libprelude/prelude.h>

#include "libmissing.h"
#include "log-common.h"
#include "lml-alert.h"
#include "log.h"

#include "rule-object.h"
#include "pcre-mod.h"
#include "rule-regex.h"

prelude_plugin_generic_t *pcre_LTX_prelude_plugin_init(void);


typedef struct {
        int rulesnum;
        char *rulesetdir;
        int last_rules_first;
        prelude_list_t rule_list;
} pcre_plugin_t;




static void free_rule_container(pcre_rule_container_t *rc);
static int parse_ruleset(pcre_plugin_t *plugin, const char *filename, FILE *fd);




static plugin_log_t pcre_plugin;
extern prelude_option_t *lml_root_optlist;



static pcre_rule_container_t *create_rule_container(pcre_rule_t *rule)
{
        pcre_rule_container_t *rc;

        rc = calloc(1, sizeof(*rc));
        if ( ! rc ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        rc->rule = rule;
        rule->refcount++;
        
        return rc;
}



static int parse_rule_id(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *id) 
{
        rule->id = (uint16_t) strtol(id, NULL, 0);

        return 0;
}



static int parse_rule_revision(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *revision) 
{
        rule->revision = (uint16_t) strtol(revision, NULL, 0);

        return 0;
}



static int parse_rule_regex(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *regex) 
{
        rule_regex_t *new;

        new = rule_regex_new(regex, 0);
        if ( ! new )
                return -1;
        
        rule->required++;
        prelude_linked_object_add_tail((prelude_linked_object_t *) new, &rule->regex_list);
        
        return 0;
}



static int parse_rule_optregex(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *regex) 
{
        rule_regex_t *new;

        new = rule_regex_new(regex, 1);
        if ( ! new )
                return -1;

        prelude_linked_object_add_tail((prelude_linked_object_t *) new, &rule->regex_list);
        
        return 0;
}



static int parse_rule_goto(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *idstr)
{
        prelude_list_t *tmp;
        int id = atoi(idstr);
        pcre_rule_container_t *new, *cur;
        
        prelude_list_for_each(tmp, &plugin->rule_list) {
                cur = prelude_list_entry(tmp, pcre_rule_container_t, list);
                
                if ( cur->rule->id != id )
                        continue;

                new = create_rule_container(cur->rule);
                if ( ! new ) 
                        return -1;
                
                rule->required++;
                prelude_list_add_tail(&new->list, &rule->rule_list);
                
                return 0;
        }
        
        log(LOG_ERR, "couldn't find a rule with ID %d.\n", id);
        
        return -1;
}



static int parse_rule_optgoto(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *idstr)
{
        int ret;
        pcre_rule_container_t *last;
        
        ret = parse_rule_goto(plugin, rule, idstr);
        if ( ret < 0 )
                return -1;
        
        last = prelude_list_entry(rule->rule_list.prev, pcre_rule_container_t, list);
        last->optionnal = 1;
        
        rule->required--;
        
        return 0;
}



static int parse_rule_min_optgoto_match(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        rule->min_optgoto_match = atoi(arg);

        return 0;
}



static int parse_rule_min_optregex_match(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *arg)
{
        rule->min_optregex_match = atoi(arg);

        return 0;
}



static int parse_rule_last(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *last)
{
        rule->last = 1;

        return 0;
}



static int parse_rule_chained(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *last)
{
        rule->chained = 1;

        return 0;
}



static int parse_include(pcre_plugin_t *plugin, const char *value) 
{
        int ret;
        FILE *fd;
        char filename[256];

        if ( plugin->rulesetdir && value[0] != '/' )
                snprintf(filename, sizeof(filename), "%s/%s", plugin->rulesetdir, value);
        else
                snprintf(filename, sizeof(filename), "%s", value);

        fd = fopen(filename, "r");
        if ( ! fd ) {
                log(LOG_ERR, "couldn't open %s for reading.\n", filename);
                return -1;
        }

        ret = parse_ruleset(plugin, filename, fd);

        fclose(fd);

        return ret;
}



static int parse_key_and_value(char *input, char **key, char **value) 
{
        char *ptr, *tmp;

        *value = NULL;
        
        /*
         * filter space at the begining of the line.
         */
        while ( (*input == ' ' || *input == '\t') && *input != '\0' )
                input++;

        if ( *input == '\0' )
                return 0;
        
        *key = input;

        /*
         * search first '=' in the input,
         * corresponding to the key = value separator.
         */
        tmp = ptr = strchr(input, '=');
        

        /*
         * strip whitespace at the tail of the key.
         */
        while ( tmp && (*tmp == '=' || isspace((int) *tmp)) )
                *tmp-- = '\0';

        if ( ! ptr )
                /* key without value */
                return 0; 
        
        /*
         * strip whitespace at the begining of the value.
         */
        ptr++;
        while ( *ptr != '\0' && isspace((int) *ptr) )
                ptr++;

        *value = ptr;

        /*
         * strip whitespace at the end of the value.
         */
        ptr = ptr + strlen(ptr) - 1;
        while ( isspace((int) *ptr) )
                *ptr-- = '\0';
        
        return 0;
}



static char *cut_line(char *buf, char **sptr) 
{
        int escaped = 0;
        char *ptr, *wptr;

        if ( ! buf && ! *sptr )
                return NULL;

        buf = wptr = (ptr = (*sptr) ? *sptr : buf);
        *sptr = NULL;

        while ( *ptr ) {
                if ( *ptr == '\\' ) 
                        escaped = 1;

                else if ( ! escaped && *ptr == ';' ) {
                        *wptr = '\0';
                        *sptr = ptr + 1;
                        break;
                }

                else if ( escaped ) {
                        if ( *ptr == ';' )
                                wptr--;

                        escaped = 0;
                }
                
                *wptr++ = *ptr++;
        }

        return buf;
}



static int parse_rule_keyword(pcre_plugin_t *plugin, pcre_rule_t *rule,
                                const char *filename, int line,
                                const char *keyword, const char *value)
{
        int i;
        struct {
                const char *keyword;
                int (*func)(pcre_plugin_t *plugin, pcre_rule_t *rule, const char *value);
        } keywords[] = {
                { "chained"             , parse_rule_chained            },
                { "goto"                , parse_rule_goto               },
                { "id"                  , parse_rule_id                 },
                { "last"                , parse_rule_last               },
                { "min-optgoto-match"   , parse_rule_min_optgoto_match  },
                { "min-optregex-match"  , parse_rule_min_optregex_match },
                { "optgoto"             , parse_rule_optgoto            },
                { "optregex"            , parse_rule_optregex           },
                { "regex"               , parse_rule_regex              },
                { "revision"            , parse_rule_revision           },
        };

        for ( i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++ ) {
                if ( strcmp(keyword, keywords[i].keyword) != 0 )
                        continue;

                if ( keywords[i].func(plugin, rule, value) < 0 ) {
                        log(LOG_INFO, "%s:%d: error parsing value for '%s'.\n", filename, line, keyword);
                        return -1;
                }

                return 1;
        }

        return 0;
}




static int parse_rule_entry(pcre_plugin_t *plugin, pcre_rule_t *rule,
                            const char *filename, int line,
                            const char *key, const char *value)
{
        int ret;

        /*
         * Do we have a keyword...
         */
        ret = parse_rule_keyword(plugin, rule, filename, line, key, value);
        if ( ret == -1 || ret == 1 )
                return ret;

        /*
         * ... or an idmef object
         */
        return rule_object_add(rule->object_list, filename, line, key, value);        
}



static pcre_rule_t *create_rule(void)
{
        pcre_rule_t *rule;

        rule = calloc(1, sizeof(*rule));
        if ( ! rule ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        rule->object_list = rule_object_list_new();
        if ( ! rule->object_list ) {
                free(rule);
                return NULL;
        }
        
        PRELUDE_INIT_LIST_HEAD(&rule->rule_list);
        PRELUDE_INIT_LIST_HEAD(&rule->regex_list);

        return rule;
}



static void free_rule(pcre_rule_t *rule) 
{
        rule_regex_t *item;
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rc;
        
        prelude_list_for_each_safe(tmp, bkp, &rule->rule_list) {
                rc = prelude_list_entry(tmp, pcre_rule_container_t, list);
                free_rule_container(rc);
        }
        
        prelude_list_for_each_safe(tmp, bkp, &rule->regex_list) {
                item = prelude_linked_object_get_object(tmp, rule_regex_t);
                rule_regex_destroy(item);
        }

        rule_object_list_destroy(rule->object_list);
                                        
        free(rule);
}



static void free_rule_container(pcre_rule_container_t *rc)
{
        if ( --rc->rule->refcount == 0 )
                free_rule(rc->rule);
        
        prelude_list_del(&rc->list);
        free(rc);
}



static int parse_ruleset_directive(pcre_plugin_t *plugin, const char *filename, int line, char *buf) 
{
        char *in;
        char *key;
        char *value;
        char *ptr = NULL;
        int first_directive = 1;
        pcre_rule_t *rule = NULL;
        pcre_rule_container_t *rc = NULL;
        
        while ( (in = cut_line(buf, &ptr)) ) {
                buf = NULL;
                
                /*
                 * filter space at the begining of the line.
                 */
                while ( *in == ' ' && *in != '\0' )
                        in++;

                /*
                 * empty line or comment. 
                 */
                if ( *in == '\0' || *in == '\n' || *in == '#' )
                        continue;

                if ( parse_key_and_value(in, &key, &value) < 0 ) {
                        log(LOG_INFO, "%s:%d: no string delimiter.\n", filename, line);
                        return -1;
                }
                
                if ( first_directive ) {
                        if ( strcmp(key, "include") == 0 ) {
                                parse_include(plugin, value);
                                return 0;
                        }
                        
                        rule = create_rule();
                        if ( ! rule )
                                return -1;
                        
                        first_directive = 0;
                }
                
                if ( parse_rule_entry(plugin, rule, filename, line, key, value) < 0 ) {
                        free_rule(rule);
                        return -1;
                }
        }

        if ( prelude_list_empty(&rule->regex_list) ) {
                log(LOG_ERR, "%s:%d: rule does not provide a regex.\n", filename, line);
                free_rule(rule);
                return -1;
        }

        rc = create_rule_container(rule);
        if ( ! rc ) {
                free_rule(rule);
                return -1;
        }
        
        if ( plugin->last_rules_first && rule->last )
                prelude_list_add(&rc->list, &plugin->rule_list);
        else
                prelude_list_add_tail(&rc->list, &plugin->rule_list);
        
        plugin->rulesnum++;

        return 0;
}



static int parse_ruleset(pcre_plugin_t *plugin, const char *filename, FILE *fd) 
{
        int line = 0;
        char buf[8192], *ptr;

        while ( prelude_read_multiline(fd, &line, buf, sizeof(buf)) == 0 ) {

                ptr = buf;
                buf[strlen(buf) - 1] = '\0'; /* strip \n */

                 /*
                  * filter space and tab at the begining of the line.
                  */
                while ( (*ptr == ' ' || *ptr == '\t') && *ptr != '\0' )
                        ptr++;

                /*
                 * empty line or comment. 
                 */
                if ( *ptr == '\0' || *ptr == '#' )
                        continue;

                parse_ruleset_directive(plugin, filename, line, ptr);
        }

        return 0;
}




static void pcre_run(prelude_plugin_instance_t *pi, const log_entry_t *log_entry)
{
        int ret;
        prelude_list_t *tmp;
        pcre_plugin_t *plugin;
        pcre_rule_container_t *rc;
        
        plugin = prelude_plugin_instance_get_data(pi);

        prelude_list_for_each(tmp, &plugin->rule_list) {
                rc = prelude_list_entry(tmp, pcre_rule_container_t, list);
                
                ret = rule_regex_match(rc, log_entry);
                
                if ( ret == 0 && rc->rule->last )
                        break;
        }
}




static int set_last_first(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        pcre_plugin_t *plugin = prelude_plugin_instance_get_data(context);
        
        plugin->last_rules_first = 1;
        
        return 0;
}




static int set_pcre_ruleset(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err) 
{
        int ret;
        FILE *fd;
        char *ptr;
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rc;
        pcre_plugin_t *plugin = prelude_plugin_instance_get_data(context);
        
        plugin->rulesetdir = strdup(optarg);

        ptr = strrchr(plugin->rulesetdir, '/');
        if ( ptr )
                *ptr = '\0';
        else {
                free(plugin->rulesetdir);
                plugin->rulesetdir = NULL;
        }
        
        fd = fopen(optarg, "r");
        if ( ! fd ) {
                prelude_string_sprintf(err, "couldn't open %s for reading", optarg);
                return -1;
        }
        
        ret = parse_ruleset(plugin, optarg, fd);

        fclose(fd);
        if ( plugin->rulesetdir )
                free(plugin->rulesetdir);
        
        if ( ret < 0 )
                return -1;

        log(LOG_INFO, "- pcre plugin added %d rules.\n", plugin->rulesnum);
        
        prelude_list_for_each_safe(tmp, bkp, &plugin->rule_list) {
                rc = prelude_list_entry(tmp, pcre_rule_container_t, list);

                if ( rc->rule->chained )
                        free_rule_container(rc);
        }

        return 0;
}



static int pcre_activate(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        pcre_plugin_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        PRELUDE_INIT_LIST_HEAD(&new->rule_list);
        prelude_plugin_instance_set_data(context, new);
        
        return 0;
}




static void pcre_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        prelude_list_t *tmp, *bkp;
        pcre_rule_container_t *rule;
        pcre_plugin_t *plugin = prelude_plugin_instance_get_data(pi);
        
        prelude_list_for_each_safe(tmp, bkp, &plugin->rule_list) {
                rule = prelude_list_entry(tmp, pcre_rule_container_t, list);
                free_rule_container(rule);
        }
        
        free(plugin);
}




prelude_plugin_generic_t *pcre_LTX_prelude_plugin_init(void)
{
        prelude_option_t *opt;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        opt = prelude_option_add(lml_root_optlist, hook, 0, "pcre", "Pcre plugin option",
                                PRELUDE_OPTION_ARGUMENT_OPTIONAL, pcre_activate, NULL);

        prelude_plugin_set_activation_option((void *) &pcre_plugin, opt, NULL);
        
        prelude_option_add(opt, hook, 'r', "ruleset", "Ruleset to use",
                                PRELUDE_OPTION_ARGUMENT_REQUIRED, set_pcre_ruleset, NULL);

        prelude_option_add(opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'p',
                                "pass-first", "Process rules with the \"last\" attribute first",
                                PRELUDE_OPTION_ARGUMENT_NONE, set_last_first, NULL);
        
        prelude_plugin_set_name(&pcre_plugin, "pcre");
        prelude_plugin_set_author(&pcre_plugin, "Yoann Vandoorselaere");
        prelude_plugin_set_contact(&pcre_plugin, "yoann@prelude-ids.org");
        prelude_plugin_set_running_func(&pcre_plugin, pcre_run);
        prelude_plugin_set_destroy_func(&pcre_plugin, pcre_destroy);
        
        return (void *) &pcre_plugin;
}
