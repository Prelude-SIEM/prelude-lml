/*****
*
* Copyright (C) 1998 - 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <inttypes.h>
#include <sys/types.h>
#include <pcre.h>

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-msg-send.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/prelude-getopt.h>

#include "log-common.h"
#include "lml-alert.h"
#include "log.h"

#define VARIABLE_TYPE_INT    0
#define VARIABLE_TYPE_STRING 1


#define generic_free_list(type, head) do {           \
        type *decl;                                  \
        struct list_head *tmp;                       \
                                                     \
        for (tmp = (head)->next; tmp != (head); ) {  \
                decl = list_entry(tmp, type, list);  \
                tmp = tmp->next;                     \
                free(decl);                          \
        }                                            \
} while (0)


typedef struct {
        void *ptr;
        int type;
        int reference;
        char *reference_str;
        idmef_string_t unexpanded;
        struct list_head list;
} variable_t;



typedef struct {
        pcre *regex;
        pcre_extra *extra;
        char *regex_string;
        idmef_impact_t *impact;  
        idmef_classification_t *class;
        idmef_source_t *source;
        struct list_head variable_list;
        struct list_head list;
} simple_rule_t;


static int parse_ruleset(const char *filename, FILE *fd);


static int rulesnum = 0;
static int is_enabled = 0;
static plugin_log_t plugin;
static LIST_HEAD(rules_list);
static char *rulesetdir = NULL;


static int parse_class_origin(simple_rule_t *rule, const char *origin, int *var_type, void **var_ptr) 
{
        int i;
        struct {
                const char *name;
                idmef_classification_origin_t origin;
        } tbl[] = {
                { "unknown", origin_unknown },
                { "bugtraqid", bugtraqid    },
                { "cve", cve                },
                { "vendor-specific", vendor_specific },
                { NULL, 0 },
        };
        
        for ( i = 0; tbl[i].name != NULL; i++ ) {

                if ( strcmp(origin, tbl[i].name) != 0 )
                        continue;

                if ( ! rule->class && ! (rule->class = calloc(1, sizeof(*rule->class))) ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                *var_type = VARIABLE_TYPE_INT;
                *var_ptr = &rule->class->origin;
                
                rule->class->origin = tbl[i].origin;

                return 0;
        }

        return -1;
}




static int parse_class_name(simple_rule_t *rule, const char *name, int *var_type, void **var_ptr) 
{
        if ( ! rule->class && ! (rule->class = calloc(1, sizeof(*rule->class))) ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        *var_type = VARIABLE_TYPE_STRING;
        *var_ptr = &rule->class->name;
        
        idmef_string_set(&rule->class->name, strdup(name));

        return 0;
}




static int parse_class_url(simple_rule_t *rule, const char *url, int *var_type, void **var_ptr) 
{
        if ( ! rule->class && ! (rule->class = calloc(1, sizeof(*rule->class))) ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        *var_type = VARIABLE_TYPE_STRING;
        *var_ptr = &rule->class->url;
        
        idmef_string_set(&rule->class->url, strdup(url));

        return 0;
}




static int parse_impact_completion(simple_rule_t *rule, const char *completion, int *var_type, void **var_ptr) 
{
        int i;
        struct {
                const char *name;
                idmef_impact_completion_t completion;
        } tbl[] = {
                { "failed", failed       },
                { "succeeded", succeeded },
                { NULL, 0 },
        };

        for ( i = 0; tbl[i].name != NULL; i++ ) {
                
                if ( strcmp(completion, tbl[i].name) != 0 )
                        continue;

                if ( ! rule->impact && ! (rule->impact = calloc(1, sizeof(*rule->impact))) ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                *var_type = VARIABLE_TYPE_INT;
                *var_ptr = &rule->impact->completion;
                
                rule->impact->completion = tbl[i].completion;

                return 0;
        }

        return -1;
}




static int parse_impact_type(simple_rule_t *rule, const char *type, int *var_type, void **var_ptr) 
{
        int i;
        struct {
                const char *name;
                idmef_impact_type_t type;
        } tbl[] = {
                { "other", other },
                { "admin", admin },
                { "dos", dos     },
                { "file", file   },
                { "recon", recon },
                { "user", user   },
                { NULL, 0        },
        };

        for ( i = 0; tbl[i].name != NULL; i++ ) {

                if ( strcmp(type, tbl[i].name) != 0 )
                        continue;

                if ( ! rule->impact && ! (rule->impact = calloc(1, sizeof(*rule->impact))) ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                *var_type = VARIABLE_TYPE_INT;
                *var_ptr = &rule->impact->type;
                
                rule->impact->type = tbl[i].type;

                return 0;
        }

        return -1;
}




static int parse_impact_severity(simple_rule_t *rule, const char *severity, int *var_type, void **var_ptr) 
{
        int i;
        struct {
                const char *name;
                idmef_impact_severity_t severity;
        } tbl[] = {
                { "low", impact_low       },
                { "medium", impact_medium },
                { "high", impact_high     },
                { NULL, 0                 },
        };

        for ( i = 0; tbl[i].name != NULL; i++ ) {

                if ( strcmp(severity, tbl[i].name) != 0 )
                        continue;

                if ( ! rule->impact && ! (rule->impact = calloc(1, sizeof(*rule->impact))) ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                *var_type = VARIABLE_TYPE_INT;
                *var_ptr = &rule->impact->severity;
                rule->impact->severity = tbl[i].severity;

                return 0;
        }

        return -1;
}



static int parse_impact_desc(simple_rule_t *rule, const char *desc, int *var_type, void **var_ptr) 
{
        if ( ! rule->impact && ! (rule->impact = calloc(1, sizeof(*rule->impact))) ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        *var_type = VARIABLE_TYPE_STRING;
        *var_ptr  = &rule->impact->description;
        
        idmef_string_set(&rule->impact->description, strdup(desc));
        
        return 0;
}



static int parse_regex(simple_rule_t *rule, const char *regex, int *var_type, void **var_ptr) 
{
        int erroffset;
        const char *errptr;

        rule->regex = pcre_compile(regex, 0, &errptr, &erroffset, NULL);
        if ( ! rule->regex ) {
                log(LOG_INFO, "unable to compile regex: %s.\n", errptr);
                return -1;
        }
        
        rule->regex_string = strdup(regex);
        rule->extra = pcre_study(rule->regex, 0, &errptr);
        
        return 0;
}


/*
 * arno (29/04/02) : new function for new imdef field : source.node.address.address
 */
static int parse_source_node_address_address(simple_rule_t *rule, const char *address, int *var_type, void **var_ptr) 
{
        idmef_node_t *idmef_node;
        idmef_address_t *idmef_address;
        
        if ( ! rule->source && ! (rule->source = calloc(1, sizeof(*rule->source))) ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        if ( ! rule->source->node ) {
                if ( ! (idmef_node = idmef_source_node_new(rule->source)) ) {
                        log(LOG_ERR, "memory exhauster.\n");
                        return -1;
                }
        }
        else
                idmef_node = rule->source->node;

        if ( ! (idmef_address = idmef_node_address_new(idmef_node)) ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        *var_type = VARIABLE_TYPE_STRING;
        *var_ptr  = &idmef_address->address;
        
        idmef_string_set(&idmef_address->address, strdup(address));
        
        return 0;
}



static int filter_string(char *input, char **key, char **value) 
{
        char *ptr, *tmp;

         /*
         * filter space at the begining of the line.
         */
        while ( *input == ' ' && *input != '\0' )
                input++;

        if ( *input == '\0' )
                return 0;
        
        *key = input;

        /*
         * search last '=' in the input,
         * corresponding to the key = value separator.
         */
        tmp = ptr = strchr(input, '=');
        if ( ! ptr ) 
                return -1;

        /*
         * strip whitespace at the tail of the key.
         */
        while ( *tmp == '=' || isspace(*tmp) )
                *tmp-- = '\0';
        
        /*
         * strip whitespace at the begining of the value.
         */
        ptr++;
        while ( *ptr != '\0' && isspace(*ptr) )
                ptr++;

        *value = ptr;

        /*
         * strip whitespace at the end of the value.
         */
        ptr = ptr + strlen(ptr) - 1;
        while ( isspace(*ptr) )
                *ptr-- = '\0';
        
        return 0;
}




static int store_runtime_variable(simple_rule_t *rule, const char *line, int var_type, void *var_ptr) 
{
        char c;
        const char *str;
        char outvar[10];
        variable_t *new;
        int escaped = 0, is_variable = 0, i = 0;

        str = line;
        
        while ( (c = *str++) != '\0' ) {

                if ( escaped ) {
                        escaped = 0;
                        continue;
                }
                
                if ( c == '\\' )
                        escaped = 1;

                else if ( c == '$' && ! escaped ) {
                        is_variable = 1;
                        outvar[i++] = c;
                        continue;
                }

                if ( ! is_variable )
                        continue;

                if ( i >= sizeof(outvar) ) {
                        log(LOG_ERR, "variable name exceed buffer size.\n");
                        is_variable = 0;
                        continue;
                }
                
                if ( isdigit(c) ) 
                        outvar[i++] = c;
                        
                if ( ! isdigit(c) || *str == '\0' ) {
                        is_variable = 0;
                        outvar[i] = '\0';
                        i = 0;
                        
                        new = malloc(sizeof(*new));
                        if ( ! new ) {
                                log(LOG_ERR, "memory exhausted.\n");
                                return -1;
                        }
                                                
                        new->ptr = var_ptr;
                        new->type = var_type;
                        new->reference = atoi(outvar + 1);
                        new->reference_str = strdup(outvar);
                        idmef_string_set(&new->unexpanded, strdup(line));
                                                
                        list_add_tail(&new->list, &rule->variable_list);
                        continue;
                }
        }

        return 0;
}




static int parse_include(simple_rule_t *rule, const char *value, int *var_type, void **var_ptr) 
{
        int ret;
        FILE *fd;
        char filename[256];

        if ( rulesetdir && value[0] != '/' )
                snprintf(filename, sizeof(filename), "%s/%s", rulesetdir, value);
        else
                strncpy(filename, value, sizeof(filename));
        
        fd = fopen(filename, "r");
        if ( ! fd ) {
                log(LOG_ERR, "couldn't open %s for reading.\n", filename);
                return -1;
        }

        ret = parse_ruleset(filename, fd);
        if ( ret < 0 )
                return -1;

        return -2;
}




static int parse_rule(const char *filename, int line, simple_rule_t *rule, char *buf) 
{
        void *var_ptr;
        int i, ret, var_type;
        char *in, *ptr, *key, *val;
        struct {
                const char *key;
                int (*func)(simple_rule_t *rule, const char *value, int *var_type, void **var_ptr);
        } tbl[] = {
                { "include", parse_include                                          },
                { "regex", parse_regex                                              },
                { "class.origin", parse_class_origin                                },
                { "class.name", parse_class_name                                    },
                { "class.url", parse_class_url                                      },
                { "impact.completion", parse_impact_completion                      },
                { "impact.type",       parse_impact_type                            },
                { "impact.severity",   parse_impact_severity                        },
                { "impact.description", parse_impact_desc                           },
                { "source.node.address.address", parse_source_node_address_address  },
                { NULL, NULL                                                        },
        };

        ptr = buf;
        while ( (in = strtok(ptr, ";")) ) {
                ptr = NULL;
                
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
                                
                ret = filter_string(in, &key, &val);
                if ( ret < 0 ) {
                        log(LOG_INFO, "%s:%d: no string delimiter.\n", filename, line);
                        return -1;
                }
                
                for ( i = 0; tbl[i].key != NULL; i++ ) {
                        if ( strcmp(key, tbl[i].key) != 0 )
                                continue;
                        
                        ret = tbl[i].func(rule, val, &var_type, &var_ptr);
                        if ( ret < 0 ) {
                                if ( ret == -1 )
                                        log(LOG_INFO, "%s:%d: error parsing value for '%s'.\n", filename, line, key);
                                return -1;
                        }

                        ret = store_runtime_variable(rule, val, var_type, var_ptr);
                                
                        break;
                }
                
                if ( tbl[i].key == NULL ) {
                        log(LOG_INFO, "%s:%d: unknown key : '%s'.\n", filename, line, key);
                        return -1;
                }
        }

        return 0;
}




static void free_rule(simple_rule_t *rule) 
{
        if ( rule->regex_string )
                free(rule->regex_string);
        
        if ( rule->regex )
                pcre_free(rule->regex);

        if ( rule->extra )
                pcre_free(rule->extra);
        
        if ( rule->impact )
                free(rule->impact);

        if ( rule->class )
                free(rule->class);

        /*** arno (29/04/02) ***/

        if ( rule->source ) {
                if ( rule->source->node ) {
                        generic_free_list(idmef_address_t, &rule->source->node->address_list);
                        free(rule->source->node);
                }

                free(rule->source);
        } 

        free(rule);
}




static int parse_ruleset(const char *filename, FILE *fd) 
{
        int ret, line = 0;
        simple_rule_t *rule;
        char buf[1024], *ptr;
        
        while ( fgets(buf, sizeof(buf), fd) ) {

                line++;
                ptr = buf;
                buf[strlen(buf) - 1] = '\0'; /* strip \n */

                 /*
                  * filter space at the begining of the line.
                  */
                while ( *ptr == ' ' && *ptr != '\0' )
                        ptr++;
                
                /*
                 * empty line or comment. 
                 */
                if ( *ptr == '\0' || *ptr == '#' )
                        continue;
                
                rule = calloc(1, sizeof(*rule));
                if ( ! rule ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                INIT_LIST_HEAD(&rule->variable_list);
                
                ret = parse_rule(filename, line, rule, ptr);
                if ( ret < 0 ) {
                        free_rule(rule);
                        continue;
                }

                list_add_tail(&rule->list, &rules_list);
                rulesnum++;
        }
        
        return 0;
}




static void emit_alert(simple_rule_t *rule, const log_container_t *log) 
{
        idmef_alert_t *alert;
        idmef_message_t *message;
        idmef_classification_t *class;
        idmef_assessment_t *assessment;
        idmef_source_t *source;
        idmef_node_t *node;
        idmef_address_t *address;
        idmef_address_t *address_tmp;
        
        struct list_head *tmp;
        
        message = idmef_message_new();
        if ( ! message )
                return;

        /*
         * Initialize the idmef structures
         */
        idmef_alert_new(message);
        alert = message->message.alert;
        
        idmef_alert_assessment_new(alert);
        assessment = alert->assessment;

        if ( rule->impact ) 
                assessment->impact = rule->impact;
        
        if ( rule->class ) {
            
                class = idmef_alert_classification_new(alert);
                if ( ! class ) {
                        idmef_message_free(message);
                        return;
                }

                class->origin = rule->class->origin;
                idmef_string_copy(&class->url, &rule->class->url);
                idmef_string_copy(&class->name, &rule->class->name);
        }

        /*** arno (30/04/02) ***/

        if ( rule->source ) {
                
                source = idmef_alert_source_new(alert);

                if ( ! source ) {
                        idmef_message_free(message);
                        return;
                }

                node = idmef_source_node_new(source);

                if ( ! node ) {
                        idmef_message_free(message);
                        return;
                }

                address = idmef_node_address_new(node);

                if ( ! address ) {
                        idmef_message_free(message);
                        return;
                }
                
                list_for_each(tmp, &rule->source->node->address_list) {
                        address_tmp = list_entry(tmp, idmef_address_t, list);
                        idmef_string_copy(&address->address, &address_tmp->address);
                }
        }
        
        lml_emit_alert(log, message, PRELUDE_MSG_PRIORITY_MID);
}


static int replace_str(idmef_string_t *str, const char *needle, const char *replacement) 
{
        char *ptr, *out;
        int off, new_len, replacement_len, needle_len;
        
        ptr = strstr(str->string, needle);
        if ( ! ptr ) {
                log(LOG_ERR, "couldn't find %s!\n", needle);
                return -1;
        }

        needle_len = strlen(needle);
        replacement_len = strlen(replacement);

        /*
         * compute the offset where needle start.
         * (idmef string count \0 in len, that's the reason of the + 1).
         */
        off = str->len - (strlen(ptr) + 1);
        new_len = str->len + replacement_len - needle_len;
        
        out = malloc(new_len);
        if ( ! out ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        memcpy(out, str->string, off);
        memcpy(out + off, replacement, replacement_len);
        strcpy(out + off + replacement_len, ptr + needle_len);

        free(str->string);
        str->string = out;
        str->len = new_len;

        return 0;
}




static void resolve_variable(const log_container_t *log,
                             simple_rule_t *rule, int *ovector, size_t osize) 
{
        int ret;
        char buf[1024];
        variable_t *var;
        struct list_head *tmp;
        
        list_for_each(tmp, &rule->variable_list){
                var = list_entry(tmp, variable_t, list);
                
                ret = pcre_copy_substring(log->log, ovector, osize, var->reference, buf, sizeof(buf));
                if ( ret < 0 ) {
                        if ( ret == PCRE_ERROR_NOMEMORY ) 
                                log(LOG_ERR, "not enough memory to get backward reference %d.\n", var->reference);

                        else if ( ret == PCRE_ERROR_NOSUBSTRING )
                                log(LOG_ERR, "backward reference %d doesn exist.\n", var->reference);

                        else
                                log(LOG_ERR, "unknown PCRE error while getting backward reference %d.\n", var->reference);

                        continue;
                }
                
                
                if ( var->type == VARIABLE_TYPE_INT ) 
                        *(int *) var->ptr = atoi(buf);
                
                else if ( var->type == VARIABLE_TYPE_STRING ) 
                        replace_str(var->ptr, var->reference_str, buf);
        }
}



static void free_variable_allocated_data(simple_rule_t *rule) 
{
        variable_t *var;
        idmef_string_t *str;
        struct list_head *tmp;

        list_for_each(tmp, &rule->variable_list) {

                var = list_entry(tmp, variable_t, list);

                if ( var->type == VARIABLE_TYPE_STRING ) {
                        str = var->ptr;
                        free(str->string);
                        str->len = idmef_string_len(&var->unexpanded);
                        str->string = strdup(idmef_string(&var->unexpanded));
                }
        }
}





static void simple_run(const log_container_t *log)
{
        int ret;
        int ovector[100];
        simple_rule_t *rule;
        struct list_head *tmp;
        
        list_for_each(tmp, &rules_list) {
                rule = list_entry(tmp, simple_rule_t, list);
                                
                ret = pcre_exec(rule->regex, rule->extra, log->log,
                                strlen(log->log), 0, 0, ovector, 100);
                if ( ret < 0 )
                        continue;
                
                printf("[%s]: matched %s\n", log->source, rule->regex_string);
                                
                resolve_variable(log, rule, ovector, ret);
                emit_alert(rule, log);
                free_variable_allocated_data(rule);
        }
}




static int set_simple_state(const char *optarg)
{
        int ret;
        
        if ( is_enabled ) {
		ret = plugin_unsubscribe((plugin_generic_t *) & plugin);
		if ( ret < 0 )
			return prelude_option_error;

		is_enabled = 0;
	} else {
		ret = plugin_subscribe((plugin_generic_t *) & plugin);
		if ( ret < 0 )
			return prelude_option_error;

		is_enabled = 1;
	}

	return prelude_option_success;
}




static int set_simple_ruleset(const char *arg) 
{
        int ret;
        FILE *fd;
        char *ptr;
        
        rulesetdir = strdup(arg);

        ptr = strrchr(rulesetdir, '/');
        if ( ptr )
                *ptr = '\0';
        else {
                free(rulesetdir);
                rulesetdir = NULL;
        }
        
        fd = fopen(arg, "r");
        if ( ! fd ) {
                log(LOG_ERR, "couldn't open %s for reading.\n", arg);
                return prelude_option_error;
        }
        
        ret = parse_ruleset(arg, fd);

        fclose(fd);
        if ( rulesetdir )
                free(rulesetdir);
        
        if ( ret < 0 )
                return prelude_option_error;

        log(LOG_INFO, "- SimpleMod plugin added %d rules.\n", rulesnum);
        
        return prelude_option_success;
}




plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt;

	opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 0, "simplemod",
                                 "Simple plugin option", no_argument,
                                 set_simple_state, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'r', "ruleset",
                           "Ruleset to use", required_argument,
                           set_simple_ruleset, NULL);
        
	plugin_set_name(&plugin, "SimpleMod");
	plugin_set_author(&plugin, "Yoann Vandoorselaere");
	plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
	plugin_set_running_func(&plugin, simple_run);

	return (plugin_generic_t *) & plugin;
}





