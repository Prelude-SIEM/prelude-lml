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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pcre.h>
#include <netdb.h>

#include <libprelude/list.h>
#include <libprelude/common.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-strbuf.h>
#include <libprelude/prelude-getopt.h>

#include <assert.h>

#include "log-common.h"
#include "lml-alert.h"
#include "log.h"


/*
 * we can store up to 64 reference value in a rule
 * it should be large enough
 */

#define MAX_REFERENCE_PER_RULE 64


typedef struct {
	struct list_head list;
        
	char *value;
} rule_object_value_t;



typedef struct {
	struct list_head list;
        
	idmef_object_t *object;
	struct list_head rule_object_value_list;
} rule_object_t;



typedef struct {
	struct list_head list;

        int refno;
	char **value;
} rule_reference_value_t;



typedef struct {
	struct list_head list;

	pcre *regex;
	pcre_extra *extra;

	uint16_t id;
	uint16_t revision;

	int last;
	char *regex_string;

	struct list_head rule_object_list;
	struct list_head references_list;
} simple_rule_t;


static int parse_ruleset(const char *filename, FILE *fd);


static int rulesnum = 0;
static int is_enabled = 0;
static plugin_log_t plugin;
static LIST_HEAD(rule_list);
static char *rulesetdir = NULL;
static int last_rules_first = 0;




static int rule_reference_value_add(simple_rule_t *rule, unsigned int reference, char **value)
{
	rule_reference_value_t *reference_value;

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
        
	list_add_tail(&reference_value->list, &rule->references_list);

	return 0;
}



static void free_rule_reference_value_list_content(simple_rule_t *rule)
{
	struct list_head *tmp;
	rule_reference_value_t *reference_value;
	
        list_for_each(tmp, &rule->references_list) {
                reference_value = list_entry(tmp, rule_reference_value_t, list);

                free(*reference_value->value);
                *reference_value->value = NULL;
	}
}



static void resolve_rule_reference_value_list(const log_container_t *log,
					      simple_rule_t *rule, int *ovector, size_t osize) 
{
	 int ret;
	 char buf[1024];
         struct list_head *tmp;
	 rule_reference_value_t *rval;
         
         list_for_each(tmp, &rule->references_list) {
                 
                 rval = list_entry(tmp, rule_reference_value_t, list);
                 
                 ret = pcre_copy_substring(log->log, ovector, osize, rval->refno, buf, sizeof(buf));
                 if ( ret < 0 ) {
                         if ( ret == PCRE_ERROR_NOMEMORY ) 
                                 log(LOG_ERR, "not enough memory to get backward reference %d.\n", rval->refno);
                         
                         else if ( ret == PCRE_ERROR_NOSUBSTRING )
                                 log(LOG_ERR, "backward reference %d doesn exist.\n", rval->refno);
                         
                         else
                                 log(LOG_ERR, "unknown PCRE error while getting backward reference %d.\n", rval->refno);
                 }
                 
                 *rval->value = strdup(buf);
        }
}




static int parse_rule_id(simple_rule_t *rule, const char *id) 
{
        rule->id = (uint16_t) strtol(id, NULL, 0);

        return 0;
}



static int parse_rule_revision(simple_rule_t *rule, const char *revision) 
{
        rule->revision = (uint16_t) strtol(revision, NULL, 0);

        return 0;
}



static int parse_rule_regex(simple_rule_t *rule, const char *regex) 
{
        int err_offset;
        const char *err_ptr;

        rule->regex = pcre_compile(regex, 0, &err_ptr, &err_offset, NULL);
        if ( ! rule->regex ) {
                log(LOG_INFO, "unable to compile regex: %s.\n", err_ptr);
                return -1;
        }

        rule->regex_string = strdup(regex);
	if ( ! rule->regex_string ) {
		log(LOG_ERR, "memory exhausted.\n");
		return -1;
	}

        rule->extra = pcre_study(rule->regex, 0, &err_ptr);

        return 0;
}



static int parse_rule_last(simple_rule_t *rule, const char *last)
{
        rule->last = 1;

        return 0;
}



static int parse_include(const char *value) 
{
        int ret;
        FILE *fd;
        char filename[256];

        if ( rulesetdir && value[0] != '/' )
                snprintf(filename, sizeof(filename), "%s/%s", rulesetdir, value);
        else
                snprintf(filename, sizeof(filename), "%s", value);

        fd = fopen(filename, "r");
        if ( ! fd ) {
                log(LOG_ERR, "couldn't open %s for reading.\n", filename);
                return -1;
        }

        ret = parse_ruleset(filename, fd);

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
        while ( tmp && (*tmp == '=' || isspace(*tmp)) )
                *tmp-- = '\0';

        if ( ! ptr )
                /* key without value */
                return 0; 
        
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



static int parse_rule_keyword(simple_rule_t *rule,
			      const char *filename, int line,
			      const char *keyword, const char *value)
{
	int i;
	struct {
                const char *keyword;
                int (*func)(simple_rule_t *rule, const char *value);
        } keywords[] = {
                { "regex",		parse_rule_regex	},
                { "id",			parse_rule_id		},
                { "revision",		parse_rule_revision	},
		{ "last",		parse_rule_last		},
        };

	for ( i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++ ) {
		if ( strcmp(keyword, keywords[i].keyword) != 0 )
			continue;

		if ( keywords[i].func(rule, value) < 0 ) {
			log(LOG_INFO, "%s:%d: error parsing value for '%s'.\n", filename, line, keyword);
			return -1;
		}

		return 1;
	}

	return 0;
}



static int add_dynamic_object_value(simple_rule_t *rule, rule_object_t *rule_object,
				    unsigned int reference)
{
	rule_object_value_t *rovalue;

	rovalue = calloc(1, sizeof(*rovalue));
	if ( ! rovalue ) {
		log(LOG_ERR, "memory exhausted.\n");
		return -1;
	}

	if ( rule_reference_value_add(rule, reference, &rovalue->value) < 0 ) {
		free(rovalue);
		return -1;
	}

	list_add_tail(&rovalue->list, &rule_object->rule_object_value_list);

	return 0;		
}



static int add_fixed_object_value(rule_object_t *rule_object, prelude_strbuf_t *strbuf)
{
	rule_object_value_t *rovalue;

	rovalue = calloc(1, sizeof(*rovalue));
	if ( ! rovalue ) {
		log(LOG_ERR, "memory exhausted.\n");
		return -1;
	}

	prelude_strbuf_dont_own(strbuf);
	rovalue->value = prelude_strbuf_get_string(strbuf);

	list_add_tail(&rovalue->list, &rule_object->rule_object_value_list);

	return 0;
}



static int parse_rule_object_value(simple_rule_t *rule, rule_object_t *rule_object,
				   const char *line)
{
        int i;
        char num[10];
	const char *str;
	prelude_strbuf_t *strbuf;

	str = line;

	while ( *str ) {

                if ( *str == '$' && *(str + 1) != '$' ) {

                        i = 0;
			str++;
                        
			while ( isdigit(*str) && i < sizeof(num) )
				num[i++] = *str++;

			if ( ! i )
				return -1;

			num[i] = 0;

			if ( add_dynamic_object_value(rule, rule_object, atoi(num)) < 0 )
				return -1;

			continue;
		}

		strbuf = prelude_strbuf_new();
		if ( ! strbuf )
			return -1;

		while ( *str ) {
			if ( *str == '$' ) {
				if ( *(str + 1) == '$' )
					str++;
				else
					break;
			}

			if ( prelude_strbuf_ncat(strbuf, str, 1) < 0 )
				return -1;
			str++;
		}

		if ( add_fixed_object_value(rule_object, strbuf) < 0 )
			return -1;

		prelude_strbuf_destroy(strbuf);
	}

	return 0;
}



static int parse_rule_object(simple_rule_t *rule,
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

	INIT_LIST_HEAD(&rule_object->rule_object_value_list);
	rule_object->object = object;

	if ( parse_rule_object_value(rule, rule_object, value) < 0 ) {
		idmef_object_destroy(object);
		free(rule_object);
		return -1;
	}

	list_add_tail(&rule_object->list, &rule->rule_object_list);

	return 0;
}



static int parse_rule_entry(simple_rule_t *rule,
			    const char *filename, int line,
			    const char *key, const char *value)
{
	int ret;

	/*
	 * Do we have a keyword...
	 */
	ret = parse_rule_keyword(rule, filename, line, key, value);
	if ( ret == -1 || ret == 1 )
		return ret;

	/*
	 * ... or an idmef object
	 */
	return parse_rule_object(rule, filename, line, key, value);	
}



static simple_rule_t *create_rule(void)
{
	simple_rule_t *rule;

	rule = calloc(1, sizeof(*rule));
	if ( ! rule ) {
		log(LOG_ERR, "memory exhausted.\n");
		return NULL;
	}

        INIT_LIST_HEAD(&rule->references_list);
	INIT_LIST_HEAD(&rule->rule_object_list);

	return rule;
}



static void free_rule(simple_rule_t *rule) 
{
        if ( rule->regex_string )
                free(rule->regex_string);
        
        if ( rule->regex )
                pcre_free(rule->regex);

        if ( rule->extra )
                pcre_free(rule->extra);

	/* FIXME: free variable list */

        free(rule);
}



static int parse_ruleset_directive(const char *filename, int line, char *buf) 
{
	char *in;
	char *key;
	char *value;
	char *ptr = NULL;
        int first_directive = 1;
	simple_rule_t *rule = NULL;
        
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
                                parse_include(value);
                                return 0;
                        }
                        
			rule = create_rule();
			if ( ! rule )
				return -1;
			
			first_directive = 0;
		}
                
		if ( parse_rule_entry(rule, filename, line, key, value) < 0 ) {
			free_rule(rule);
			return -1;
		}
        }

	if ( ! rule->regex ) {
		log(LOG_ERR, "%s:%d: rule does not provide a regex.\n", filename, line);
		free_rule(rule);
		return -1;
	}

        if ( last_rules_first && rule->last )
                list_add(&rule->list, &rule_list);
        else
                list_add_tail(&rule->list, &rule_list);
        
	rulesnum++;

        return 0;
}



static int parse_ruleset(const char *filename, FILE *fd) 
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

		parse_ruleset_directive(filename, line, ptr);
        }

        return 0;
}



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



static idmef_value_t *build_message_object_value(rule_object_t *rule_object)
{
	rule_object_value_t *rovalue;
	idmef_value_t *value;
	prelude_strbuf_t *strbuf;
	struct list_head *tmp;
	char *str;

	strbuf = prelude_strbuf_new();
	if ( ! strbuf )
		return NULL;

	list_for_each(tmp, &rule_object->rule_object_value_list) {
		rovalue = list_entry(tmp, rule_object_value_t, list);

                if ( prelude_strbuf_cat(strbuf, rovalue->value) < 0 ) {
			prelude_strbuf_destroy(strbuf);
			return NULL;
		}
	}

	str = prelude_strbuf_get_string(strbuf);

	if ( strrncmp(idmef_object_get_name(rule_object->object), ".port") == 0 && ! isdigit(*str) ) {
		struct servent *service;

		service = getservbyname(str, NULL);
		if ( ! service ) {
			log(LOG_ERR, "Service name '%s' could not be found in /etc/services.\n", str);
			return NULL;
		}

		value = idmef_value_new_uint16(ntohs(service->s_port));

	} else {
		value = idmef_value_new_for_object(rule_object->object, str);
	}

	prelude_strbuf_destroy(strbuf);
	
	return value;
}



static idmef_message_t *build_message(simple_rule_t *rule)
{
	idmef_message_t *message;
	struct list_head *tmp;
	rule_object_t *rule_object;
	idmef_value_t *value;
	int ret;

	message = idmef_message_new();
	if ( ! message )
		return NULL;

	list_for_each(tmp, &rule->rule_object_list) {
		rule_object = list_entry(tmp, rule_object_t, list);

                value = build_message_object_value(rule_object);
		if ( ! value ) {
			idmef_message_destroy(message);
			return NULL;
                }

		ret = idmef_message_set(message, rule_object->object, value);

		idmef_value_destroy(value);

		if ( ret < 0 ) {
			log(LOG_ERR, "idmef_message_set failed.\n");
			idmef_message_destroy(message);
			return NULL;
		}
	}

	return message;
}



static void simple_run(const log_container_t *log)
{
        int ret;
        simple_rule_t *rule;
        struct list_head *tmp;
        int ovector[MAX_REFERENCE_PER_RULE * 3];
        
        list_for_each(tmp, &rule_list) {
                rule = list_entry(tmp, simple_rule_t, list);

		ret = pcre_exec(rule->regex, rule->extra, log->log,
                                strlen(log->log), 0, 0, ovector, sizeof(ovector) / sizeof(int) );
		if ( ret < 0 )
                        continue;

                resolve_rule_reference_value_list(log, rule, ovector, ret);

                if ( ! list_empty(&rule->rule_object_list) ) 
                        lml_emit_alert(log, build_message(rule), PRELUDE_MSG_PRIORITY_MID);
                
                free_rule_reference_value_list_content(rule);

                if ( rule->last )
                        break;
        }
}



static int set_simple_state(prelude_option_t *opt, const char *optarg)
{
        int ret;
        
        if ( is_enabled ) {
		ret = plugin_unsubscribe((plugin_generic_t *) & plugin);
		if ( ret < 0 )
			return prelude_option_error;

		is_enabled = 0;
	}

	else {
		ret = plugin_subscribe((plugin_generic_t *) & plugin);
		if ( ret < 0 )
			return prelude_option_error;

		is_enabled = 1;
	}

	return prelude_option_success;
}




static int set_last_first(prelude_option_t *opt, const char *arg)
{
        last_rules_first = 1;
        
        return prelude_option_success;
}




static int set_simple_ruleset(prelude_option_t *opt, const char *arg) 
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

        opt = prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'p', "pass-first",
                                 "Process rules with the \"last\" attribute first", no_argument,
                                 set_last_first, NULL);
        prelude_option_set_priority(opt, option_run_first);
        
	plugin_set_name(&plugin, "SimpleMod");
	plugin_set_author(&plugin, "Yoann Vandoorselaere");
	plugin_set_contact(&plugin, "yoann@prelude-ids.org");
	plugin_set_running_func(&plugin, simple_run);

	return (plugin_generic_t *) &plugin;
}
