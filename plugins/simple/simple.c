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



typedef struct {
        pcre *regex;
        pcre_extra *extra;
        char *regex_string;
        idmef_impact_t *impact;  
        idmef_classification_t *class;
        struct list_head list;
} simple_rule_t;



static int is_enabled = 0;
static plugin_log_t plugin;
static LIST_HEAD(rules_list);


static int parse_class_origin(simple_rule_t *rule, const char *origin) 
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
                
                rule->class->origin = tbl[i].origin;

                return 0;
        }

        return -1;
}




static int parse_class_name(simple_rule_t *rule, const char *name) 
{
        if ( ! rule->class && ! (rule->class = calloc(1, sizeof(*rule->class))) ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        idmef_string_set(&rule->class->name, strdup(name));

        return 0;
}




static int parse_class_url(simple_rule_t *rule, const char *url) 
{
        if ( ! rule->class && ! (rule->class = calloc(1, sizeof(*rule->class))) ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        idmef_string_set(&rule->class->url, strdup(url));

        return 0;
}




static int parse_impact_completion(simple_rule_t *rule, const char *completion) 
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
                
                rule->impact->completion = tbl[i].completion;

                return 0;
        }

        return -1;
}




static int parse_impact_type(simple_rule_t *rule, const char *type) 
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
                
                rule->impact->type = tbl[i].type;

                return 0;
        }

        return -1;
}




static int parse_impact_severity(simple_rule_t *rule, const char *severity) 
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
                
                rule->impact->severity = tbl[i].severity;

                return 0;
        }

        return -1;
}




static int parse_regex(simple_rule_t *rule, const char *regex) 
{
        int erroffset;
        const char *errptr;
        
        rule->regex = pcre_compile(regex, 0, &errptr, &erroffset, NULL);
        if ( ! rule->regex ) {
                log(LOG_INFO, "unable to compile regex: %s.\n", errptr);
                return -1;
        }

        rule->extra = pcre_study(rule->regex, 0, &errptr);

        rule->regex_string = strdup(regex);
        
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
        tmp = ptr = strrchr(input, '=');
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
        ptr = ptr + strlen(ptr);
        while ( isspace(*ptr) )
                *ptr-- = '\0';

        /* printf("key=\"%s\" val=\"%s\"\n", *key, *value); */

        return 0;
}




static int parse_rule(const char *filename, int line, simple_rule_t *rule, char *buf) 
{
        int i, ret;
        char *in, *ptr, *key, *val;
        struct {
                const char *key;
                int (*func)(simple_rule_t *rule, const char *value);
        } tbl[] = {
                { "regex", parse_regex                         },
                { "class.origin", parse_class_origin           },
                { "class.name", parse_class_name               },
                { "class.url", parse_class_url                 },
                { "impact.completion", parse_impact_completion },
                { "impact.type",       parse_impact_type       },
                { "impact.severity",   parse_impact_severity   },
                { NULL, NULL                                   },
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
                        
                        if ( strcmp(key, tbl[i].key) == 0 ) {
                                
                                ret = tbl[i].func(rule, val);
                                if ( ret < 0 ) {
                                        log(LOG_INFO, "%s:%d: error parsing value for '%s'.\n", filename, line, key);
                                        return -1;
                                }
                                
                                break;
                        }
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

        free(rule);
}




static int parse_ruleset(const char *filename, FILE *fd) 
{
        simple_rule_t *rule;
        char buf[1024], *ptr;
        int ret, line = 0, rulenum = 0;
        
        while ( fgets(buf, sizeof(buf), fd) ) {

                line++;
                ptr = buf;

                 /*
                  * filter space at the begining of the line.
                  */
                while ( *ptr == ' ' && *ptr != '\0' )
                        ptr++;
                
                /*
                 * empty line or comment. 
                 */
                if ( *ptr == '\0' || *ptr == '\n' || *ptr == '#' )
                        continue;
                
                rule = calloc(1, sizeof(*rule));
                if ( ! rule ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                ret = parse_rule(filename, line, rule, ptr);
                if ( ret < 0 ) {
                        free_rule(rule);
                        continue;
                }

                list_add_tail(&rule->list, &rules_list);
                rulenum++;
        }

        log(LOG_INFO, "- Simple plugin added %d rules.\n", rulenum);
        
        return 0;
}




static void emit_alert(simple_rule_t *rule, const log_container_t *log) 
{
        idmef_alert_t *alert;
        idmef_message_t *message;
        idmef_classification_t *class;
        idmef_assessment_t *assessment;
        
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

        lml_emit_alert(log, message, PRELUDE_MSG_PRIORITY_MID);
}




static void simple_run(const log_container_t *log)
{
        int ret;
        simple_rule_t *rule;
        struct list_head *tmp;

        list_for_each(tmp, &rules_list) {
                rule = list_entry(tmp, simple_rule_t, list);
                                
                ret = pcre_exec(rule->regex, rule->extra, log->log,
                                strlen(log->log), 0, 0, NULL, 0);
                if ( ret < 0 )
                        continue;

                printf("matched %s\n", rule->regex_string);
                emit_alert(rule, log);
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
        
        fd = fopen(arg, "r");
        if ( ! fd ) {
                log(LOG_ERR, "couldn't open %s for reading.\n", arg);
                return prelude_option_error;
        }
        
        ret = parse_ruleset(arg, fd);

        fclose(fd);
        
        if ( ret < 0 )
                return prelude_option_error;
        
        return prelude_option_success;
}




plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt;

	opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 0, "simplemod",
                                 "Simple plugin option", no_argument,
                                 set_simple_state, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'r', "ruleset",
                           "Ruleset to user", required_argument,
                           set_simple_ruleset, NULL);
        
	plugin_set_name(&plugin, "SimpleMod");
	plugin_set_author(&plugin, "Yoann Vandoorselaere");
	plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
	plugin_set_running_func(&plugin, simple_run);

	return (plugin_generic_t *) & plugin;
}





