#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "common.h"
#include "regex.h"

struct regex_entry {
	pcre *regex_compiled;
	pcre_extra *regex_extra;
	int options;
	char *name;
	struct list_head int_list;
};



static char *trim(char *str)
{
	char *ibuf, *obuf;

	if ( ! str )
		return NULL;

	for ( ibuf = str, obuf = str; *ibuf; ) {
		while ( *ibuf && isspace(*ibuf) )
			ibuf++;
                
		if ( *ibuf && (obuf != str) )
			*(obuf++) = ' ';
                
		while (*ibuf && (!isspace(*ibuf)))
			*(obuf++) = *(ibuf++);
	}
	*obuf = '\0';

	return str;
}




static regex_entry_t *regex_entry_new(regex_list_t *list)
{
	regex_entry_t *new;

        new = malloc(sizeof(*new));
	if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

	new->regex_compiled = NULL;
	new->regex_extra = NULL;
	new->options = 0;
	new->name = NULL;

	list_add_tail(&new->int_list, list);

	return new;
}




static void regex_entry_delete(regex_entry_t *entry)
{
	list_del(&entry->int_list);
        
	pcre_free(entry->regex_compiled);
	pcre_free(entry->regex_extra);

        free(entry->name);
	free(entry);
}




regex_list_t *regex_init(char *filename)
{
	FILE *f;
	int line = 1;

	regex_list_t *conf = malloc(sizeof(*conf));
	assert(conf);
	INIT_LIST_HEAD(conf);

	f = fopen(filename, "r");
	if (NULL == f) {
		log(LOG_ERR, "couldn't open config file.\n");
		return NULL;
	}

	while (!feof(f)) {
		char *token;
		char buf[MAX_LINE_LEN];
		char name[MAX_NAME_LEN];
		char regex[MAX_LINE_LEN];
		char options[MAX_OPTIONS_LEN];
		char *tmp = NULL;

		if (fgets(buf, MAX_LINE_LEN, f) == NULL)
			break;

		trim(buf);
		//sscanf( buf, "%s %s %*s\n", name, options, regex );

		token = strtok_r(buf, " \t", &tmp);
		if (NULL == token) {
			line++;
			continue;
		}
		strncpy(name, token, MAX_NAME_LEN);

		token = strtok_r(NULL, " \t", &tmp);
		if (NULL == token) {
			line++;
			continue;
		}
		strncpy(options, token, MAX_OPTIONS_LEN);

		token = strtok_r(NULL, "", &tmp);
		if (NULL == token) {
			line++;
			continue;
		}
		strncpy(regex, token, MAX_LINE_LEN);

		/* ignore comments and empty lines */
		if (buf[0] != '#' && buf[0] != '\0') {
			const char *errptr;
			int erroffset;
			regex_entry_t *entry;
			pcre *compiled;

			compiled =  pcre_compile(regex, 0, &errptr, &erroffset, NULL);
			if (NULL == compiled) {
				log(LOG_WARNING, "%s:%d : unable to compile: %s\n",
				    filename, line, errptr);
				continue;
			}
                        
			entry = regex_entry_new(conf);
			entry->name = strdup(name);
			entry->regex_compiled = compiled;
			entry->regex_extra = pcre_study(entry->regex_compiled, 0, &errptr);

			/*
			 * TBD: take care of options field
			 */

			dprint("[REGEX] rule found: plugin: %s - pattern: %s - options: %s\n",
                               name, regex, options);
		}
		line++;
	}

	return conf;
}




void regex_destroy(regex_list_t *list)
{
        regex_entry_t *entry;
	struct list_head *tmp, *bkp;

	list_for_each_safe(tmp, bkp, list) {
		entry = list_entry(tmp, regex_entry_t, int_list);
		regex_entry_delete(entry);
	}
        
	free(list);
}




int regex_exec(regex_list_t *list, const char *str,
               void (*cb)(const char *name, void *data), void *data)
{
        regex_entry_t *entry;
	struct list_head *tmp;
        int count, ovector[20 * 3];
        
	list_for_each(tmp, list) {
                entry = list_entry(tmp, regex_entry_t, int_list);

		count = pcre_exec(entry->regex_compiled, entry->regex_extra,
                                  str, strlen(str), 0, 0, ovector, 20 * 3);
                if ( count <= 0 )
                        continue;
                
                dprint("[REGEX] string <%s> matched - count = %d - plugin: %s\n",
                       str, count, entry->name);

                cb(entry->name, data);
	}
        
	return 0;
}
