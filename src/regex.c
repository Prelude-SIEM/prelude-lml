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
#include "log-common.h"
#include "plugin-log-prv.h"


struct regex_entry {
        pcre *regex_compiled;
        pcre_extra *regex_extra;
        int options;
        plugin_container_t *plugin;
        struct list_head list;
};



static char *trim(char *str)
{
        char *ibuf, *obuf;

        if ( ! str )
                return NULL;

        for ( ibuf = str, obuf = str; *ibuf; ) {
                while ( *ibuf && isspace((int) *ibuf) )
                        ibuf++;
                
                if ( *ibuf && (obuf != str) )
                        *(obuf++) = ' ';
                
                while ( *ibuf && (!isspace((int) *ibuf)) )
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

        list_add_tail(&new->list, list);

        return new;
}




static void regex_entry_delete(regex_entry_t *entry)
{
        list_del(&entry->list);

        if ( entry->regex_compiled )
                pcre_free(entry->regex_compiled);

        if ( entry->regex_extra )
                pcre_free(entry->regex_extra);
        
        free(entry);
}




static int regex_create_entry(regex_list_t *list, const char *filename,
                              int line, const char *pname, const char *regex, const char *options) 
{
        int erroffset;
        pcre *compiled;
        const char *errptr;
        regex_entry_t *entry;
        
        compiled = pcre_compile(regex, 0, &errptr, &erroffset, NULL);
        if ( ! compiled ) {
                log(LOG_INFO, "%s:%d : unable to compile: %s.\n", filename, line, errptr);
                return -1;
        }
        
        entry = regex_entry_new(list);
        if ( ! entry ) {
                pcre_free(compiled);
                return -1;
        }
        
        entry->regex_compiled = compiled;
        entry->regex_extra = pcre_study(entry->regex_compiled, 0, &errptr);

        entry->plugin = log_plugin_register(pname);
        if ( ! entry->plugin ) {
                regex_entry_delete(entry);
                log(LOG_INFO, "%s:%d : couldn't find plugin: %s.\n", filename, line, pname);
        }
        
        /*
         * TBD: take care of options field
         */
        
        dprint("[REGEX] rule found: plugin: %s - pattern: %s - options: %s\n", pname, regex, options);

        return 0;
}





regex_list_t *regex_init(char *filename)
{
        FILE *f;
        int line = 1, ret;
        char *token, *tmp = NULL;
        char buf[MAX_LINE_LEN];
        char name[MAX_NAME_LEN];
        char regex[MAX_LINE_LEN];
        char options[MAX_OPTIONS_LEN];

        regex_list_t *conf = malloc(sizeof(*conf));
        assert(conf);
        INIT_LIST_HEAD(conf);

        f = fopen(filename, "r");
        if (NULL == f) {
                log(LOG_ERR, "couldn't open config file.\n");
                return NULL;
        }

        while ( fgets(buf, MAX_LINE_LEN, f) ) {
                
                trim(buf);

                if ( buf[0] == '#' || buf[0] == '\0' )
                        /*
                         * ignore comments and empty lines
                         */
                        continue;
                
                token = strtok_r(buf, " \t", &tmp);
                if (NULL == token) {
                        line++;
                        continue;
                }
                strncpy(name, token, MAX_NAME_LEN);
                name[MAX_NAME_LEN - 1] = 0;
                
                token = strtok_r(NULL, " \t", &tmp);
                if (NULL == token) {
                        line++;
                        continue;
                }
                strncpy(options, token, MAX_OPTIONS_LEN);
                option[MAX_OPTIONS_LEN - 1] = 0;
                
                token = strtok_r(NULL, "", &tmp);
                if (NULL == token) {
                        line++;
                        continue;
                }
                strncpy(regex, token, MAX_LINE_LEN);
                regex[MAX_LINE_LEN - 1] = 0;
        
                ret = regex_create_entry(conf, filename, line, name, regex, options);
                if ( ret < 0 )
                        continue;
                
                line++;
        }
        fclose(f);
    
        return conf;
}




void regex_destroy(regex_list_t *list)
{
        regex_entry_t *entry;
        struct list_head *tmp, *bkp;

        list_for_each_safe(tmp, bkp, list) {
                entry = list_entry(tmp, regex_entry_t, list);
                regex_entry_delete(entry);
        }
        
        free(list);
}




int regex_exec(regex_list_t *list, const char *str,
               void (*cb)(void *plugin, void *data), void *data)
{
        regex_entry_t *entry;
        struct list_head *tmp;
        int count, ovector[20 * 3];
        
        list_for_each(tmp, list) {
                entry = list_entry(tmp, regex_entry_t, list);

                count = pcre_exec(entry->regex_compiled, entry->regex_extra,
                                  str, strlen(str), 0, 0, ovector, 20 * 3);
                if ( count <= 0 )
                        continue;
                
                dprint("[REGEX] string <%s> matched - count = %d\n", str, count);
                cb(entry->plugin, data);
        }
        
        return 0;
}
