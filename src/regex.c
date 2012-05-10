/*****
*
* Copyright (C) 2003-2012 CS-SI. All Rights Reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>

#include "prelude-lml.h"
#include "common.h"
#include "regex.h"
#include "log-entry.h"
#include "log-plugins.h"


typedef struct {
        prelude_list_t list;

        pcre *source_regex;

        char *regex;
        pcre *regex_regex;
        pcre_extra *regex_regex_extra;

        int line;
        char *plugin;
} regex_table_item_t;


typedef struct {
        prelude_list_t list;
        regex_table_item_t *rt;
        prelude_plugin_instance_t *plugin;
} regex_entry_t;



static PRELUDE_LIST(regex_conf_list);



static char *trim(char *str)
{
        char *rptr, *wptr;

        if ( ! str )
                return NULL;

        wptr = rptr = str;

        while ( *rptr != '\0' ) {
                if ( isspace((int) *rptr) ) {
                        do {
                                rptr++;
                        } while ( isspace((int) *rptr) );

                        *wptr++ = ' ';
                } else
                        *wptr++ = *rptr++;
        }

        *wptr = '\0';

        return str;
}




static regex_entry_t *regex_entry_new(regex_list_t *list)
{
        regex_entry_t *new;

        new = malloc(sizeof(*new));
        if ( ! new ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->rt = NULL;
        prelude_list_add_tail(list, &new->list);

        return new;
}




static void regex_entry_delete(regex_entry_t *entry)
{
        prelude_list_del(&entry->list);
        free(entry);
}




static int regex_create_entry(regex_list_t *list, regex_table_item_t *rt, const char *source)
{
        regex_entry_t *entry;
        prelude_plugin_generic_t *plugin;

        entry = regex_entry_new(list);
        if ( ! entry )
                return -1;

        entry->rt = rt;

        entry->plugin = log_plugin_register(rt->plugin);
        if ( ! entry->plugin ) {
                regex_entry_delete(entry);
                prelude_log(PRELUDE_LOG_WARN, "%s:%d : couldn't find plugin: %s.\n", REGEX_CONF, rt->line, rt->plugin);
                return -1;
        }

        plugin = prelude_plugin_instance_get_plugin(entry->plugin);
        prelude_log_debug(1, "Will route %s data through %s[%s]\n",
                          source, plugin->name, prelude_plugin_instance_get_name(entry->plugin));

        prelude_log(PRELUDE_LOG_DEBUG, "[REGEX] rule found: plugin: %s - pattern: %s\n", rt->plugin, rt->regex);

        return 0;
}




static int get_regex_table(void)
{
        FILE *fd;
        size_t len;
        char buf[1024];
        const char *errptr;
        int line = 0, erroff;
        regex_table_item_t *rt;
        pcre_extra *regex_regex_extra = NULL;
        char *regex, *options, *source, *plugin;
        pcre *regex_regex = NULL, *source_regex = NULL;

        fd = fopen(REGEX_CONF, "r");
        if ( ! fd ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't open config file %s.\n", REGEX_CONF);
                return -1;
        }

        while ( fgets(buf, sizeof(buf), fd) ) {
                trim(buf);
                line++;

                if ( buf[0] == '#' || buf[0] == '\0' )
                        /*
                         * ignore comments and empty lines
                         */
                        continue;

                source = strtok(buf, " \t");
                if ( ! source )
                        continue;

                plugin = strtok(NULL, " \t");
                if ( ! plugin )
                        continue;

                options = strtok(NULL, " \t");
                if ( ! options )
                        continue;

                regex = strtok(NULL, "");
                if ( ! regex )
                        continue;

                for ( len = strlen(regex); len && regex[len - 1] == ' '; len--)
                        regex[len - 1] = 0;

                if ( strcmp(source, "*") != 0 ) {
                        source_regex = pcre_compile(source, 0, &errptr, &erroff, NULL);
                        if ( ! source_regex ) {
                                prelude_log(PRELUDE_LOG_WARN, "%s:%d: Unable to compile source regexp: %s.\n", REGEX_CONF, line, errptr);
                                continue;
                        }
                }

                if ( strcmp(regex, "*") != 0 ) {
                        regex_regex = pcre_compile(regex, 0, &errptr, &erroff, NULL);
                        if ( ! regex_regex ) {
                                if ( source_regex )
                                        pcre_free(source_regex);

                                prelude_log(PRELUDE_LOG_WARN, "%s:%d: Unable to compile regexp: %s.\n", REGEX_CONF, line, errptr);
                                continue;
                        }

                        regex_regex_extra = pcre_study(regex_regex, 0, &errptr);
                }

                rt = malloc(sizeof(*rt));
                if ( ! rt ) {
                        fclose(fd);
                        return -1;
                }

                rt->line = line;
                rt->source_regex = source_regex;

                rt->regex = strdup(regex);
                rt->regex_regex = regex_regex;
                rt->regex_regex_extra = regex_regex_extra;

                rt->plugin = strdup(plugin);

                prelude_list_add_tail(&regex_conf_list, &rt->list);
        }

        fclose(fd);
        return 0;
}


regex_list_t *regex_init(const char *source)
{
        int ret;
        regex_list_t *conf;
        prelude_list_t *tmp;
        regex_table_item_t *rt;

        if ( prelude_list_is_empty(&regex_conf_list) ) {
                ret = get_regex_table();
                if ( ret < 0 )
                        return NULL;
        }

        conf = malloc(sizeof(*conf));
        if ( ! conf ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        prelude_list_init(conf);

        prelude_list_for_each(&regex_conf_list, tmp) {
                rt = prelude_list_entry(tmp, regex_table_item_t, list);

                if ( rt->source_regex != NULL ) {
                        ret = pcre_exec(rt->source_regex, NULL, source, strlen(source), 0, 0, NULL, 0);
                        if ( ret < 0 )
                                continue;
                }

                ret = regex_create_entry(conf, rt, source);
                if ( ret < 0 )
                        continue;
        }

        if ( prelude_list_is_empty(conf) ) {
                prelude_log(PRELUDE_LOG_WARN, "No plugin configured to receive data from source '%s'.\n", source);
                free(conf);
                return NULL;
        }

        return conf;
}




void regex_destroy(regex_list_t *list)
{
        regex_entry_t *entry;
        prelude_list_t *tmp, *bkp;

        prelude_list_for_each_safe(list, tmp, bkp) {
                entry = prelude_list_entry(tmp, regex_entry_t, list);
                regex_entry_delete(entry);
        }

        free(list);
}




int regex_exec(regex_list_t *list,
               void (*cb)(void *plugin, void *data), void *data,
               const char *str, size_t len)
{
        int ret;
        prelude_list_t *tmp;
        regex_entry_t *entry;

        prelude_list_for_each(list, tmp) {
                entry = prelude_list_entry(tmp, regex_entry_t, list);

                if ( entry->rt->regex_regex ) {
                        ret = pcre_exec(entry->rt->regex_regex, entry->rt->regex_regex_extra, str, len, 0, 0, NULL, 0);
                        if ( ret < 0 )
                                continue;
                }

                prelude_log_debug(10, "[%s]: sending <%s>\n", entry->rt->plugin, str);
                cb(entry->plugin, data);
        }

        return 0;
}
