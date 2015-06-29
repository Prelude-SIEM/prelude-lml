/*****
*
* Copyright (C) 2002-2015 CS-SI. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>                /* for NAME_MAX */

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>

#include "prelude-lml.h"
#include "log-source.h"
#include "log-entry.h"
#include "log-plugins.h"


#define LML_PLUGIN_SYMBOL "lml_plugin_init"


static PRELUDE_LIST(log_plugins_instance);


static int subscribe(prelude_plugin_instance_t *pi)
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);

        prelude_log(PRELUDE_LOG_DEBUG, "Subscribing plugin %s[%s]\n", plugin->name, prelude_plugin_instance_get_name(pi));
        prelude_linked_object_add(&log_plugins_instance, (prelude_linked_object_t *) pi);

        return 0;
}



static void unsubscribe(prelude_plugin_instance_t *pi)
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);

        prelude_log(PRELUDE_LOG_DEBUG, "Unsubscribing plugin %s[%s]\n", plugin->name, prelude_plugin_instance_get_name(pi));
        prelude_linked_object_del((prelude_linked_object_t *) pi);
}



void log_plugin_run(prelude_plugin_instance_t *pi, lml_log_source_t *ls, lml_log_entry_t *log)
{
        prelude_plugin_run(pi, lml_log_plugin_t, run, pi, ls, log);
}




prelude_plugin_instance_t *log_plugin_register(const char *plugin)
{
        int ret;
        char pname[256], iname[256];
        prelude_plugin_generic_t *pl;
        prelude_plugin_instance_t *pi;

        ret = sscanf(plugin, "%255[^[][%255[^]]", pname, iname);

        pi = prelude_plugin_search_instance_by_name(NULL, pname, (ret == 2) ? iname : NULL);
        if ( pi )
                return pi;

        pl = prelude_plugin_search_by_name(NULL, pname);
        if ( ! pl )
                return NULL;

        ret = prelude_plugin_new_instance(&pi, pl, (ret == 2) ? iname : NULL, NULL);
        if ( ret < 0 )
                return NULL;

        return pi;
}




/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located int it.
 */
int log_plugins_init(const char *dirname, void *data)
{
        int ret;

        ret = access(dirname, F_OK);
        if ( ret < 0 ) {
                if ( errno == ENOENT )
                        return 0;

                prelude_log(PRELUDE_LOG_ERR, "could not access '%s': %s.\n", dirname, strerror(errno));
                return -1;
        }

        ret = prelude_plugin_load_from_dir(NULL, dirname, LML_PLUGIN_SYMBOL, data, subscribe, unsubscribe);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error loading plugins: %s.\n", prelude_strerror(ret));
                return -1;
        }

        return ret;
}

