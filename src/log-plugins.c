/*****
*
* Copyright (C) 2002 - 2005 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>                /* for NAME_MAX */
#include <sys/time.h>
#include <time.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>

#include "common.h"
#include "log-common.h"
#include "plugin-log.h"
#include "plugin-log-prv.h"


static PRELUDE_LIST_HEAD(log_plugins_instance);


static int subscribe(prelude_plugin_instance_t *pi)
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        log(LOG_INFO, "- Subscribing plugin %s[%s]\n", plugin->name, prelude_plugin_instance_get_name(pi));
        prelude_linked_object_add((prelude_linked_object_t *) pi, &log_plugins_instance);

        return 0;
}



static void unsubscribe(prelude_plugin_instance_t *pi)
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        log(LOG_INFO, "- Unsubscribing plugin %s[%s]\n", plugin->name, prelude_plugin_instance_get_name(pi));
        prelude_linked_object_del((prelude_linked_object_t *) pi);
}



void log_plugin_run(prelude_plugin_instance_t *pi, log_entry_t *log)
{
        prelude_plugin_run(pi, plugin_log_t, run, pi, log);
}




prelude_plugin_instance_t *log_plugin_register(const char *plugin) 
{
        int ret;
        char pname[256], iname[256];
        
        ret = sscanf(plugin, "%255[^[][%255[^]]", pname, iname);
        
        return prelude_plugin_search_instance_by_name(pname, (ret == 2) ? iname : NULL);
}




/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located int it.
 */
int log_plugins_init(const char *dirname, int argc, char **argv)
{
        int ret;
        
        ret = access(dirname, F_OK);
        if ( ret < 0 ) {
                if ( errno == ENOENT )
                        return 0;

                log(LOG_ERR, "can't access %s.\n", dirname);

                return -1;
        }

        ret = prelude_plugin_load_from_dir(dirname, subscribe, unsubscribe);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't load plugin subsystem.\n");
                return -1;
        }
        
        return ret;
}

