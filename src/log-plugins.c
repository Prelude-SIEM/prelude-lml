#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>		/* for NAME_MAX */
#include <sys/time.h>
#include <time.h>


#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>


#include "common.h"
#include "hashkey.h"
#include "log-common.h"
#include "plugin-log.h"
#include "plugin-log-prv.h"


static LIST_HEAD(plugins_list);


static int subscribe(plugin_container_t *pc)
{
	dprint("- Subscribing plugin %s\n", pc->plugin->name);
        return plugin_add(pc, &plugins_list, NULL);
}



static void unsubscribe(plugin_container_t *pc)
{
	dprint("- Unsubscribing plugin %s\n", pc->plugin->name);
        plugin_del(pc);
}



static plugin_container_t *log_plugin_search(plugin_generic_t *plugin) 
{
        struct list_head *tmp;
        plugin_container_t *pc;
        
        list_for_each(tmp, &plugins_list) {

                pc = list_entry(tmp, plugin_container_t, ext_list);

                if ( pc->plugin == plugin )
                        return pc;
        }

        return NULL;
}



void log_plugin_run(plugin_container_t *pc, log_container_t *log)
{
        plugin_run(pc, plugin_log_t, run, log);
}




plugin_container_t *log_plugin_register(const char *pname) 
{
        plugin_container_t *pc;
        plugin_generic_t *plugin;
        
        /*
         * search in the whole plugin list a plugin
         * with pname as it's name.
         */
        plugin = plugin_search_by_name(pname);
        if ( ! plugin ) 
                return NULL;

        /*
         * register the plugin.
         */
        plugin_subscribe(plugin);

        pc = log_plugin_search(plugin);
        assert(pc);

        return pc;
}




/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located int it.
 */
int log_plugins_init(const char *dirname, int argc, char **argv)
{
	int ret;
        
	ret = plugin_load_from_dir(dirname, argc, argv, subscribe,
                                   unsubscribe);
	if (ret < 0) {
		log(LOG_ERR, "couldn't load plugin subsystem.\n");
		return -1;
	}
        
	return ret;
}





