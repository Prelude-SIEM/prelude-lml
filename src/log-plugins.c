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

static hash_table plugins;

/* Derived from /usr/CVSroot/XEmacs/xemacs/src/symbols.c 2001/04/30 09:02:41 */

static int hash_string(const void *k)
{
        int len;
	unsigned int hash = 0;
        const char *ptr = (const char *) k;

        len = strlen(ptr);
        
	for (hash = 0; len; len--, ptr++)
		hash = 31 * hash + *ptr;

	return hash;
}



static int equal_string(const void *k1, const void *k2)
{
	if ( ! strcmp((const char *) k1, (const char *) k2))
		return 1;
	return 0;
}



static int subscribe(plugin_container_t *pc)
{
	dprint("- Subscribing plugin %s\n", pc->plugin->name);
	hash_position(plugins, pc->plugin->name);
	hash_insert(plugins, pc->plugin->name, pc);
	return 0;
}



static void unsubscribe(plugin_container_t *pc)
{
	dprint("- Unsubscribing plugin %s\n", pc->plugin->name);
	hash_position(plugins, pc->plugin->name);
	hash_delete(plugins);
}




void log_plugins_run(const char *plugin_name, log_container_t *log)
{
	plugin_container_t *pc;

	if ( hash_position(plugins, plugin_name) ) {
		pc = (plugin_container_t *) hash_get(plugins);
                if ( ! pc )
                        return;
                
                plugin_run(pc, plugin_log_t, run, log);
	}
}




/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located int it.
 */
int log_plugins_init(const char *dirname, int argc, char **argv)
{
	int ret;

	plugins = hash_create(hash_string, equal_string);

	ret = plugin_load_from_dir(dirname, argc, argv, subscribe,
                                   unsubscribe);
	if (ret < 0) {
		log(LOG_ERR, "couldn't load plugin subsystem.\n");
		return -1;
	}
        
	return ret;
}
