#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "config.h"
#include "common.h"
#include "queue.h"
#include "regex.h"
#include "pconfig.h"
#include "udp-server.h"
#include "log-common.h"
#include "plugin-log.h"
#include "plugin-log-prv.h"
#include "file-server.h"
#include "lml-alert.h"


extern udp_server_t *udp_srvr;


static void sig_handler(int signum)
{
	fprintf(stderr, "\n\nCaught signal %d.\n", signum);
        signal(signum, SIG_DFL);

        if ( udp_srvr )
                udp_server_close(udp_srvr);
        
	exit(2);
}




static void regex_match_cb(void *plugin, void *log) 
{
        log_plugin_run(plugin, (log_container_t *) log);
}




static void dispatcher(regex_list_t *list, lml_queue_t *myqueue)
{
        int ret;
        log_container_t *log;
        
	while ( 1 ) {

		log = (log_container_t *) queue_pop(myqueue);
                if ( ! log )
                        continue;

                dprint("[DSPTC] dispatching object: <%s> from %s.\n",
                       log->log, log->source);
                
#if 0
                dprint("[DSPTC] dispatching object: <%s> from %s at %02d:%02d:%02d %04d/%02d/%02d\n",
                       log->log, log->source,
                       log->time_received.tm_hour,
                       log->time_received.tm_min,
                       log->time_received.tm_sec,
                       log->time_received.tm_year + 1900,
                       log->time_received.tm_mon + 1,
                       log->time_received.tm_mday);
#endif
                
                ret = regex_exec(list, log->log, regex_match_cb, log);
                log_container_delete(log);
	}
}



/**
 * lml_dispatch_log:
 * @list: List of regex.
 * @queue: Queue where this should be queued.
 * @str: The log.
 * @from: Where does this log come from.
 *
 * This function is to be called by module reading log devices.
 * It will take appropriate action.
 */
void lml_dispatch_log(regex_list_t *list, lml_queue_t *queue, const char *str, const char *from)
{
        log_container_t *log;

        log = log_container_new(str, from);
        if ( ! log )
                return;
                
        dprint("[MSGRD] received <%s> from %s\n", str, from);

        if ( queue ) 
                queue_push(queue, log);
        else {
                regex_exec(list, log->log, &regex_match_cb, log);
                log_container_delete(log);
        }
        
}




int main(int argc, char **argv)
{
        int ret;
	lml_queue_t *myqueue;
	regex_list_t *regex_list;
        
	ret = log_plugins_init(LOG_PLUGIN_DIR, argc, argv);
	if (ret < 0) {
		log(LOG_INFO, "error initializing logs plugins.\n");
		return -1;
	}
	log(LOG_INFO, "- Initialized %d logs plugins.\n", ret);

        myqueue = queue_new(NULL);
        if ( ! myqueue )
                exit(1);
        
        ret = pconfig_set(argc, argv);
        if ( ret < 0 )
                exit(1);
        
        ret = lml_alert_init();
        if ( ret < 0 )
                return -1;
        
	regex_list = regex_init(REGEX_CONF);
        if ( ! regex_list )
                exit(1);

        signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGQUIT, sig_handler);
	signal(SIGABRT, sig_handler);
        
        if ( udp_srvr ) {
                /*
                 * the UDP server run in a thread.
                 */
                udp_server_start(udp_srvr, regex_list, myqueue);
                dispatcher(regex_list, myqueue);
        } else {
                /*
                 * standalone file server don't need a thread at all. 
                 */
                file_server_standalone(regex_list, NULL);
        }
        
	return 0;
}

