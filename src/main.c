#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>
#include <libprelude/timer.h>

#include "config.h"
#include "common.h"
#include "regex.h"
#include "pconfig.h"
#include "udp-server.h"
#include "log-common.h"
#include "plugin-log.h"
#include "plugin-log-prv.h"
#include "file-server.h"
#include "lml-alert.h"


#define MAX(x, y) (((x) > (y)) ? (x) : (y))


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





/**
 * lml_dispatch_log:
 * @list: List of regex.
 * @str: The log.
 * @from: Where does this log come from.
 *
 * This function is to be called by module reading log devices.
 * It will take appropriate action.
 */
void lml_dispatch_log(regex_list_t *list, const char *str, const char *from)
{
        log_container_t *log;

        log = log_container_new(str, from);
        if ( ! log )
                return;
                
        dprint("[MSGRD] received <%s> from %s\n", str, from);

        regex_exec(list, log->log, &regex_match_cb, log);
        log_container_delete(log);
}



static void wait_for_event(regex_list_t *list) 
{
        int ret;
        fd_set fds;
        struct timeval tv, start, end;
        int file_event_fd, udp_event_fd;

        udp_event_fd = udp_server_get_event_fd(udp_srvr);
        file_event_fd = file_server_get_event_fd();
        
        FD_ZERO(&fds);
        FD_SET(udp_event_fd, &fds);
        
        if ( file_event_fd > 0 )
                FD_SET(file_event_fd, &fds);
        
        gettimeofday(&start, NULL);
        
        while ( 1 ) {

                tv.tv_sec = 1;
                tv.tv_usec = 0;
                
                ret = select(MAX(file_event_fd, udp_event_fd) + 1, &fds, NULL, NULL, &tv);
                if ( ret < 0 ) {
                        log(LOG_ERR, "select returned an error.\n");
                        return;
                }
                
                gettimeofday(&end, NULL);
                
                if ( ret == 0 || end.tv_sec - start.tv_sec >= 1 ) {
                        gettimeofday(&start, NULL);
                        prelude_wake_up_timer();

                        if ( file_event_fd < 0 )
                                file_server_wake_up(list);
                }
                
                if ( FD_ISSET(udp_event_fd, &fds) ) 
                        udp_server_process_event(udp_srvr, list);
                
                if ( file_event_fd > 0 && FD_ISSET(file_event_fd, &fds) ) 
                        file_server_wake_up(list);

                FD_SET(udp_event_fd, &fds);

                if ( file_event_fd > 0 )
                        FD_SET(file_event_fd, &fds);
        }
}




int main(int argc, char **argv)
{
        int ret;
	regex_list_t *regex_list;
        
	ret = log_plugins_init(LOG_PLUGIN_DIR, argc, argv);
	if (ret < 0) {
		log(LOG_INFO, "error initializing logs plugins.\n");
		return -1;
	}
	log(LOG_INFO, "- Initialized %d logs plugins.\n", ret);
        
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

        if ( ! udp_srvr ) 
                file_server_standalone(regex_list);
        else 
                wait_for_event(regex_list);
        
	return 0;
}

