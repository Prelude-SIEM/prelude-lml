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

#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/prelude-plugin.h>
#include <libprelude/prelude-client.h>
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

#ifndef MAX
 #define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

extern int batch_mode;
static char **global_argv;
extern udp_server_t *udp_srvr;
extern prelude_client_t *lml_client;
static volatile sig_atomic_t got_sighup = 0;


static void sig_handler(int signum)
{
	log(LOG_INFO, "\n\nCaught signal %d.\n", signum);
        
        signal(signum, SIG_DFL);

        if ( udp_srvr )
                udp_server_close(udp_srvr);
        
	exit(2);
}




static void sighup_handler(int signum) 
{
        /*
         * We can't directly restart LML from the signal handler.
         * It'll be restarted as soon as the main loop poll the
         * got_sighup variable.
         */
        got_sighup = 1;
}




static void handle_sighup_if_needed(void) 
{
        int ret;

        if ( ! got_sighup )
                return;
        
        log(LOG_INFO, "- Restarting Prelude LML (%s).\n", global_argv[0]);

        if ( udp_srvr )
                /*
                 * close the UDP server, so that we can bind the port again.
                 */
                udp_server_close(udp_srvr);

        /*
         * Here we go !
         */
        ret = execvp(global_argv[0], global_argv);
        if ( ret < 0 ) {
                log(LOG_ERR, "error re-executing lml\n");
                return;
        }
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
void lml_dispatch_log(regex_list_t *list, log_source_t *ls, const char *str)
{
        log_container_t *log;
        
        log = log_container_new(ls);
        if ( ! log )
                return;
        
        log_container_set_log(log, str);

        regex_exec(list, log->log, &regex_match_cb, log);
        log_container_delete(log);
}



static void add_fd_to_set(fd_set *fds, int fd) 
{
        if ( fd > 0 )
                FD_SET(fd, fds);
}



static void wait_for_event(void) 
{
        int ret;
        fd_set fds;
        struct timeval tv, start, end;
        int file_event_fd, udp_event_fd;
        
        udp_event_fd = udp_server_get_event_fd(udp_srvr);
        file_event_fd = file_server_get_event_fd();

        FD_ZERO(&fds);                
        gettimeofday(&start, NULL);
        
        while ( 1 ) {
                handle_sighup_if_needed();
                
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                
                add_fd_to_set(&fds, udp_event_fd);
                add_fd_to_set(&fds, file_event_fd);

                ret = select(MAX(file_event_fd, udp_event_fd) + 1, &fds, NULL, NULL, &tv);
                if ( ret < 0 ) {
                        if ( errno == EINTR )
                                continue;
                        
                        log(LOG_ERR, "select returned an error.\n");
                        return;
                }
                
                gettimeofday(&end, NULL);
                
                if ( ret == 0 || end.tv_sec - start.tv_sec >= 1 ) {
                        gettimeofday(&start, NULL);
                        prelude_wake_up_timer();

                        if ( file_event_fd < 0 )
                                file_server_wake_up();
                }
                
                if ( udp_event_fd > 0 && FD_ISSET(udp_event_fd, &fds) ) 
                        udp_server_process_event(udp_srvr);
                
                if ( file_event_fd > 0 && FD_ISSET(file_event_fd, &fds) )
                        file_server_wake_up();
        }
}




int main(int argc, char **argv)
{
        int ret;
        
        global_argv = argv;

	PRELUDE_PLUGIN_SET_PRELOADED_SYMBOLS();
        
	ret = log_plugins_init(LOG_PLUGIN_DIR, argc, argv);
	if (ret < 0) {
		log(LOG_INFO, "error initializing logs plugins.\n");
		return -1;
	}
	log(LOG_INFO, "- Initialized %d logs plugins.\n", ret);
        
        ret = pconfig_set(argc, argv);
        if ( ret < 0 )
                exit(1);
        
        signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGQUIT, sig_handler);
        signal(SIGABRT, sig_handler);
        signal(SIGHUP, sighup_handler);

        file_server_start_monitoring();

        /*
         * if either FAM or UDP server is enabled, we use polling to know
         * if there are data available for reading. if batch_mode is set,
         * then we revert to reading every data at once.
         */
        if ( (udp_srvr || file_server_get_event_fd() > 0) && ! batch_mode )
                wait_for_event();
        else {
                do {
                        handle_sighup_if_needed();
                        ret = file_server_wake_up();

                        if ( ! batch_mode )
                                sleep(1);
                        
                        prelude_wake_up_timer();
                        
                } while ( batch_mode == 0 || ret > 0 );
        }
        
	return 0;
}
