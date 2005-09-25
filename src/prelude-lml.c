/*****
*
* Copyright (C) 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-timer.h>

#include "config.h"

#include "regex.h"
#include "prelude-lml.h"
#include "common.h"

#include "lml-options.h"
#include "udp-server.h"
#include "file-server.h"
#include "log-entry.h"
#include "log-plugins.h"
#include "lml-alert.h"

#ifndef MAX
 #define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

struct regex_data {
        lml_log_source_t *log_source;
        lml_log_entry_t *log_entry;
};


static struct timeval start;
extern lml_config_t config;
static char **global_argv;
static prelude_option_t *lml_root_optlist;
static volatile sig_atomic_t got_sighup = 0;



static void print_stats(struct timeval *end)
{
        unsigned int tdiv;
        
        prelude_log(PRELUDE_LOG_WARN, "- Dumping stat: %d line processed in %u seconds.\n",
                    config.line_processed, end->tv_sec - start.tv_sec);

        tdiv = end->tv_sec - start.tv_sec;
        if ( tdiv == 0 )
                tdiv = 1;
        
        prelude_log(PRELUDE_LOG_WARN, "- Average %d events / seconds .\n",
                    config.line_processed / tdiv);
        
        prelude_log(PRELUDE_LOG_WARN, "- %d alert issued.\n", config.alert_count);
}



static void sig_handler(int signum)
{
        signal(signum, SIG_DFL);
        
        prelude_log(PRELUDE_LOG_WARN, "\n\nCaught signal %d.\n", signum);

        if ( config.udp_srvr )
                udp_server_close(config.udp_srvr);
        
        exit(2);
}




static void sighup_handler(int signum) 
{
        /*
         * re-establish signal handler
         */
        signal(signum, sighup_handler);
        
        /*
         * We can't directly restart LML from the signal handler.
         * It'll be restarted as soon as the main loop poll the
         * got_sighup variable.
         */
        got_sighup = 1;
}



static void sig_stats_handler(int signum)
{
        struct timeval end;

        /*
         * re-establish signal handler
         */
        signal(signum, sig_stats_handler);
        
        gettimeofday(&end, NULL);
        print_stats(&end);
}



static void handle_sighup_if_needed(void) 
{
        int ret;

        if ( ! got_sighup )
                return;
        
        prelude_log(PRELUDE_LOG_WARN, "- Restarting Prelude LML (%s).\n", global_argv[0]);

        if ( config.udp_srvr )
                /*
                 * close the UDP server, so that we can bind the port again.
                 */
                udp_server_close(config.udp_srvr);

        /*
         * Here we go !
         */
        ret = execvp(global_argv[0], global_argv);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error re-executing lml\n");
                return;
        }
}



static void regex_match_cb(void *plugin, void *data) 
{
        struct regex_data *rdata = data;
        
        log_plugin_run(plugin, rdata->log_source, rdata->log_entry);
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
void lml_dispatch_log(regex_list_t *list, lml_log_source_t *ls, const char *str, size_t size)
{
        struct regex_data rdata;
        lml_log_entry_t *log_entry;
        
        prelude_log_debug(3, "[LOG] %s\n", str);

        log_entry = lml_log_entry_new();
        if ( ! log_entry )
                return;
        
        lml_log_entry_set_log(log_entry, ls, str, size);

        rdata.log_source = ls;
        rdata.log_entry = log_entry;
        
        regex_exec(list, &regex_match_cb, &rdata,
                   lml_log_entry_get_message(log_entry), lml_log_entry_get_message_len(log_entry));

        lml_log_entry_destroy(log_entry);
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
        
        file_event_fd = file_server_get_event_fd();

        FD_ZERO(&fds);                
        gettimeofday(&start, NULL);
        
        while ( 1 ) {
                handle_sighup_if_needed();
                
                tv.tv_sec = 1;
                tv.tv_usec = 0;

                udp_event_fd = udp_server_get_event_fd(config.udp_srvr);
                
                add_fd_to_set(&fds, udp_event_fd);
                add_fd_to_set(&fds, file_event_fd);

                ret = select(MAX(file_event_fd, udp_event_fd) + 1, &fds, NULL, NULL, &tv);
                if ( ret < 0 ) {
                        if ( errno == EINTR )
                                continue;
                        
                        prelude_log(PRELUDE_LOG_ERR, "select returned an error.\n");
                        return;
                }
                
                gettimeofday(&end, NULL);
                
                if ( ret == 0 || end.tv_sec - start.tv_sec >= 1 ) {
                        gettimeofday(&start, NULL);
                        prelude_timer_wake_up();

                        if ( file_event_fd < 0 )
                                file_server_wake_up();
                }
                
                if ( udp_event_fd > 0 && FD_ISSET(udp_event_fd, &fds) ) 
                        udp_server_process_event(config.udp_srvr);
                
                if ( file_event_fd > 0 && FD_ISSET(file_event_fd, &fds) )
                        file_server_wake_up();
        }
}



int main(int argc, char **argv)
{
        int ret;
        struct timeval end;

        memset(&start, 0, sizeof(start));
        memset(&end, 0, sizeof(end));
        
        prelude_init(&argc, argv);
        global_argv = argv;
        
        PRELUDE_PLUGIN_SET_PRELOADED_SYMBOLS();
        
        ret = prelude_option_new_root(&lml_root_optlist);
        if ( ret < 0 )
                return ret;
        
        ret = log_plugins_init(LOG_PLUGIN_DIR, lml_root_optlist);
        if (ret < 0) {
                prelude_log(PRELUDE_LOG_WARN, "error initializing logs plugins.\n");
                return -1;
        }
        prelude_log_debug(1, "- Initialized %d logs plugins.\n", ret);
        
        ret = lml_options_init(lml_root_optlist, argc, argv);
        if ( ret < 0 )
                exit(1);
        
        signal(SIGTERM, sig_handler);
        signal(SIGINT, sig_handler);
        signal(SIGQUIT, sig_handler);
        signal(SIGABRT, sig_handler);
        signal(SIGHUP, sighup_handler);
        signal(SIGUSR1, sig_stats_handler);
        signal(SIGQUIT, sig_stats_handler);
        
        file_server_start_monitoring();

        /*
         * if either FAM or UDP server is enabled, we use polling to know
         * if there are data available for reading. if batch_mode is set,
         * then we revert to reading every data at once.
         */
        if ( (config.udp_srvr || file_server_get_event_fd() > 0) && ! config.batch_mode )
                wait_for_event();
        else {
                gettimeofday(&start, NULL);
                                
                do {
                        handle_sighup_if_needed();
                        ret = file_server_wake_up();
                        
                        if ( ! config.batch_mode )
                                sleep(1);
                        
                        prelude_timer_wake_up();
                        
                } while ( ! config.batch_mode || ret > 0 );
                
                gettimeofday(&end, NULL);
                
                /*
                 * only call prelude_client_destroy in case we are running in batch
                 * mode, causing an heartbeat to be sent to notice of a normal exit.
                 */
                if ( ! config.dry_run )
                        prelude_client_destroy(config.lml_client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);

                print_stats(&end);
        }
        
        return 0;
}
