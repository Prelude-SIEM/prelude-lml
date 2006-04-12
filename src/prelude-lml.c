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

#include "config.h"
#include "libmissing.h"

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


void _lml_handle_signal_if_needed(void);


static struct timeval start;
extern lml_config_t config;
static char **global_argv;
static prelude_option_t *lml_root_optlist;
static volatile sig_atomic_t got_signal = 0;



static void print_stats(const char *prefix, struct timeval *end)
{
        double tdiv;

        tdiv = (end->tv_sec + (double) end->tv_usec / 1000000) - (start.tv_sec + (double) start.tv_usec / 1000000);
                
        prelude_log(PRELUDE_LOG_WARN, "%s%u line processed in %.2f seconds (%.2f EPS), %d alert emited.\n",
                    prefix, config.line_processed, tdiv, config.line_processed / tdiv, config.alert_count);
}



static void sig_handler(int signum)
{
        got_signal = signum;      
}


static void handle_signal(void)
{
        size_t i;
        
        for ( i = 0; i < config.udp_nserver; i++ )
                udp_server_close(config.udp_server[i]);
        
        exit(2);
}



static void handle_sigquit(void)
{
        struct timeval end;
        
        gettimeofday(&end, NULL);
        print_stats("statistics signal received: ", &end);
}



static const char *get_restart_string(void)
{
        int ret;
        size_t i;
        prelude_string_t *buf;
        
        ret = prelude_string_new(&buf);
        if ( ret < 0 )
                return global_argv[0];
        
        for ( i = 0; global_argv[i] != NULL; i++ ) {
                if ( ! prelude_string_is_empty(buf) )
                        prelude_string_cat(buf, " ");
                        
                prelude_string_cat(buf, global_argv[i]);
        }

        return prelude_string_get_string(buf);
}


static void handle_sighup(void) 
{
        int ret;
        size_t i;

        /*
         * close the UDP server, so that we can bind the port again.
         */
        for ( i = 0; i < config.udp_nserver; i++ )
                udp_server_close(config.udp_server[i]);
        
        /*
         * Here we go !
         */
        ret = execvp(global_argv[0], global_argv);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error re-executing lml\n");
                return;
        }
}



void _lml_handle_signal_if_needed(void)
{
        int signo;
        
        if ( ! got_signal )
                return;

        signo = got_signal;
        got_signal = 0;

        if ( signo == SIGHUP ) {
                prelude_log(PRELUDE_LOG_WARN, "signal %d received, restarting (%s).\n", signo, get_restart_string());
                handle_sighup();
        }
        
        if ( signo == SIGQUIT || signo == SIGUSR1 ) {
                handle_sigquit();
                return;
        }
        
        prelude_log(PRELUDE_LOG_WARN, "signal %d received, terminating prelude-lml.\n", signo);
        handle_signal();
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
void lml_dispatch_log(lml_log_source_t *ls, const char *str, size_t size)
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
        
        regex_exec(lml_log_source_get_regex_list(ls), &regex_match_cb, &rdata,
                   lml_log_entry_get_message(log_entry), lml_log_entry_get_message_len(log_entry));

        lml_log_entry_destroy(log_entry);
}



static void wait_for_event(void) 
{
        int ret;
        size_t i;
        fd_set fds;
        struct timeval tv, lstart, end;
        int file_event_fd, udp_event_fd, max = 0;
        
        FD_ZERO(&fds);

        file_event_fd = file_server_get_event_fd();        
        if ( file_event_fd >= 0 ) {
                max = file_event_fd;
                FD_SET(file_event_fd, &fds);
        }
        
        for ( i = 0; i < config.udp_nserver; i++ ) {
                udp_event_fd = udp_server_get_event_fd(config.udp_server[i]);
                
                FD_SET(udp_event_fd, &fds);
                max = MAX(max, udp_event_fd);
        }

        gettimeofday(&start, NULL);
        gettimeofday(&lstart, NULL);
        
        while ( 1 ) {
                _lml_handle_signal_if_needed();
                
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                
                ret = select(max + 1, &fds, NULL, NULL, &tv);
                if ( ret < 0 ) {
                        if ( errno == EINTR )
                                continue;
                        
                        prelude_log(PRELUDE_LOG_ERR, "select returned an error: %s.\n", strerror(errno));
                        break;
                }
                
                gettimeofday(&end, NULL);
                
                if ( ret == 0 || end.tv_sec - lstart.tv_sec >= 1 ) {
                        gettimeofday(&lstart, NULL);
                        prelude_timer_wake_up();
                        
                        if ( file_event_fd < 0 )
                                file_server_wake_up();
                }

                for ( i = 0; i < config.udp_nserver; i++ ) {
                        udp_event_fd = udp_server_get_event_fd(config.udp_server[i]);
                        
                        if ( FD_ISSET(udp_event_fd, &fds) ) 
                                udp_server_process_event(config.udp_server[i]);
                        else
                                FD_SET(udp_event_fd, &fds);
                }

                if ( file_event_fd < 0 )
                        continue;
                
                if ( FD_ISSET(file_event_fd, &fds) )
                        file_server_wake_up();
                else
                        FD_SET(file_event_fd, &fds);
        }
}



int main(int argc, char **argv)
{
        int ret;
        struct timeval end;
        struct sigaction action;
        
        /*
         * make sure we ignore sighup until acceptable.
         */
        action.sa_flags = 0;
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        sigaction(SIGHUP, &action, NULL);
        
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

        /*
         * setup signal handling
         */
        action.sa_flags = 0;
        sigemptyset(&action.sa_mask);
        action.sa_handler = sig_handler;
        
#ifdef SA_INTERRUPT
        action.sa_flags |= SA_INTERRUPT;
#endif

        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
        sigaction(SIGUSR1, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        
        file_server_start_monitoring();

        /*
         * if either FAM or UDP server is enabled, we use polling to know
         * if there are data available for reading. if batch_mode is set,
         * then we revert to reading every data at once.
         */
        if ( (config.udp_nserver || file_server_get_event_fd() > 0) && ! config.batch_mode )
                wait_for_event();
        else {
                gettimeofday(&start, NULL);
                
                do {
                        _lml_handle_signal_if_needed();
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

                print_stats("- ", &end);
        }
        
        return 0;
}
