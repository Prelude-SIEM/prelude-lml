/*****
*
* Copyright (C) 2004-2012 CS-SI. All Rights Reserved.
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
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "ev.h"

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-timer.h>
#include <libprelude/daemonize.h>

#include "config.h"

#include "regex.h"
#include "prelude-lml.h"
#include "common.h"

#include "lml-options.h"
#include "udp-server.h"
#include "tcp-server.h"
#include "file-server.h"
#include "log-entry.h"
#include "log-plugins.h"
#include "lml-alert.h"

#ifndef MAX
 #define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif


typedef struct {
        int pri;
} syslog_header_t;


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
static ev_async ev_interrupt;



static void print_stats(const char *prefix, struct timeval *end)
{
        double tdiv;

        tdiv = (end->tv_sec + (double) end->tv_usec / 1000000) - (start.tv_sec + (double) start.tv_usec / 1000000);

        prelude_log(PRELUDE_LOG_WARN, "%s%lu line processed in %.2f seconds (%.2f EPS), %lu alert emited.\n",
                    prefix, config.line_processed, tdiv, config.line_processed / tdiv, config.alert_count);
}


static RETSIGTYPE sig_handler(int signum)
{
        got_signal = signum;
        ev_async_send(EV_DEFAULT_ &ev_interrupt);
}


static void server_close(void)
{
        size_t i;

        for ( i = 0; i < config.udp_nserver; i++ )
                udp_server_close(config.udp_server[i]);

        for ( i = 0; i < config.tcp_nserver; i++ )
                tcp_server_close(config.tcp_server[i]);
}


#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
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

        /*
         * Here we go !
         */
        ret = execvp(global_argv[0], global_argv);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error restarting '%s': %s\n", global_argv[0], prelude_strerror(ret));
                return;
        }
}
#endif



void _lml_handle_signal_if_needed(void)
{
        int signo;

        if ( ! got_signal )
                return;

        signo = got_signal;
        got_signal = 0;

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( signo == SIGQUIT || signo == SIGUSR1 ) {
                handle_sigquit();
                return;
        }
#endif

        server_close();

        if ( config.lml_client )
                prelude_client_destroy(config.lml_client, PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

        prelude_deinit();

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( signo == SIGHUP ) {
                prelude_log(PRELUDE_LOG_WARN, "signal %d received, restarting (%s).\n", signo, get_restart_string());
                handle_sighup();
        }
#endif

        prelude_log(PRELUDE_LOG_WARN, "signal %d received, terminating prelude-lml.\n", signo);
        ev_default_destroy();
        exit(2);
}


static void libev_timer_cb(struct ev_timer *w, int revents)
{
        prelude_timer_wake_up();
}


static void libev_udp_cb(struct ev_io *w, int revents)
{
        udp_server_process_event(w->data);
}


static void libev_tcp_accept_cb(struct ev_io *w, int revents)
{
        tcp_server_accept(w->data);
}


static void libev_interrupt_cb(EV_P_ ev_async *w, int revents)
{
        _lml_handle_signal_if_needed();
}


static void regex_match_cb(void *plugin, void *data)
{
        struct regex_data *rdata = data;
        log_plugin_run(plugin, rdata->log_source, rdata->log_entry);
}



static int logparse_pri(syslog_header_t *hdr, const char **src, size_t *len)
{
        size_t i = 0;
        const char *ptr = *src;

        hdr->pri = 0;

        if ( ptr[i++] != '<' )
                goto error;

        while ( ptr[i] != '>' ) {
                if ( ! isdigit(ptr[i]) )
                        goto error;

                hdr->pri = hdr->pri * 10 + (ptr[i++] - '0');
        }

        if ( ptr[i] == '>' && i >= 3 && i <= 4 ) {
                *len -= i + 1;
                *src += i + 1;
                return 0;
        }

error:
        /*
         * If the relay receives a syslog message without a PRI, or with an
         * unidentifiable PRI, then it MUST insert a PRI with a Priority value
         * of 13
         */
        hdr->pri = 13;
        return -1;
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
        int ret;
        char *out;
        syslog_header_t hdr;
        struct regex_data rdata;
        lml_log_entry_t *log_entry;

        logparse_pri(&hdr, &str, &size);

        ret = lml_log_source_preprocess_input(ls, str, size, &out, &size);
        if ( ret < 0 )
                return;

        prelude_log_debug(3, "[LOG from=%s] %s\n", lml_log_source_get_name(ls), out);

        log_entry = lml_log_entry_new();
        if ( ! log_entry )
                return;

        lml_log_entry_set_log(log_entry, ls, out, size);

        rdata.log_source = ls;
        rdata.log_entry = log_entry;

        regex_exec(lml_log_source_get_regex_list(ls), &regex_match_cb, &rdata,
                   lml_log_entry_get_message(log_entry), lml_log_entry_get_message_len(log_entry));

        lml_log_entry_destroy(log_entry);
        config.line_processed++;
}



static void wait_for_event(void)
{
        size_t i;
        int udp_event_fd;
        int tcp_event_fd;
        size_t nb_server = config.udp_nserver + config.tcp_nserver;
        ev_io events[nb_server];

        /* 
         *  Initialize callback function for SIGHUP/SIGTERM/... events for interrupted running (daemonize or standalone)
         */
        ev_async_init(&ev_interrupt, libev_interrupt_cb);
        ev_async_start(&ev_interrupt);

        for ( i = 0; i < config.udp_nserver; i++ ) {
                udp_event_fd = udp_server_get_event_fd(config.udp_server[i]);
                ev_io_init(&events[i], libev_udp_cb, udp_event_fd, EV_READ);
                events[i].data = config.udp_server[i];
                ev_io_start(&events[i]);
        }

        for ( ; i < config.udp_nserver + config.tcp_nserver; i++ ) {
                tcp_event_fd = tcp_server_get_event_fd(config.tcp_server[i - config.udp_nserver]);
                ev_io_init(&events[i], libev_tcp_accept_cb, tcp_event_fd, EV_READ);
                events[i].data = config.tcp_server[i - config.udp_nserver];
                ev_io_start(&events[i]);
        }

        ev_run(0);
}



int main(int argc, char **argv)
{
        int ret;
        ev_timer evt;
        struct timeval end;
        struct sigaction action;

        /*
         * Initialize libev.
         */
        ev_default_loop(EVFLAG_AUTO);

        /*
         * make sure we ignore sighup until acceptable.
         */
#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        action.sa_flags = 0;
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        sigaction(SIGHUP, &action, NULL);
#endif

        memset(&start, 0, sizeof(start));
        memset(&end, 0, sizeof(end));

        prelude_init(&argc, argv);
        global_argv = argv;

        PRELUDE_PLUGIN_SET_PRELOADED_SYMBOLS();

        ret = prelude_option_new_root(&lml_root_optlist);
        if ( ret < 0 )
                return ret;

        ret = log_plugins_init(LOG_PLUGIN_DIR, lml_root_optlist);
        if (ret < 0)
                return ret;

        prelude_log_debug(1, "Initialized %d logs plugins.\n", ret);

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
        sigaction(SIGABRT, &action, NULL);
#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        sigaction(SIGUSR1, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
#endif

        ret = file_server_start_monitoring();
        if ( ret < 0 && ! config.udp_nserver && ! config.tcp_nserver ) {
                prelude_log(PRELUDE_LOG_WARN, "No file or UDP/TCP server available for monitoring: terminating.\n");
                return -1;
        }

        if ( config.daemon_mode ) {
                prelude_daemonize(config.pidfile);
                if ( config.pidfile )
                        free(config.pidfile);

                ev_loop_fork(EV_DEFAULT);
        }

        ev_timer_init(&evt, libev_timer_cb, 1, 1);
        ev_timer_start(&evt);

        /*
         * Whether we are using batch-mode or file notification, we need
         * to process the currently un-processed entry.
         */
        gettimeofday(&start, NULL);

        do {
                ret = file_server_read_once();
                prelude_timer_wake_up();
        } while ( ret > 0 );

        /*
         * if either FAM or UDP server is enabled, we use polling to know
         * if there are data available for reading. if batch_mode is set,
         * then we revert to reading every data at once.
         */
        if ( ! config.batch_mode )
                wait_for_event();
        else {
                gettimeofday(&end, NULL);

                /*
                 * only call prelude_client_destroy in case we are running in batch
                 * mode, causing an heartbeat to be sent to notice of a normal exit.
                 */
                if ( ! config.dry_run )
                        prelude_client_destroy(config.lml_client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);

                print_stats("", &end);
        }

        prelude_deinit();
        return 0;
}
