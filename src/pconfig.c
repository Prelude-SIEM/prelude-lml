/*****
*
* Copyright (C) 1998-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include <libprelude/prelude-inttypes.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-log.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/daemonize.h>
#include <libprelude/prelude-client.h>

#include "config.h"
#include "pconfig.h"
#include "regex.h"
#include "log-common.h"
#include "lml-alert.h"
#include "file-server.h"
#include "udp-server.h"

#define DEFAULT_ANALYZER_NAME "prelude-lml"
#define DEFAULT_UDP_SERVER_PORT 514

/*
 * udp server stuff
 */
static char *udp_srvr_addr;
static uint16_t udp_srvr_port;
udp_server_t *udp_srvr = NULL;

int batch_mode = 0;
prelude_client_t *lml_client;
static char *pidfile = NULL;
static uid_t prelude_lml_user = 0;
static gid_t prelude_lml_group = 0;
static char *logfile_format = NULL, *logfile_ts_format = NULL;


static int get_version(void *context, prelude_option_t *opt, char *buf, size_t size)
{
        snprintf(buf, size, "prelude-lml %s", VERSION);
        return 0;
}


static int print_version(void *context, prelude_option_t *opt, const char *arg)
{
	printf("prelude-lml %s.\n", VERSION);
	return prelude_option_end;
}



static int print_help(void *context, prelude_option_t *opt, const char *arg)
{
        prelude_option_print(NULL, CLI_HOOK, 25);
	return prelude_option_end;
}



static int set_batch_mode(void *context, prelude_option_t *opt, const char *arg)
{
        batch_mode = 1;
        file_server_set_batch_mode();
        return prelude_option_success;
}



static int set_rotation_time_offset(void *context, prelude_option_t *opt, const char *arg) 
{
        file_server_set_max_rotation_time_offset(atoi(arg));
        return prelude_option_success;
}



static int get_rotation_time_offset(void *context, prelude_option_t *opt, char *buf, size_t size)
{
        snprintf(buf, size, "%u", file_server_get_max_rotation_time_offset());
        return 0;
}


static int set_rotation_size_offset(void *context, prelude_option_t *opt, const char *arg) 
{
        file_server_set_max_rotation_size_offset(atoi(arg));
        return prelude_option_success;
}



static int get_rotation_size_offset(void *context, prelude_option_t *opt, char *buf, size_t size)
{
        snprintf(buf, size, "%u", file_server_get_max_rotation_size_offset());
        return 0;
}


static int set_quiet_mode(void *context, prelude_option_t *opt, const char *arg)
{
	prelude_log_use_syslog();
	return prelude_option_success;
}



static int set_daemon_mode(void *context, prelude_option_t *opt, const char *arg)
{
        prelude_daemonize(pidfile);
        if ( pidfile )
                free(pidfile);
        
        prelude_log_use_syslog();
        
        return prelude_option_success;
}


static int set_pidfile(void *context, prelude_option_t *opt, const char *arg)
{
        pidfile = strdup(arg);
        if ( ! pidfile ) {
                log(LOG_ERR, "memory exhausted.\n");
                return prelude_option_error;
        }
        
        return prelude_option_success;
}



static int set_logfile_format(void *context, prelude_option_t *opt, const char *arg)
{        
        if ( logfile_format )
                free(logfile_format);
        
        logfile_format = strdup(arg);       

        return prelude_option_success;
}



static int set_logfile_ts_format(void *context, prelude_option_t *opt, const char *arg)
{        
        if ( logfile_ts_format )
                free(logfile_ts_format);
        
        logfile_ts_format = strdup(arg);
                
        return prelude_option_success;
}




static int set_file(void *context, prelude_option_t *opt, const char *arg) 
{
        int ret;
        log_source_t *ls;
        regex_list_t *rlist;
        
        ls = log_source_new();
        if ( ! ls )
                return prelude_option_error;

        if ( logfile_format ) {
                ret = log_source_set_log_fmt(ls, logfile_format);
                if ( ret < 0 )
                        return prelude_option_error;
        }

        if ( logfile_ts_format ) {
                ret = log_source_set_timestamp_fmt(ls, logfile_ts_format);
                if ( ret < 0 )
                        return prelude_option_error;
        }
        
        ret = access(arg, R_OK);
        if ( ret < 0 ) {
                log(LOG_ERR, "%s does not exist or have wrong permissions: check your configuration.\n", arg);
                return -1;
        }
        
        ret = log_source_set_name(ls, arg);
        if ( ret < 0 ) 
                return prelude_option_error;

        rlist = regex_init(arg);
        if ( ! rlist )
                return prelude_option_error;
        
        ret = file_server_monitor_file(rlist, ls);
        if ( ret < 0 ) 
                return prelude_option_error;
                
        return prelude_option_success;
}



static int destroy_udp_server(void *context, prelude_option_t *opt)
{
        if ( ! udp_srvr )
                return 0;
                
        log(LOG_INFO, "- Closing syslog server listening at %s:%d.\n", udp_srvr_addr, udp_srvr_port);

        udp_server_close(udp_srvr);
        udp_srvr = NULL;
        
        return 0;
}



static int get_udp_server(void *context, prelude_option_t *opt, char *out, size_t size)
{
        if ( ! udp_srvr )
                return 0;
        
        snprintf(out, size, "%s:%u", udp_srvr_addr, udp_srvr_port);
        return 0;
}


static int set_udp_server(void *context, prelude_option_t *opt, const char *arg) 
{
        char *ptr = NULL;
        regex_list_t *rlist;
       
        destroy_udp_server(context, opt);
        
        udp_srvr_port = DEFAULT_UDP_SERVER_PORT;

        if ( arg ) {
                ptr = strrchr(arg, ':');
                if ( ptr ) {
                        *ptr = 0;
                        udp_srvr_port = atoi(ptr + 1);
                }
                
                udp_srvr_addr = strdup(arg);
                
                if ( ptr )
                        *ptr = ':';
        } 
        
        else udp_srvr_addr = strdup("0.0.0.0");
        
        rlist = regex_init("syslog");
        if ( ! rlist ) 
                return prelude_option_error;
        
        udp_srvr = udp_server_new(rlist, udp_srvr_addr, udp_srvr_port);        
        if ( ! udp_srvr )
                return prelude_option_error;

        log(LOG_INFO, "- Listening for syslog message on %s:%d.\n", udp_srvr_addr, udp_srvr_port);

        return prelude_option_success;
}



static int set_lml_group(void *context, prelude_option_t *opt, const char *arg) 
{
        struct group *grp;

        grp = getgrnam(arg);
        if ( ! grp ) {
                log(LOG_ERR, "couldn't find group %s.\n", arg);
                return prelude_option_error;
        }

        prelude_lml_group = grp->gr_gid;

        return prelude_option_success;
}




static int set_lml_user(void *context, prelude_option_t *opt, const char *arg) 
{
        struct passwd *p;
        
        p = getpwnam(arg);
        if ( ! p ) {
                log(LOG_ERR, "couldn't find user %s.\n", arg);
                return prelude_option_error;
        }

        prelude_lml_user = p->pw_uid;
        prelude_client_set_uid(context, p->pw_uid);
        
        return prelude_option_success;
}




int pconfig_set(int argc, char **argv)
{
        int ret;
        prelude_option_t *opt;
        
	prelude_option_add(NULL, CLI_HOOK, 'h', "help",
			   "Print this help", no_argument, print_help,
			   NULL);

	prelude_option_add(NULL, CLI_HOOK|WIDE_HOOK, 'v', "version",
			   "Print version number", no_argument,
			   print_version, get_version);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'q', "quiet",
			   "Quiet mode", no_argument, set_quiet_mode,
			   NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'u', "user",
                           "Run as the specified user", required_argument,
                           set_lml_user, NULL);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'g', "group",
                           "Run in the specified group", required_argument,
                           set_lml_group, NULL);
        
	prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'd', "daemon",
			   "Run in daemon mode", no_argument,
			   set_daemon_mode, NULL);
        
	opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'P', "pidfile",
                                 "Write Prelude LML PID to specified pidfile",
                                 required_argument, set_pidfile, NULL);
        prelude_option_set_priority(opt, option_run_first);
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 's', "udp-srvr",
                           "address:port pair to listen to syslog to UDP messages (default port 514)", 
                           optionnal_argument, set_udp_server, get_udp_server);
        prelude_option_set_destroy_callback(opt, destroy_udp_server);
        prelude_option_set_priority(opt, option_run_last);
        
        prelude_option_set_priority(opt, option_run_last);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 't', "max-rotation-time-offset",
                           "Specifies the maximum time difference, in seconds, between the time " \
                           "of logfiles rotation. If this amount is reached, a high "   \
                           "severity alert will be emited", required_argument,
                           set_rotation_time_offset, get_rotation_time_offset);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 's', "max-rotation-size-offset",
                           "Specifies the maximum difference, in bytes, between two logfile "
                           "rotation. If this difference is reached, a high severity alert "
                           "will be emited", required_argument, set_rotation_size_offset, 
                           get_rotation_size_offset);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'b', "batchmode",
                           "Tell LML to run in batch mode", no_argument,
                           set_batch_mode, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|ALLOW_MULTIPLE_CALL, 't', "time-format", 
                           "Specify the input timestamp format", required_argument,
                           set_logfile_ts_format, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|ALLOW_MULTIPLE_CALL, 'l', "log-format", 
                           "Specify the input format", required_argument,
                           set_logfile_format, NULL);
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|ALLOW_MULTIPLE_CALL, 'f', "file",
                                 "Specify a file to monitor (you might specify \"stdin\")",
                                 required_argument, set_file, NULL);

        prelude_option_set_priority(opt, option_run_last);

        lml_client = prelude_client_new(PRELUDE_CLIENT_CAPABILITY_SEND_IDMEF);
        if ( ! lml_client )
                return -1;
        
        ret = lml_alert_init(lml_client);
        if ( ret < 0 )
                return -1;
        
        ret = prelude_client_init(lml_client, "prelude-lml", PRELUDE_CONF, argc, argv);
        if ( ret < 0 )
                exit(1);
        
        if ( batch_mode && udp_srvr ) {
                log(LOG_ERR, "UDP server and batch modes can't be used together.\n");
                return -1;
        }
        
        if ( prelude_lml_group && setgid(prelude_lml_group) < 0 ) {
                log(LOG_ERR, "couldn't set GID to %d.\n", prelude_lml_group);
                return -1;
        }

        if ( prelude_lml_user && setuid(prelude_lml_user) < 0 ) {
                log(LOG_ERR, "couldn't set UID to %d.\n", prelude_lml_user);
                return -1;
        }
        
	return 0;
}
