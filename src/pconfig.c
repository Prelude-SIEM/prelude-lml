/*****
*
* Copyright (C) 1998, 1999, 2000, 2002, 2003 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#include <libprelude/list.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>
#include <libprelude/prelude-log.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/daemonize.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/sensor.h>
#include <libprelude/prelude-path.h>

#include "config.h"
#include "pconfig.h"
#include "regex.h"
#include "log-common.h"
#include "file-server.h"
#include "udp-server.h"

#define MAX_FD 1024


int batch_mode = 0;
static char *pidfile = NULL;
udp_server_t *udp_srvr = NULL;
static char *udp_srvr_addr = NULL;
static uint16_t udp_srvr_port = 514;
static uid_t prelude_lml_user = 0;
static gid_t prelude_lml_group = 0;
static char *logfile_format = NULL, *logfile_ts_format = NULL;


static int print_version(prelude_option_t *opt, const char *arg)
{
	printf("prelude-lml %s.\n", VERSION);
	return prelude_option_end;
}



static int print_help(prelude_option_t *opt, const char *arg)
{
        prelude_option_print(NULL, CLI_HOOK, 25);
	return prelude_option_end;
}



static int set_batch_mode(prelude_option_t *opt, const char *arg)
{
        batch_mode = 1;
        file_server_set_batch_mode();
        return prelude_option_success;
}



static int set_rotation_interval(prelude_option_t *opt, const char *arg) 
{
        file_server_set_rotation_interval_max_difference(atoi(arg));
        return prelude_option_success;
}



static int set_quiet_mode(prelude_option_t *opt, const char *arg)
{
	prelude_log_use_syslog();
	return prelude_option_success;
}



static int set_daemon_mode(prelude_option_t *opt, const char *arg)
{
        prelude_daemonize(pidfile);
        if ( pidfile )
                free(pidfile);
        
        prelude_log_use_syslog();
        
        return prelude_option_success;
}


static int set_pidfile(prelude_option_t *opt, const char *arg)
{
        pidfile = strdup(arg);
        if ( ! pidfile ) {
                log(LOG_ERR, "memory exhausted.\n");
                return prelude_option_error;
        }
                                                
	return prelude_option_success;
}



static int set_logfile_format(prelude_option_t *opt, const char *arg)
{        
        if ( logfile_format )
                free(logfile_format);
        
        logfile_format = strdup(arg);       

        return prelude_option_success;
}



static int set_logfile_ts_format(prelude_option_t *opt, const char *arg)
{        
        if ( logfile_ts_format )
                free(logfile_ts_format);
        
        logfile_ts_format = strdup(arg);
                
        return prelude_option_success;
}




static int set_file(prelude_option_t *opt, const char *arg) 
{
        int ret;
        log_file_t *lf;

        lf = log_file_new();
        if ( ! lf )
                return prelude_option_error;

        if ( logfile_format ) {
                ret = log_file_set_log_fmt(lf, logfile_format);
                if ( ret < 0 )
                        return prelude_option_error;
        }

        if ( logfile_ts_format ) {
                ret = log_file_set_timestamp_fmt(lf, logfile_ts_format);
                if ( ret < 0 )
                        return prelude_option_error;
        }
        
        ret = log_file_set_filename(lf, arg);
        if ( ret < 0 ) 
                return prelude_option_error;
        
        ret = file_server_monitor_file(lf);
        if ( ret < 0 ) 
                return prelude_option_error;
        
        log(LOG_INFO, "- Added monitor for '%s' in %p.\n", arg, lf);
        
        return prelude_option_success;
}



#if 0
static int set_logwatch(prelude_option_t *opt, const char *arg)
{
        log_file_t *lf;
        
        lf = log_file_new();
        if ( ! lf )
                return prelude_option_error;

        prelude_option_set_private_data(opt, lf);
        prelude_option_parse_from_context(opt, NULL);
        
        return prelude_option_success;
}
#endif



static int enable_udp_server(prelude_option_t *opt, const char *arg) 
{
        udp_srvr = udp_server_new(udp_srvr_addr, udp_srvr_port);
        free(udp_srvr_addr);
        
        if ( ! udp_srvr )
                return prelude_option_error;
        
        return prelude_option_success;
}



static int set_udp_server_addr(prelude_option_t *opt, const char *arg) 
{
        udp_srvr_addr = strdup(arg);
        if ( ! udp_srvr_addr ) {
                log(LOG_ERR, "memory exhausted.\n");
                return prelude_option_error;
        }

        return prelude_option_success;
}


static int set_udp_server_port(prelude_option_t *opt, const char *arg) 
{
        udp_srvr_port = atoi(arg);
        return prelude_option_success;
}




static int set_lml_group(prelude_option_t *opt, const char *arg) 
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




static int set_lml_user(prelude_option_t *opt, const char *arg) 
{
        struct passwd *p;
        
        p = getpwnam(arg);
        if ( ! p ) {
                log(LOG_ERR, "couldn't find user %s.\n", arg);
                return prelude_option_error;
        }

        prelude_lml_user = p->pw_uid;

        /*
         * tell the prelude library that every operation should be done as
         * non root.
         */
        prelude_set_program_userid(p->pw_uid);

        return prelude_option_success;
}



int pconfig_set(int argc, char **argv)
{
	int ret;
        prelude_option_t *opt;
        
	prelude_option_add(NULL, CLI_HOOK, 'h', "help",
			   "Print this help", no_argument, print_help,
			   NULL);

	prelude_option_add(NULL, CLI_HOOK, 'v', "version",
			   "Print version number", no_argument,
			   print_version, NULL);

        prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'q', "quiet",
			   "Quiet mode", no_argument, set_quiet_mode,
			   NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'u', "user",
                           "Run as the specified user", required_argument,
                           set_lml_user, NULL);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'g', "group",
                           "Run in the specified group", required_argument,
                           set_lml_group, NULL);
        
	prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'd', "daemon",
			   "Run in daemon mode", no_argument,
			   set_daemon_mode, NULL);

	opt = prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'P', "pidfile",
                                 "Write Prelude LML PID to specified pidfile",
                                 required_argument, set_pidfile, NULL);
        prelude_option_set_priority(opt, option_run_first);
        
        opt = prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 's', "udp-srvr",
                                 "Listen syslog to UDP messages", no_argument,
                                 enable_udp_server, NULL);

        prelude_option_add(opt, CLI_HOOK | CFG_HOOK, 'a', "addr",
                           "Address to listen on (default 0.0.0.0)", required_argument,
                           set_udp_server_addr, NULL);
        
        prelude_option_add(opt, CLI_HOOK | CFG_HOOK, 'p', "port",
                           "Port to listen on (default 514)", required_argument,
                           set_udp_server_port, NULL);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'r', "rotation-interval",
                           "Specifies the maximum difference, in seconds, between the interval " \
                           "of two logfiles' rotation. If this difference is reached, a high "   \
                           "severity alert will be emited", required_argument,
                           set_rotation_interval, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'b', "batchmode",
                           "Tell LML to run in batch mode", no_argument,
                           set_batch_mode, NULL);

#if 0
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'w', "logwatch",
                                 "Specify a file to monitor (you might specify \"stdin\")",
                                 no_argument, set_logwatch, NULL);
        prelude_option_set_priority(opt, option_run_first);
#endif
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 't', "time-format", 
                           "Specify the input timestamp format", required_argument,
                           set_logfile_ts_format, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'l', "log-format", 
                           "Specify the input format", required_argument,
                           set_logfile_format, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'f', "file",
                           "Specify a file to monitor (you might specify \"stdin\")",
                           required_argument, set_file, NULL);
        
        ret = prelude_sensor_init("prelude-lml", PRELUDE_CONF, argc, argv);
	if ( ret == prelude_option_error || ret == prelude_option_end )
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
