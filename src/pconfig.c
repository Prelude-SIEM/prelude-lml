/*****
*
* Copyright (C) 1998, 1999, 2000, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libprelude/list.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>
#include <libprelude/prelude-log.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/daemonize.h>
#include <libprelude/sensor.h>
#include <libprelude/prelude-path.h>

#include "config.h"
#include "pconfig.h"
#include "queue.h"
#include "regex.h"
#include "file-server.h"
#include "udp-server.h"

#define MAX_FD 1024


udp_server_t *udp_srvr = NULL;
static uint16_t udp_srvr_port = 514;
static char *udp_srvr_addr = NULL;
static char *pidfile = NULL;
static uid_t prelude_lml_user = 0;


static int print_version(const char *arg)
{
	printf("prelude-lml %s.\n", VERSION);
	return prelude_option_end;
}



static int print_help(const char *arg)
{
	prelude_option_print(CLI_HOOK, 25);
	return prelude_option_end;
}



static int set_quiet_mode(const char *arg)
{
	prelude_log_use_syslog();
	return prelude_option_success;
}



static int set_daemon_mode(const char *arg)
{
        prelude_daemonize(pidfile);
        if ( pidfile )
                free(pidfile);
        
        prelude_log_use_syslog();
        
        return prelude_option_success;
}


static int set_pidfile(const char *arg)
{
        pidfile = strdup(arg);
	return prelude_option_success;
}



static int set_file(const char *arg) 
{
        int ret;
                
        ret = file_server_monitor_file(arg);
        if ( ret < 0 ) 
                return prelude_option_error;
        
        log(LOG_INFO, "- Added monitor for '%s'.\n", arg);

        return prelude_option_success;
}



static int enable_udp_server(const char *arg) 
{
        udp_srvr = udp_server_new(udp_srvr_addr, udp_srvr_port);
        free(udp_srvr_addr);
        
        if ( ! udp_srvr )
                return prelude_option_error;
        
        return prelude_option_success;
}



static int set_udp_server_addr(const char *arg) 
{
        udp_srvr_addr = strdup(arg);
        return prelude_option_success;
}


static int set_udp_server_port(const char *arg) 
{
        udp_srvr_port = atoi(arg);
        return prelude_option_success;
}



static int set_lml_user(const char *arg) 
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
        
        prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'f', "file",
                           "Specify a file to monitor", required_argument, set_file, NULL);

        
	ret = prelude_sensor_init("prelude-lml", PRELUDE_CONF, argc, argv);
	if ( ret == prelude_option_error || ret == prelude_option_end )
                exit(1);

        
        if ( prelude_lml_user && setuid(prelude_lml_user) < 0 ) {
                log(LOG_ERR, "couldn't set UID to %d.\n", prelude_lml_user);
                return -1;
        }
        
	return 0;
}
