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

#include "config.h"
#include "pconfig.h"
#include "queue.h"
#include "file-server.h"


static const char *pidfile = NULL;

static int udp_srvr_enabled = 0;
static uint16_t udp_srvr_port = 514;
static const char *udp_srvr_addr = NULL;



static int print_version(const char *arg)
{
	printf("prelude-lml %s.\n", VERSION);
	return prelude_option_success;
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
        prelude_log_use_syslog();

        return prelude_option_success;
}


static int set_pidfile(const char *arg)
{
        pidfile = arg;
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
        udp_srvr_enabled = 1;
        return prelude_option_success;
}



static int set_udp_server_addr(const char *arg) 
{
        udp_srvr_addr = arg;
        return prelude_option_success;
}


static int set_udp_server_port(const char *arg) 
{
        udp_srvr_port = atoi(arg);
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

	prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'd', "daemon",
			   "Run in daemon mode", no_argument,
			   set_daemon_mode, NULL);

	opt = prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'P', "pidfile",
                                 "Write Prelude PID to pidfile",
                                 required_argument, set_pidfile, NULL);
        prelude_option_set_priority(opt, option_run_first);
        
        opt = prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'u', "udp-srvr",
                                 "Listen to UDP messages", no_argument,
                                 enable_udp_server, NULL);

        prelude_option_add(opt, CLI_HOOK | CFG_HOOK, 'a', "addr",
                           "Address to listen on (default 0.0.0.0)", required_argument,
                           set_udp_server_addr, NULL);
        
        prelude_option_add(opt, CLI_HOOK | CFG_HOOK, 'p', "port",
                           "Port to listen on (default 514)", required_argument,
                           set_udp_server_port, NULL);
        
        prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'f', "file",
                           "File to monitor", required_argument, set_file, NULL);
        
	ret = prelude_sensor_init("prelude-lml", PRELUDE_CONF, argc, argv);
	if (ret == prelude_option_error || ret == prelude_option_end)
		exit(1);

	return 0;
}



const char *pconfig_get_udp_srvr_addr(void) 
{
        return udp_srvr_addr;
}


int pconfig_get_udp_srvr_port(void) 
{
        return udp_srvr_port;
}


int pconfig_is_udp_srvr_enabled(void)
{
        return udp_srvr_enabled;
}


