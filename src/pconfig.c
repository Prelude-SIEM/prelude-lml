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
#include <libprelude/sensor.h>

#include "config.h"
#include "pconfig.h"

extern Pconfig_t config;



static int print_version(const char *arg)
{
	printf("prelude-lml %s.\n", VERSION);
	return prelude_option_success;
}



static int get_version(char *buf, size_t size)
{
	snprintf(buf, size, "prelude-lml %s\n", VERSION);
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
	config.daemonize = 1;
	return prelude_option_success;
}


static int set_pidfile(const char *arg)
{
	config.pidfile = arg;
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



int pconfig_set(int argc, char **argv)
{
	int ret;

	/*
	 * default.
	 */
	config.daemonize = 0;
	config.report_only_one = 1;
	config.pidfile = NULL;

	prelude_option_add(NULL, CLI_HOOK, 'h', "help",
			   "Print this help", no_argument, print_help,
			   NULL);

	prelude_option_add(NULL, CLI_HOOK | WIDE_HOOK, 'v', "version",
			   "Print version number", no_argument,
			   print_version, get_version);

	prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'q', "quiet",
			   "Quiet mode", no_argument, set_quiet_mode,
			   NULL);

	prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'd', "daemon",
			   "Run in daemon mode", no_argument,
			   set_daemon_mode, NULL);

	prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'P', "pidfile",
			   "Write Prelude PID to pidfile",
			   required_argument, set_pidfile, NULL);

        prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 'f', "file",
                           "File to monitor", required_argument, set_file, NULL);
        
	ret = prelude_sensor_init("prelude-lml", PRELUDE_CONF, argc, argv);
	if (ret == prelude_option_error || ret == prelude_option_end)
		exit(1);

	return 0;
}
