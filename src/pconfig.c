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

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/daemonize.h>

#include "config.h"
#include "libmissing.h"
#include "pconfig.h"
#include "regex.h"
#include "log-common.h"
#include "lml-alert.h"
#include "file-server.h"
#include "udp-server.h"

#define DEFAULT_UDP_SERVER_PORT 514


lml_config_t config;
static const char *config_file = PRELUDE_LML_CONF;


static int set_conf_file(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        config_file = strdup(optarg);
        return 0;
}


static int print_version(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        printf("prelude-lml %s.\n", VERSION);
        return prelude_error(PRELUDE_ERROR_EOF);
}



static int print_help(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        prelude_option_print(NULL, PRELUDE_OPTION_TYPE_CLI, 25);
        return prelude_error(PRELUDE_ERROR_EOF);
}



static int set_batch_mode(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        config.batch_mode = TRUE;
        file_server_set_batch_mode();
        return 0;
}



static int set_ignore_metadata(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        config.ignore_metadata = TRUE;
        file_server_set_ignore_metadata();
        return 0;
}

static int set_rotation_time_offset(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err) 
{
        file_server_set_max_rotation_time_offset(atoi(optarg));
        return 0;
}



static int get_rotation_time_offset(void *context, prelude_option_t *opt, prelude_string_t *out)
{
        return prelude_string_sprintf(out, "%u", file_server_get_max_rotation_time_offset());
}


static int set_rotation_size_offset(void *context, prelude_option_t *opt, const char *arg, prelude_string_t *err) 
{
        file_server_set_max_rotation_size_offset(atoi(arg));
        return 0;
}



static int get_rotation_size_offset(void *context, prelude_option_t *opt, prelude_string_t *out)
{
        return prelude_string_sprintf(out, "%u", file_server_get_max_rotation_size_offset());
}


static int set_quiet_mode(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        prelude_log_use_syslog();
        return 0;
}


static int set_daemon_mode(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        prelude_daemonize(config.pidfile);
        if ( config.pidfile )
                free(config.pidfile);
        
        prelude_log_use_syslog();
        
        return 0;
}


static int set_pidfile(void *context, prelude_option_t *opt, const char *arg, prelude_string_t *err)
{
        config.pidfile = strdup(arg);
        if ( ! config.pidfile )
                return prelude_error_from_errno(errno);
        
        return 0;
}



static int set_logfile_format(void *context, prelude_option_t *opt, const char *arg, prelude_string_t *err)
{        
        if ( config.logfile_format )
                free(config.logfile_format);
        
        config.logfile_format = strdup(arg);

        return 0;
}



static int set_logfile_ts_format(void *context, prelude_option_t *opt, const char *arg, prelude_string_t *err)
{        
        if ( config.logfile_ts_format )
                free(config.logfile_ts_format);
        
        config.logfile_ts_format = strdup(arg);
                
        return 0;
}



static int set_dry_run(void *context, prelude_option_t *opt, const char *arg, prelude_string_t *err)
{
        config.dry_run = TRUE;

        return 0;
}



static int set_text_output(void *context, prelude_option_t *opt, const char *arg, prelude_string_t *err)
{
        int ret;
        FILE *fd;
        
        ret = prelude_io_new(&(config.text_output_fd));
        if ( ret < 0 )
                return ret;

        if ( ! arg ) {
                prelude_io_set_file_io(config.text_output_fd, stdout);
                return 0;
        }

        fd = fopen(arg, "w");
        if ( ! fd ) {
                log(LOG_INFO, "could not open %s for writing.\n", arg);
                prelude_io_destroy(config.text_output_fd);
                return -1;
        }

        prelude_io_set_file_io(config.text_output_fd, fd);

        return 0;
}



static int set_file(void *context, prelude_option_t *opt, const char *arg, prelude_string_t *err) 
{
        int ret;
        log_source_t *ls;
        regex_list_t *rlist;
        
        ls = log_source_new();
        if ( ! ls )
                return prelude_error_from_errno(errno);

        if ( config.logfile_format ) {
                ret = log_source_set_log_fmt(ls, config.logfile_format);
                if ( ret < 0 )
                        return ret;
        }

        if ( config.logfile_ts_format ) {
                ret = log_source_set_timestamp_fmt(ls, config.logfile_ts_format);
                if ( ret < 0 )
                        return ret;
        }
        
        ret = access(arg, R_OK);
        if ( ret < 0 ) {
                prelude_string_sprintf(err, "%s does not exist or have wrong permissions", arg);
                return -1;
        }
        
        ret = log_source_set_name(ls, arg);
        if ( ret < 0 ) 
                return ret;

        rlist = regex_init(arg);
        if ( ! rlist )
                return -1;
        
        ret = file_server_monitor_file(rlist, ls);
        if ( ret < 0 ) 
                return ret;
                
        return 0;
}



static int destroy_udp_server(void *context, prelude_option_t *opt, prelude_string_t *err)
{
        if ( ! config.udp_srvr )
                return 0;
                
        log(LOG_INFO, "- closing syslog server listening at %s:%d.\n", config.udp_srvr_addr, config.udp_srvr_port);

        udp_server_close(config.udp_srvr);
        config.udp_srvr = NULL;
        
        return 0;
}



static int get_udp_server(void *context, prelude_option_t *opt, prelude_string_t *out)
{
        if ( ! config.udp_srvr )
                return 0;
        
        return prelude_string_sprintf(out, "%s:%u", config.udp_srvr_addr, config.udp_srvr_port);
}


static int set_udp_server(void *context, prelude_option_t *opt, const char *arg, prelude_string_t *err) 
{
        char *ptr = NULL;
        regex_list_t *rlist;
        
        destroy_udp_server(context, opt, err);

        if ( ! arg )
                return 0;
        
        if ( arg ) {
                ptr = strrchr(arg, ':');
                if ( ptr ) {
                        *ptr = 0;
                        config.udp_srvr_port = atoi(ptr + 1);
                }
                
                config.udp_srvr_addr = strdup(arg);
                
                if ( ptr )
                        *ptr = ':';
        } 
        
        else config.udp_srvr_addr = strdup("0.0.0.0");
        
        rlist = regex_init("syslog");
        if ( ! rlist ) 
                return -1;
        
        config.udp_srvr = udp_server_new(rlist, config.udp_srvr_addr, config.udp_srvr_port);        
        if ( ! config.udp_srvr )
                return -1;

        log(LOG_INFO, "- Listening for syslog message on %s:%d.\n", config.udp_srvr_addr, config.udp_srvr_port);

        return 0;
}




int pconfig_init(prelude_option_t *ropt, int argc, char **argv)
{
        int ret;
        prelude_option_t *opt;
        prelude_string_t *err;
        int all_hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        config.pidfile = NULL;
        config.logfile_format = NULL;
        config.logfile_ts_format = NULL;
        config.lml_client = NULL;
        config.batch_mode = FALSE;
        config.dry_run = FALSE;
        config.ignore_metadata = FALSE;
        config.udp_srvr = NULL;
        config.udp_srvr_addr = NULL;
        config.udp_srvr_port = DEFAULT_UDP_SERVER_PORT;
        config.text_output_fd = NULL;
        
        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI, 'h', "help",
                           "Print this help", PRELUDE_OPTION_ARGUMENT_NONE, print_help, NULL);

        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI, 'v', "version",
                           "Print version number", PRELUDE_OPTION_ARGUMENT_NONE,
                           print_version, NULL);

        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'q', "quiet",
                           "Quiet mode", PRELUDE_OPTION_ARGUMENT_NONE, set_quiet_mode, NULL);
                
        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'd', "daemon",
                           "Run in daemon mode", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_daemon_mode, NULL);

        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI, 0, "text-output",
                           "Dump alert to stdout, or to the specified file", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                           set_text_output, NULL);
        
        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI, 0, "dry-run",
                           "No alert emission / Prelude connection", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_dry_run, NULL);
        
        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI, 'c', "config",
                           "Configuration file to use", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_conf_file, NULL);
        
        opt = prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'P', "pidfile",
                                 "Write Prelude LML PID to specified pidfile",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, set_pidfile, NULL);
        
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_FIRST);
        
        opt = prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|
                                 PRELUDE_OPTION_TYPE_WIDE, 's', "udp-srvr",
                                 "address:port pair to listen to syslog to UDP messages (default port 514)", 
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, set_udp_server, get_udp_server);

        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);
                
        prelude_option_add(ropt, all_hook, 't', "max-rotation-time-offset",
                           "Specifies the maximum time difference, in seconds, between the time " \
                           "of logfiles rotation. If this amount is reached, a high "   \
                           "severity alert will be emited", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_rotation_time_offset, get_rotation_time_offset);
        
        prelude_option_add(ropt, all_hook, 's', "max-rotation-size-offset",
                           "Specifies the maximum difference, in bytes, between two logfile "
                           "rotation. If this difference is reached, a high severity alert "
                           "will be emited", PRELUDE_OPTION_ARGUMENT_REQUIRED, set_rotation_size_offset, 
                           get_rotation_size_offset);
        
        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'b', "batchmode",
                           "Tell LML to run in batch mode", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_batch_mode, NULL);

        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 0, "ignore-metadata",
                           "Tell LML not to read/write metadata", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_ignore_metadata, NULL);
        
        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_ALLOW_MULTIPLE_CALL,
                           't', "time-format", "Specify the input timestamp format", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_logfile_ts_format, NULL);
        
        prelude_option_add(ropt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_ALLOW_MULTIPLE_CALL,
                           'l', "log-format", "Specify the input format", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_logfile_format, NULL);
        
        opt = prelude_option_add(ropt,  PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_ALLOW_MULTIPLE_CALL,
                                 'f', "file", "Specify a file to monitor (use \"-\" for standard input)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, set_file, NULL);
        
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);
        
        
        ret = prelude_option_parse_arguments(NULL, ropt, &config_file, &argc, argv, &err);
        if ( ret < 0 ) {
                if ( err )
                        log(LOG_INFO, "%s.\n", prelude_string_get_string(err));
                else
                        prelude_perror(ret, "failed parsing LML options");
                
                return -1;
        }
        
        if ( config.batch_mode && config.udp_srvr ) {
                log(LOG_ERR, "UDP server and batch modes can't be used together.\n");
                return -1;
        }

        if ( config.dry_run )
                return 0;
        
        ret = prelude_client_new(&(config.lml_client), PRELUDE_CONNECTION_CAPABILITY_CONNECT, "prelude-lml", config_file);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating prelude-client");
                
                if ( prelude_client_is_setup_needed(config.lml_client, ret) )
                        prelude_client_print_setup_error(config.lml_client);
                
                return -1;
        }
        
        ret = lml_alert_init(config.lml_client);
        if ( ret < 0 )
                return -1;
        
        ret = prelude_client_start(config.lml_client);
        if ( ret < 0 ) {
                prelude_perror(ret, "error starting prelude-client");
                return -1;
        }
                
        return 0;
}
