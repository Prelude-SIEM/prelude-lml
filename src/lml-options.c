/*****
*
* Copyright (C) 1998, 1999, 2000, 2001, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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
#include "prelude-lml.h"
#include "lml-options.h"
#include "log-source.h"
#include "log-entry.h"
#include "lml-alert.h"
#include "file-server.h"
#include "udp-server.h"

#define DEFAULT_UDP_SERVER_PORT 514


lml_config_t config;
static const char *config_file = PRELUDE_LML_CONF;


static int set_conf_file(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        config_file = strdup(optarg);
        return 0;
}


static int print_version(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        printf("prelude-lml-%s\n", VERSION);
        exit(0);
}



static int print_help(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        prelude_option_print(NULL, PRELUDE_OPTION_TYPE_CLI, 25, stderr);
        return prelude_error(PRELUDE_ERROR_EOF);
}



static int set_batch_mode(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        config.batch_mode = TRUE;
        file_server_set_batch_mode();
        return 0;
}



static int set_ignore_metadata(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        config.ignore_metadata = TRUE;
        file_server_set_ignore_metadata();
        return 0;
}


static int set_no_resolve(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        config.no_resolve = TRUE;
        return 0;
}


static int set_rotation_time_offset(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        file_server_set_max_rotation_time_offset(atoi(optarg));
        return 0;
}



static int get_rotation_time_offset(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        return prelude_string_sprintf(out, "%u", file_server_get_max_rotation_time_offset());
}


static int set_rotation_size_offset(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        file_server_set_max_rotation_size_offset(atoi(arg));
        return 0;
}



static int get_rotation_size_offset(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        return prelude_string_sprintf(out, "%u", file_server_get_max_rotation_size_offset());
}


static int set_quiet_mode(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        prelude_log_set_flags(prelude_log_get_flags() | PRELUDE_LOG_FLAGS_QUIET);
        return 0;
}


static int set_debug_mode(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int level = (optarg) ? atoi(optarg) : PRELUDE_LOG_DEBUG;
        prelude_log_set_debug_level(level);
        return 0;
}


static int set_daemon_mode(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        prelude_daemonize(config.pidfile);
        if ( config.pidfile )
                free(config.pidfile);
        
        prelude_log_set_flags(prelude_log_get_flags()|PRELUDE_LOG_FLAGS_QUIET|PRELUDE_LOG_FLAGS_SYSLOG);
        
        return 0;
}


static int set_pidfile(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        config.pidfile = strdup(arg);
        if ( ! config.pidfile )
                return prelude_error_from_errno(errno);
        
        return 0;
}



static int set_logfile_prefix_regex(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{        
        if ( config.logfile_prefix_regex )
                free(config.logfile_prefix_regex);
        
        config.logfile_prefix_regex = strdup(arg);

        return 0;
}



static int set_logfile_ts_format(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{        
        if ( config.logfile_ts_format )
                free(config.logfile_ts_format);
        
        config.logfile_ts_format = strdup(arg);
                
        return 0;
}



static int set_dry_run(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        config.dry_run = TRUE;

        return 0;
}



static int set_text_output(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        int ret;
        FILE *fd;
        
        ret = prelude_io_new(&(config.text_output_fd));
        if ( ret < 0 )
                return ret;

        if ( strcmp(arg, "stdout") == 0 ) {
                prelude_io_set_file_io(config.text_output_fd, stdout);
                return 0;
        }

        else if ( strcmp(arg, "stderr") == 0 ) {
                prelude_io_set_file_io(config.text_output_fd, stderr);
                return 0;
        }

        fd = fopen(arg, "w");
        if ( ! fd ) {
                prelude_log(PRELUDE_LOG_ERR, "could not open %s for writing.\n", arg);
                prelude_io_destroy(config.text_output_fd);
                return -1;
        }

        prelude_io_set_file_io(config.text_output_fd, fd);

        return 0;
}



static int set_file(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        int ret;
        lml_log_source_t *ls;
        regex_list_t *rlist;
        
        ls = lml_log_source_new();
        if ( ! ls )
                return prelude_error_from_errno(errno);

        if ( config.logfile_prefix_regex ) {
                ret = lml_log_source_set_prefix_regex(ls, config.logfile_prefix_regex);
                if ( ret < 0 )
                        return ret;
        }

        if ( config.logfile_ts_format ) {
                ret = lml_log_source_set_ts_fmt(ls, config.logfile_ts_format);
                if ( ret < 0 )
                        return ret;
        }

        ret = access(arg, R_OK);
        if ( ret < 0 ) {
                prelude_string_sprintf(err, "%s does not exist or have wrong permissions", arg);
                return -1;
        }
        
        ret = lml_log_source_set_name(ls, arg);
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



static int destroy_udp_server(prelude_option_t *opt, prelude_string_t *err, void *context)
{
        if ( ! config.udp_srvr )
                return 0;
                
        prelude_log(PRELUDE_LOG_INFO, "- closing syslog server listening at %s:%d.\n",
                    config.udp_srvr_addr, config.udp_srvr_port);

        udp_server_close(config.udp_srvr);
        config.udp_srvr = NULL;

        if ( config.udp_srvr_addr ) {
                free(config.udp_srvr_addr); 
                config.udp_srvr_addr = NULL;
        }
        
        return 0;
}



static int get_udp_server(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        if ( ! config.udp_srvr )
                return 0;
        
        return prelude_string_sprintf(out, "%s:%u", config.udp_srvr_addr, config.udp_srvr_port);
}


static int set_udp_server(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        char *ptr = NULL;
        regex_list_t *rlist;
        
        destroy_udp_server(opt, err, context);
        
        if ( arg && *arg ) {
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

        prelude_log(PRELUDE_LOG_INFO, "- Listening for syslog message on %s:%d.\n", config.udp_srvr_addr, config.udp_srvr_port);

        return 0;
}




int lml_options_init(prelude_option_t *ropt, int argc, char **argv)
{
        int ret;
        prelude_option_t *opt;
        prelude_string_t *err;
        int all_hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        memset(&config, 0, sizeof(config));
        config.udp_srvr_port = DEFAULT_UDP_SERVER_PORT;
                
        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI, 'h', "help",
                           "Print this help", PRELUDE_OPTION_ARGUMENT_NONE, print_help, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);
        
        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI, 'v', "version",
                           "Print version number", PRELUDE_OPTION_ARGUMENT_NONE,
                           print_version, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'q', "quiet",
                           "Quiet mode", PRELUDE_OPTION_ARGUMENT_NONE, set_quiet_mode, NULL);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'D', "debug-level",
                           "Debug mode", PRELUDE_OPTION_ARGUMENT_OPTIONAL, set_debug_mode, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);
        
        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'd', "daemon",
                           "Run in daemon mode", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_daemon_mode, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_FIRST);
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI, 0, "text-output",
                           "Dump alert to stdout, or to the specified file", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_text_output, NULL);
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI, 0, "dry-run",
                           "No alert emission / Prelude connection", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_dry_run, NULL);
        
        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI, 'c', "config",
                           "Configuration file to use", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_conf_file, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);
        
        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'P', "pidfile",
                           "Write Prelude LML PID to specified pidfile",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_pidfile, NULL);
        
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);
        
        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|
                           PRELUDE_OPTION_TYPE_WIDE, 's', "udp-srvr",
                           "address:port pair to listen to syslog to UDP messages (default port 514)", 
                           PRELUDE_OPTION_ARGUMENT_OPTIONAL, set_udp_server, get_udp_server);

        prelude_option_set_destroy_callback(opt, destroy_udp_server);        
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);
                
        prelude_option_add(ropt, NULL, all_hook, 0, "max-rotation-time-offset",
                           "Specifies the maximum time difference, in seconds, between the time " \
                           "of logfiles rotation. If this amount is reached, a high "   \
                           "severity alert will be emited", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_rotation_time_offset, get_rotation_time_offset);
        
        prelude_option_add(ropt, NULL, all_hook, 0, "max-rotation-size-offset",
                           "Specifies the maximum difference, in bytes, between two logfile "
                           "rotation. If this difference is reached, a high severity alert "
                           "will be emited", PRELUDE_OPTION_ARGUMENT_REQUIRED, set_rotation_size_offset, 
                           get_rotation_size_offset);
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'b', "batch-mode",
                           "Tell LML to run in batch mode", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_batch_mode, NULL);

        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 0, "ignore-metadata",
                           "Tell LML not to read/write metadata", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_ignore_metadata, NULL);

        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 0, "no-resolve",
                           "Do not attempt to resolve target address (useful for profiling)",
                           PRELUDE_OPTION_ARGUMENT_NONE, set_no_resolve, NULL);
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG,
                           't', "time-format", "Specify the input timestamp format", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_logfile_ts_format, NULL);
        
        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG,
                           'p', "prefix-regex", "Specify the input prefix format", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_logfile_prefix_regex, NULL);
        
        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG,
                           'f', "file", "Specify a file to monitor (use \"-\" for standard input)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_file, NULL);
        
        ret = prelude_option_read(ropt, &config_file, &argc, argv, &err, NULL);
        if ( ret < 0 ) {
                if ( err )
                        prelude_log(PRELUDE_LOG_WARN, "%s.\n", prelude_string_get_string(err));
                else
                        prelude_perror(ret, "failed parsing LML options");
                
                return -1;
        }
        
        if ( config.batch_mode && config.udp_srvr ) {
                prelude_log(PRELUDE_LOG_WARN, "UDP server and batch modes can't be used together.\n");
                return -1;
        }

        if ( config.dry_run )
                return 0;
        
        ret = prelude_client_new(&config.lml_client, "prelude-lml");
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating prelude-client");                
                return -1;
        }

        prelude_client_set_config_filename(config.lml_client, config_file);
        
        ret = lml_alert_init(config.lml_client);
        if ( ret < 0 )
                return -1;
        
        ret = prelude_client_start(config.lml_client);
        if ( ret < 0 ) {
                prelude_perror(ret, "error starting prelude-client");
                
                if ( prelude_client_is_setup_needed(ret) )
                        prelude_client_print_setup_error(config.lml_client);

                return -1;
        }
                
        return 0;
}
