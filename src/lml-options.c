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

#include "config.h"
#include "libmissing.h"

#include <stdio.h>
#include <ctype.h>
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
#include <glob.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/daemonize.h>

#include "prelude-lml.h"
#include "lml-options.h"
#include "log-source.h"
#include "log-entry.h"
#include "lml-alert.h"
#include "file-server.h"
#include "udp-server.h"

#define DEFAULT_UDP_SERVER_PORT 514


lml_config_t config;
static prelude_bool_t have_file = FALSE;
static const char *config_file = PRELUDE_LML_CONF;



static int drop_privilege(void)
{
        int ret;

        if ( config.wanted_gid != getgid() ) {
                ret = setgid(config.wanted_gid);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "change to GID %d failed: %s.\n",
                                    (int) config.wanted_gid, strerror(errno));
                        return ret;
                }

                ret = setgroups(1, &config.wanted_gid);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "removal of ancillary groups failed: %s.\n", strerror(errno));
                        return ret;
                }
        }


        if ( config.wanted_uid != getuid() ) {
                ret = setuid(config.wanted_uid);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "change to UID %d failed: %s.\n",
                                    (int) config.wanted_uid, strerror(errno));
                        return ret;
                }
        }

        return 0;
}


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
        char *endptr;
        unsigned long int off;

        off = strtoul(optarg, &endptr, 10);
        if ( *endptr != '\0' ) {
                prelude_string_sprintf(err, "Invalid max rotation time offset specified: %s", optarg);
                return -1;
        }

        file_server_set_max_rotation_time_offset(off);
        return 0;
}



static int get_rotation_time_offset(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        return prelude_string_sprintf(out, "%u", file_server_get_max_rotation_time_offset());
}


static int set_rotation_size_offset(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        char *endptr;
        unsigned long int off;

        off = strtoul(arg, &endptr, 10);
        if ( *endptr != '\0' ) {
                prelude_string_sprintf(err, "Invalid max rotation size offset specified: %s", arg);
                return -1;
        }

        file_server_set_max_rotation_size_offset(off);
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
        return lml_log_format_set_prefix_regex(context, arg);
}



static int set_logfile_ts_format(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        return lml_log_format_set_ts_fmt(context, arg);
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

        if ( ! arg || strcmp(arg, "-") == 0 ) {
                prelude_io_set_file_io(config.text_output_fd, stdout);
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


static int check_file_access(const char *filename)
{
        int ret;
        struct stat st;

        ret = stat(filename, &st);
        if ( ret < 0 ) {
                if ( errno == ENOENT )
                        prelude_log(PRELUDE_LOG_WARN, "%s does not exist.\n", filename);

                else if ( errno == EACCES )
                        goto out;

                else prelude_log(PRELUDE_LOG_WARN, "could not stat %s: %s.\n", filename, strerror(errno));

                return -1;
        }

        if ( config.wanted_uid == 0 )
                return 0;

        if ( st.st_uid == config.wanted_uid && st.st_mode & S_IRUSR )
                return 0;

        if ( st.st_gid == config.wanted_gid && st.st_mode & S_IRGRP )
                return 0;

        if ( st.st_mode & S_IROTH )
                return 0;

 out:
        prelude_log(PRELUDE_LOG_WARN, "%s is not available for reading to uid %d/gid %d.\n",
                    filename, config.wanted_uid, config.wanted_gid);

        return -1;
}


static int glob_errfunc_cb(const char *epath, int eerrno)
{
        prelude_log(PRELUDE_LOG_WARN, "error with '%s': %s.\n", epath, strerror(eerrno));
        return 0;
}


static int get_file_from_pattern(void *context, const char *pattern)
{
        int ret;
        size_t i;
        glob_t gl;
        lml_log_source_t *ls;

        ret = glob(pattern, GLOB_NOCHECK | GLOB_TILDE, glob_errfunc_cb, &gl);
        if ( ret != 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "glob failed: %s.\n", strerror(errno));
                return ret;
        }

        for ( i = 0; i < gl.gl_pathc; i++ ) {
                ret = check_file_access(gl.gl_pathv[i]);
                if ( ret < 0 )
                        continue; /* ignore error */

                ret = lml_log_source_new(&ls, context, gl.gl_pathv[i]);
                if ( ret < 0 )
                        break;

                else if ( ret == 1 )
                        continue;

                ret = file_server_monitor_file(ls);
                if ( ret < 0 )
                        break;

                have_file = TRUE;
        }

        globfree(&gl);

        return ret;
}


static int set_file(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        int ret;
        lml_log_source_t *ls;

        if ( *arg != '-' ) {
                ret = get_file_from_pattern(context, arg);
                if ( ret < 0 )
                        return 0; /* ignore error */
        } else {
                ret = lml_log_source_new(&ls, context, arg);
                if ( ret < 0 )
                        return prelude_error_from_errno(errno);

                if ( ret == 1 )
                        return 0;

                ret = file_server_monitor_file(ls);
                if ( ret < 0 )
                        return ret;

                have_file = TRUE;
        }

        return 0;
}



static int add_server(lml_log_source_t *ls, const char *addr, unsigned int port)
{
        config.udp_nserver++;

        config.udp_server = _prelude_realloc(config.udp_server, sizeof(*config.udp_server) * config.udp_nserver);
        if ( ! config.udp_server )
                return -1;

        config.udp_server[config.udp_nserver - 1] = udp_server_new(ls, addr, port);
        if ( ! config.udp_server[config.udp_nserver - 1] )
                return -1;

        return 0;
}



static int set_udp_server(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        int ret;
        unsigned int port;
        lml_log_source_t *ls;
        char *addr, source[512];

        if ( arg && *arg ) {
                ret = prelude_parse_address(arg, &addr, &port);
                if ( ret < 0 )
                        return ret;

                port = port ? port : DEFAULT_UDP_SERVER_PORT;
        } else {
                addr = strdup("0.0.0.0");
                port = DEFAULT_UDP_SERVER_PORT;
        }

        snprintf(source, sizeof(source), "%s:%u/udp", addr, port);

        ret = lml_log_source_new(&ls, context, source);
        if ( ret < 0 || ret == 1 ) {
                free(addr);
                return ret;
        }

        ret = add_server(ls, addr, port);
        free(addr);

        if ( ret < 0 )
                return -1;

        prelude_log(PRELUDE_LOG_INFO, "Listening for syslog message on %s.\n", source);

        return 0;
}



static int set_warning_limit(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        char *endptr;

        config.warning_limit = strtol(arg, &endptr, 10);
        if ( *endptr != '\0' || config.warning_limit < -1 ) {
                prelude_string_sprintf(err, "Invalid warning limit: %s", arg);
                return -1;
        }

        return 0;
}


static int set_format(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        lml_log_format_t *format;
        prelude_option_context_t *octx;

        format = lml_log_format_new(arg);
        if ( ! format )
                return -1;

        return prelude_option_new_context(opt, &octx, arg, format);
}



static int set_user(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        uid_t uid;
        const char *p;
        struct passwd *pw;

        for ( p = optarg; isdigit((int) *p); p++ );

        if ( *p == 0 )
                uid = atoi(optarg);
        else {
                pw = getpwnam(optarg);
                if ( ! pw ) {
                        prelude_log(PRELUDE_LOG_ERR, "could not lookup user '%s'.\n", optarg);
                        return -1;
                }

                uid = pw->pw_uid;
        }

        config.wanted_uid = uid;

        return 0;
}


static int set_group(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        gid_t gid;
        const char *p;
        struct group *grp;

        for ( p = optarg; isdigit((int) *p); p++ );

        if ( *p == 0 )
                gid = atoi(optarg);
        else {
                grp = getgrnam(optarg);
                if ( ! grp ) {
                        prelude_log(PRELUDE_LOG_ERR, "could not lookup group '%s'.\n", optarg);
                        return -1;
                }

                gid = grp->gr_gid;
        }

        config.wanted_gid = gid;

        return 0;
}



int lml_options_init(prelude_option_t *ropt, int argc, char **argv)
{
        int ret;
        prelude_option_t *opt;
        prelude_string_t *err;
        int all_hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        memset(&config, 0, sizeof(config));
        config.warning_limit = -1;
        config.wanted_uid = getuid();
        config.wanted_gid = getgid();

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI, 'h', "help",
                           "Print this help", PRELUDE_OPTION_ARGUMENT_NONE, print_help, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI, 'v', "version",
                           "Print version number", PRELUDE_OPTION_ARGUMENT_NONE,
                           print_version, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_CLI, 0, "user",
                           "Set the user ID used by prelude-lml", PRELUDE_OPTION_ARGUMENT_REQUIRED, set_user, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_CLI, 0, "group",
                           "Set the group ID used by prelude-lml", PRELUDE_OPTION_ARGUMENT_REQUIRED, set_group, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'q', "quiet",
                           "Quiet mode", PRELUDE_OPTION_ARGUMENT_NONE, set_quiet_mode, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'D', "debug-level",
                           "Debug mode", PRELUDE_OPTION_ARGUMENT_OPTIONAL, set_debug_mode, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'd', "daemon",
                           "Run in daemon mode", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_daemon_mode, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_FIRST);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'P', "pidfile",
                           "Write Prelude LML PID to specified file",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_pidfile, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI, 0, "text-output",
                           "Dump alert to stdout, or to the specified file", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                           set_text_output, NULL);

        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI, 0, "dry-run",
                           "No alert emission / Prelude connection", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_dry_run, NULL);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI, 'c', "config",
                           "Configuration file to use", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_conf_file, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

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

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 0, "warning-limit",
                           "Limit the number of parse warnings reported from sources (0 suppress, "
                           "-1 unlimited, or user defined number)", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_warning_limit, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'b', "batch-mode",
                           "Tell LML to run in batch mode", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_batch_mode, NULL);

        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 0, "ignore-metadata",
                           "Tell LML not to read/write metadata", PRELUDE_OPTION_ARGUMENT_NONE,
                           set_ignore_metadata, NULL);

        prelude_option_add(ropt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 0, "no-resolve",
                           "Do not attempt to resolve target address (useful for profiling)",
                           PRELUDE_OPTION_ARGUMENT_NONE, set_no_resolve, NULL);

        prelude_option_add(ropt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG,
                           0, "format", NULL, PRELUDE_OPTION_ARGUMENT_REQUIRED, set_format, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);

        prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG,
                           't', "time-format", "Specify the input timestamp format", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_logfile_ts_format, NULL);

        prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG,
                           'p', "prefix-regex", "Specify the input prefix format", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_logfile_prefix_regex, NULL);

        prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG,
                           'f', "file", "Specify a file to monitor (use \"-\" for standard input)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_file, NULL);

        prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 's', "udp-server",
                           "address:port pair to listen to syslog to UDP messages (default port 514)",
                           PRELUDE_OPTION_ARGUMENT_OPTIONAL, set_udp_server, NULL);

        ret = prelude_option_read(ropt, &config_file, &argc, argv, &err, NULL);
        if ( ret < 0 ) {
                if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EOF )
                        return -1;

                if ( err )
                        prelude_log(PRELUDE_LOG_WARN, "%s.\n", prelude_string_get_string(err));
                else
                        prelude_perror(ret, "error processing options");

                return -1;
        }

        while ( ret < argc )
                prelude_log(PRELUDE_LOG_WARN, "Unhandled command line argument: '%s'.\n", argv[ret++]);

        if ( config.batch_mode && config.udp_nserver ) {
                prelude_log(PRELUDE_LOG_WARN, "UDP server and batch modes can't be used together.\n");
                return -1;
        }

        if ( config.ignore_metadata && ! config.batch_mode ) {
                prelude_log(PRELUDE_LOG_WARN, "--ignore-metadata is only supported in batch mode.\n");
                return -1;
        }

        if ( ! have_file && ! config.udp_nserver ) {
                prelude_log(PRELUDE_LOG_WARN, "No file or UDP server available for monitoring: terminating.\n");
                return -1;
        }

        ret = drop_privilege();
        if ( ret < 0 )
                return -1;

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
                return -1;
        }

        return 0;
}
