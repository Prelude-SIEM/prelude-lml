/*****
*
* Copyright (C) 2000-2016 CS-SI. All Rights Reserved.
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

#ifndef LML_OPTIONS_H
#define LML_OPTIONS_H

#include <libprelude/prelude-inttypes.h>
#include "regex.h"
#include "udp-server.h"
#include "tcp-server.h"

int lml_options_init(prelude_option_t *lml_optlist, int argc, char **argv);

typedef struct {
        char *pidfile;
        const char *system_charset;
        char *charset;
        int charset_ref;

        char *log_buffer;
        unsigned int log_max_length;

        prelude_client_t *lml_client;

        prelude_bool_t batch_mode;
        prelude_bool_t dry_run;
        prelude_bool_t ignore_metadata;
        prelude_bool_t no_resolve;
        prelude_bool_t daemon_mode;

        size_t udp_nserver;
        udp_server_t **udp_server;

        size_t tcp_nserver;
        tcp_server_t **tcp_server;

        unsigned int tls_dh_bits;
        unsigned int tls_dh_regenerate;

        prelude_io_t *text_output_fd;
        unsigned long alert_count;
        unsigned long line_processed;

        int warning_limit;
        uid_t wanted_uid;
        gid_t wanted_gid;
} lml_config_t;

#endif
