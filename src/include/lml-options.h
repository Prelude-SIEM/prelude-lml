/*****
*
* Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _LML_PCONFIG_H
#define _LML_PCONFIG_H

#include <libprelude/prelude-inttypes.h>
#include "regex.h"
#include "udp-server.h"

int lml_options_init(prelude_option_t *lml_optlist, int argc, char **argv);

typedef struct {
        char *pidfile;
        char *logfile_prefix_regex;
        char *logfile_ts_format;

        prelude_client_t *lml_client;

        prelude_bool_t batch_mode;
        prelude_bool_t dry_run;
        prelude_bool_t ignore_metadata;
        prelude_bool_t no_resolve;
        
        udp_server_t *udp_srvr;
        char *udp_srvr_addr;
        unsigned int udp_srvr_port;

        prelude_io_t *text_output_fd;
        unsigned long alert_count;
        unsigned long line_processed;
} lml_config_t;

#endif /* _LML_PCONFIG_H */
