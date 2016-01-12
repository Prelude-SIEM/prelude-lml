/*****
*
* Copyright (C) 2003-2016 CS-SI. All Rights Reserved.
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

#ifndef UDP_SERVER_H
#define UDP_SERVER_H

typedef struct udp_server udp_server_t;


void udp_server_process_event(udp_server_t *server);

udp_server_t *udp_server_new(lml_log_source_t *ls, const char *addr, unsigned int port);

void udp_server_close(udp_server_t *server);

int udp_server_get_event_fd(udp_server_t *srvr);

const char *udp_server_get_addr(udp_server_t *server);

unsigned int udp_server_get_port(udp_server_t *server);

#endif 
