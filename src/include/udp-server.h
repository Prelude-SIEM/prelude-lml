/*****
*
* Copyright (C) 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef UDP_SERVER_H
#define UDP_SERVER_H

typedef struct udp_server udp_server_t;


void udp_server_process_event(udp_server_t *server);

udp_server_t *udp_server_new(regex_list_t *list, const char *addr, unsigned int port);

void udp_server_close(udp_server_t *server);

int udp_server_get_event_fd(udp_server_t *srvr);

#endif				/* UDP_SERVER_H */
