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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libprelude/common.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-list.h>

#include "config.h"
#include "libmissing.h"
#include "prelude-lml.h"
#include "common.h"
#include "regex.h"
#include "log-source.h"
#include "udp-server.h"


/*
 * From RFC 3164, section 4.1:
 *
 * The full format of a syslog message seen on the wire has three
 * discernable parts.  The first part is called the PRI, the second part
 * is the HEADER, and the third part is the MSG.  The total length of
 * the packet MUST be 1024 bytes or less.
 */
#define SYSLOG_MSG_MAX_SIZE 1024


struct udp_server {
        int sockfd;
        lml_log_source_t *ls;
        regex_list_t *rlist;
};



void udp_server_process_event(udp_server_t *server)
{
        ssize_t ret;
        socklen_t len;
        char src[512];
        struct sockaddr_in addr;
        char buf[SYSLOG_MSG_MAX_SIZE], *ptr;
        
        len = sizeof(struct sockaddr);

        ret = recvfrom(server->sockfd, buf, sizeof(buf) - 1, 0, (struct sockaddr *) &addr, &len);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error receiving syslog message.\n");
                return;
        }

        buf[ret] = '\0';
        
        snprintf(src, sizeof(src), "%s:%d", inet_ntoa(addr.sin_addr), addr.sin_port);        
        lml_log_source_set_name(server->ls, src);

        /*
         * we don't care about syslog priority / facility.
         */
        ptr = strchr(buf, '>');
        if ( ! ptr )
                ptr = buf;
        else {
                ret--;
                ptr++;
        }
        
        lml_dispatch_log(server->rlist, server->ls, ptr, ret);
}



void udp_server_close(udp_server_t *server)
{
        lml_log_source_destroy(server->ls);
        close(server->sockfd);
        free(server);
}



int udp_server_get_event_fd(udp_server_t *server) 
{
        if ( ! server )
                return -1;
        
        return server->sockfd;
}



udp_server_t *udp_server_new(regex_list_t *rlist, const char *addr, unsigned int port)
{
        int ret;
        udp_server_t *server;
        char buf[sizeof("65535")];
        struct addrinfo hints, *ai;
        
        server = malloc(sizeof(*server));
        if ( ! server ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        server->rlist = rlist;
        
        server->ls = lml_log_source_new();
        if ( ! server->ls )
                return NULL;
        
        server->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if ( server->sockfd < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't create socket.\n");
                free(server);
                return NULL;
        }

        memset(&hints, 0, sizeof(hints));
        snprintf(buf, sizeof(buf), "%u", port);
        
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        
        ret = getaddrinfo(addr, buf, &hints, &ai);
        if ( ret != 0 ) {
                fprintf(stderr, "could not resolve %s: %s.\n", addr,
                        (ret == EAI_SYSTEM) ? strerror(errno) : gai_strerror(ret));
                return NULL;
        }
        
        ret = bind(server->sockfd, ai->ai_addr, ai->ai_addrlen);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't bind to socket: %s.\n", strerror(errno));
                udp_server_close(server);
                return NULL;
        }

        freeaddrinfo(ai);
        
        return server;
}
