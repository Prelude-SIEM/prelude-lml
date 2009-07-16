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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <libprelude/common.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-list.h>

#include "prelude-lml.h"
#include "common.h"
#include "regex.h"
#include "log-source.h"
#include "udp-server.h"
#include "lml-options.h"

#ifndef MIN
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif


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
        char *addr;
        unsigned int port;
};



extern lml_config_t config;



static char *my_strnchr(char *input, char wanted, size_t size)
{
        while ( *input && size-- ) {
                if ( *input == 0 )
                        break;

                if ( *input == wanted )
                        return input;

                input++;
        }

        return NULL;
}



void udp_server_process_event(udp_server_t *server)
{
        ssize_t ret;
        socklen_t len;
        void *in_addr;
        union {
                struct sockaddr sa;
                struct sockaddr_in sa4;
#ifdef HAVE_IPV6
                struct sockaddr_in6 sa6;
# define SOCKADDR_PORT_MEMBER(x) (x.sa6.sin6_port)
#else
# define SOCKADDR_PORT_MEMBER(x) (x.sa4.sin_port)
#endif
        } addr;
        char buf[SYSLOG_MSG_MAX_SIZE], *ptr = NULL, src[512];

        len = sizeof(addr);

        ret = recvfrom(server->sockfd, buf, sizeof(buf) - 1, 0, &addr.sa, &len);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error receiving syslog message.\n");
                return;
        }

        if ( ret == 0 )
                return;

        buf[ret] = '\0';

        in_addr = prelude_sockaddr_get_inaddr(&addr.sa);
        prelude_return_if_fail(in_addr);
        prelude_return_if_fail(inet_ntop(addr.sa.sa_family, in_addr, src, sizeof(src)));

        snprintf(src + strlen(src), sizeof(src) - strlen(src), ":%d", SOCKADDR_PORT_MEMBER(addr));
        lml_log_source_set_name(server->ls, src);

        /*
         * We don't care about syslog priority / facility. From RFC 3164:
         *
         * - If the first character is not a less-than sign: no valid PRI.
         * - If the 3rd, 4th, or 5th character is not a right angle bracket character: no valid PRI.
         */
        if ( buf[0] == '<' && ret > 2 ) {
                ptr = my_strnchr(buf + 2, '>', MIN(ret - 2, 3));
                if ( ptr ) {
                        ptr++;
                        ret -= (ptr - buf);
                }
        }

        lml_dispatch_log(server->ls, ptr ? ptr : buf, ret);
}



void udp_server_close(udp_server_t *server)
{
        lml_log_source_destroy(server->ls);

        close(server->sockfd);

        free(server->addr);
        free(server);
}


const char *udp_server_get_addr(udp_server_t *server)
{
        return server->addr;
}


unsigned int udp_server_get_port(udp_server_t *server)
{
        return server->port;
}


int udp_server_get_event_fd(udp_server_t *server)
{
        if ( ! server )
                return -1;

        return server->sockfd;
}



udp_server_t *udp_server_new(lml_log_source_t *ls,  const char *addr, unsigned int port)
{
        int ret, sockfd;
        udp_server_t *server;
        char buf[sizeof("65535")];
        struct addrinfo hints, *ai;

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

        sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if ( sockfd < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't create socket.\n");
                freeaddrinfo(ai);
                return NULL;
        }

        ret = bind(sockfd, ai->ai_addr, ai->ai_addrlen);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't bind to socket: %s.\n", strerror(errno));
                freeaddrinfo(ai);
                close(sockfd);
                return NULL;
        }

        freeaddrinfo(ai);

        server = malloc(sizeof(*server));
        if ( ! server ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                close(sockfd);
                return NULL;
        }

        server->addr = strdup(addr);
        server->port = port;
        server->sockfd = sockfd;
        server->ls = ls;

        return server;
}
