/*****
*
* Copyright (C) 2003-2017 CS-SI. All Rights Reserved.
* Author: Prelude Team <support.prelude@c-s.fr>
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

#include "config.h"
#include "ev.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <netinet/tcp.h>

#include <libprelude/common.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-list.h>

#include "prelude-lml.h"
#include "common.h"
#include "regex.h"
#include "log-source.h"
#include "tcp-server.h"

#ifdef HAVE_GNUTLS
# include "tcp-server-tls.h"
#endif

#include "lml-options.h"

#include <ctype.h>

#include <sys/types.h>


#ifndef SOMAXCONN
# define SOMAXCONN 128
#endif


#ifdef HAVE_IPV6
# define SOCKADDR_PORT_MEMBER(x) x.sin6_port
# define SERVER_SOCKADDR_TYPE struct sockaddr_in6
#else
# define SOCKADDR_PORT_MEMBER(x) x.sin_port
# define SERVER_SOCKADDR_TYPE struct sockaddr_in
#endif


typedef enum {
        TCP_SYSLOG_STATE_START_FRAME             = 0x00,
        TCP_SYSLOG_STATE_OCTET_COUNTING          = 0x01,
        TCP_SYSLOG_STATE_NON_TRANSPARENT_FRAMING = 0x02,
        TCP_SYSLOG_STATE_MSG                     = 0x04
} tcp_syslog_state_t;


extern lml_config_t config;


void lml_log_client(tcp_client_t *client, prelude_log_t priority, const char *fmt, ...)
{
        int ret;
        va_list ap;
        prelude_string_t *out;

        ret = prelude_string_new(&out);
        if ( ret < 0 )
                return;

        va_start(ap, fmt);
        ret = prelude_string_vprintf(out, fmt, ap);
        va_end(ap);

        if ( ret < 0 ) {
                prelude_string_destroy(out);
                return;
        }

        prelude_log(priority, "[%s]: %s", client->addr, prelude_string_get_string(out));
        prelude_string_destroy(out);
}



static void destroy_client(tcp_client_t *client)
{
        lml_log_client(client, PRELUDE_LOG_INFO, "connection closed.\n");
        ev_io_stop(&client->evio);


#ifdef HAVE_GNUTLS
        if ( client->tls_session )
                gnutls_deinit(client->tls_session);
#endif

        close(client->evio.fd);

        prelude_string_destroy(client->data);
        free(client->addr);

        free(client);
}



static void process_log(tcp_client_t *client, prelude_string_t *log)
{
        lml_log_source_set_name(client->server->ls, client->addr);
        lml_dispatch_log(client->server->ls, prelude_string_get_string(log), prelude_string_get_len(log));
        prelude_string_clear(log);
}



static ssize_t raw_read(tcp_client_t *client, void *buf, size_t size)
{
        ssize_t ret;

        ret = read(client->evio.fd, buf, size);
        if ( ret < 0 )
                lml_log_client(client, PRELUDE_LOG_WARN, "error reading syslog-tcp message: %s.\n", strerror(errno));

        return ret;
}


#ifdef HAVE_GNUTLS
static ssize_t tls_read(tcp_client_t *client, void *buf, size_t size)
{
        ssize_t ret;

        ret = gnutls_record_recv(client->tls_session, buf, size);
        if ( ret < 0 )
                lml_log_client(client, PRELUDE_LOG_WARN, "error reading syslog-tcp/ssl message: %s.\n", gnutls_strerror(errno));

        return ret;
}



static void libev_tls_auth_cb(struct ev_io *io, int revents)
{
        int ret;
        tcp_client_t *client = io->data;
        gnutls_alert_description_t alert;

        ret = tls_auth_client(client, io->fd, &alert, client->server->cred);
        if ( ret < 0 )
                return destroy_client(client);

        if ( ret == 0 )
                return;

        ev_io_stop(io);
        ev_io_init(io, libev_tcp_process_cb, io->fd, EV_READ);
        ev_io_start(io);
}

#endif


void libev_tcp_process_cb(struct ev_io *io, int revents)
{
        ssize_t ret;
        tcp_client_t *client = io->data;
        char *ptr, *end;

        ret = client->server->read_func(client, config.log_buffer, config.log_max_length);
        if ( ret <= 0 ) {
                destroy_client(client);
                return;
        }

        /*
         * As defined per RFC 6587
         */
        for ( ptr = config.log_buffer, end = config.log_buffer + ret; ptr < end; ptr++ ) {
                if ( client->state == TCP_SYSLOG_STATE_START_FRAME ) {
                        if ( *ptr > '0' && *ptr <= '9' ) {
                                client->remaining = 0;
                                client->state = TCP_SYSLOG_STATE_OCTET_COUNTING;
                        }

                        else client->state = TCP_SYSLOG_STATE_NON_TRANSPARENT_FRAMING;
                }

                if ( client->state == TCP_SYSLOG_STATE_OCTET_COUNTING ) {
                        if ( isdigit(*ptr) )
                                client->remaining = client->remaining * 10 + (*ptr - '0');

                        else if ( *ptr != ' ' ) {
                                lml_log_client(client, PRELUDE_LOG_WARN, "Framing error in TCP message : delimiter is not SPACE (value %d).\n", *ptr);
                                return;
                        }

                        else {
                                if ( client->remaining <= 0 ) {
                                        lml_log_client(client, PRELUDE_LOG_WARN, "Framing error in TCP message : invalid octet-count : %d.\n", client->remaining);
                                        return;
                                }

                                client->state |= TCP_SYSLOG_STATE_MSG;
                        }
                }

                else if ( client->state == TCP_SYSLOG_STATE_NON_TRANSPARENT_FRAMING ) {
                        if ( *ptr == '\n' || *ptr == '\0' ) {
                                process_log(client, client->data);
                                client->state = TCP_SYSLOG_STATE_START_FRAME;
                        }

                        else prelude_string_ncat(client->data, ptr, 1);
                }

                else if ( client->state & TCP_SYSLOG_STATE_MSG && client->state & TCP_SYSLOG_STATE_OCTET_COUNTING ) {
                        prelude_string_ncat(client->data, ptr, 1);

                        if ( --client->remaining == 0 ) {
                                process_log(client, client->data);
                                client->state = TCP_SYSLOG_STATE_START_FRAME;
                        }
                }

                if ( prelude_string_get_len(client->data) == config.log_max_length ) {
                        lml_log_client(client, PRELUDE_LOG_WARN, "splitting log line bigger than %u bytes.\n", config.log_max_length);
                        process_log(client, client->data);
                }
        }
}


void tcp_server_accept(tcp_server_t *server)
{
        void *in_addr;
        char src[512];
        socklen_t addrlen;
        tcp_client_t *client;
        int ret, sock, on = 1;
        SERVER_SOCKADDR_TYPE sa;

        addrlen = sizeof(sa);

        sock = accept(server->sockfd, (struct sockaddr *) &sa, &addrlen);
        if ( sock < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "accept error: %s.\n", strerror(errno));
                return;
        }

        ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(int));
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_ERR, "could not set SO_KEEPALIVE socket option: %s.\n", strerror(errno));


        in_addr = prelude_sockaddr_get_inaddr((struct sockaddr *) &sa);
        prelude_return_if_fail(in_addr);

        if ( ! inet_ntop(((struct sockaddr *) &sa)->sa_family, in_addr, src, sizeof(src)) ) {
                prelude_log(PRELUDE_LOG_ERR, "error retrieving client address: %s.\n", strerror(errno));
                close(sock);
                return;
        }

        snprintf(src + strlen(src), sizeof(src) - strlen(src), ":%d", SOCKADDR_PORT_MEMBER(sa));

        client = malloc(sizeof(*client));
        if ( ! client ) {
                prelude_log(PRELUDE_LOG_ERR, "error allocating memory: %s.\n", strerror(errno));
                return;
        }

        client->state = 0;
        client->addr = strdup(src);
        client->server = server;
        prelude_string_new(&client->data);

#ifdef HAVE_GNUTLS
        client->tls_session = NULL;
        ev_io_init(&client->evio, (server->authmode) ? libev_tls_auth_cb : libev_tcp_process_cb, sock, EV_READ);
#else
        ev_io_init(&client->evio, libev_tcp_process_cb, sock, EV_READ);
#endif
        client->evio.data = client;

        ev_io_start(&client->evio);
}



void tcp_server_close(tcp_server_t *server)
{
        lml_log_source_destroy(server->ls);

        close(server->sockfd);

        free(server->addr);
        free(server);
}



int tcp_server_get_event_fd(tcp_server_t *server)
{
        if ( ! server )
                return -1;

        return server->sockfd;
}



tcp_server_t *tcp_server_new(lml_log_source_t *ls,  const char *addr, unsigned int port, tcp_tls_config_t *tls_config)
{
        tcp_server_t *server;
        int ret, sock, on = 1;
        char buf[sizeof("65535")];
        struct addrinfo hints, *ai;

        memset(&hints, 0, sizeof(hints));
        snprintf(buf, sizeof(buf), "%u", port);

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        ret = getaddrinfo(addr, buf, &hints, &ai);
        if ( ret != 0 ) {
                fprintf(stderr, "could not resolve %s: %s.\n", addr,
                        (ret == EAI_SYSTEM) ? strerror(errno) : gai_strerror(ret));
                return NULL;
        }

        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if ( sock < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't create tcp-server socket.\n");
                freeaddrinfo(ai);
                return NULL;
        }

        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
        if ( ret < 0 ) {
                ret = prelude_error_verbose(PRELUDE_ERROR_GENERIC, "error setting SO_REUSEADDR: %s", strerror(errno));
                freeaddrinfo(ai);
                close(sock);
                return NULL;
        }

        ret = bind(sock, ai->ai_addr, ai->ai_addrlen);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't bind to socket: %s.\n", strerror(errno));
                freeaddrinfo(ai);
                close(sock);
                return NULL;
        }

        freeaddrinfo(ai);

        ret = listen(sock, SOMAXCONN);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "listen error: %s.\n", strerror(errno));
                close(sock);
                return NULL;
        }

        server = malloc(sizeof(*server));
        if ( ! server ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                close(sock);
                return NULL;
        }

        server->addr = strdup(addr);
        server->port = port;
        server->sockfd = sock;
        server->ls = ls;
        server->read_func = raw_read;
        server->authmode = 0;

#ifdef HAVE_GNUTLS
        if ( tls_config ) {
                server->authmode = tls_config->authmode;
                server->read_func = tls_read;

                prelude_list_init(&server->trusted_name);
                prelude_list_splice(&server->trusted_name, &tls_config->trusted_name);

                prelude_list_init(&server->trusted_fingerprint);
                prelude_list_splice(&server->trusted_fingerprint, &tls_config->trusted_fingerprint);

                ret = tls_auth_init(&server->cred, tls_config);
                if ( ret < 0 ) {
                        close(sock);
                        free(server->addr);
                        free(server);
                        return NULL;
                }
        }
#endif

        return server;
}

