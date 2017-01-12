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


#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
#endif

#include "prelude-lml.h"
#include "ev.h"


typedef enum {
        TCP_SERVER_TLS_AUTH_ANONYMOUS = 0x01,
        TCP_SERVER_TLS_AUTH_X509      = 0x02,
        TCP_SERVER_TLS_AUTH_CLIENT_CERT_OPTIONAL = 0x04,
} tcp_tls_server_authmode_t;


typedef struct {
        char *ca_path;
        char *cert_path;
        char *key_path;
        tcp_tls_server_authmode_t authmode;
        prelude_list_t trusted_name;
        prelude_list_t trusted_fingerprint;
} tcp_tls_config_t;


typedef struct tcp_client tcp_client_t;

typedef struct {
        int sockfd;
        lml_log_source_t *ls;
        char *addr;
        unsigned int port;

        ssize_t (*read_func)(tcp_client_t *client, void *buf, size_t size);
        tcp_tls_server_authmode_t authmode;

#ifdef HAVE_GNUTLS
        gnutls_certificate_credentials_t cred;
        prelude_list_t trusted_name;
        prelude_list_t trusted_fingerprint;
#endif
} tcp_server_t;


#ifdef HAVE_GNUTLS
typedef struct {
        PRELUDE_LINKED_OBJECT;
        char *value;
} tcp_tls_trusted_value_t;


typedef struct {
        PRELUDE_LINKED_OBJECT;
        gnutls_digest_algorithm_t algo;
        char *value;
} tcp_tls_trusted_fingerprint_t;
#endif

struct tcp_client {
        ev_io evio;
        char *addr;
        tcp_server_t *server;

        int state;
        size_t remaining;
        prelude_string_t *data;

#ifdef HAVE_GNUTLS
        gnutls_session_t tls_session;
#endif
};



void libev_tcp_process_cb(struct ev_io *w, int revents);

void tcp_server_accept(tcp_server_t *server);

tcp_server_t *tcp_server_new(lml_log_source_t *ls, const char *addr, unsigned int port, tcp_tls_config_t *tls_config);

void tcp_server_close(tcp_server_t *server);

int tcp_server_get_event_fd(tcp_server_t *srvr);

void lml_log_client(tcp_client_t *client, prelude_log_t priority, const char *fmt, ...);

#endif  /* TCP_SERVER_H */
