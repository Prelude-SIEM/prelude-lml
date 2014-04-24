
#ifndef TCP_SERVER_TLS_H
#define TCP_SERVER_TLS_H

#include <gnutls/gnutls.h>

#include "prelude-lml.h"
#include "ev.h"

int tls_auth_global_init(void);

int tls_auth_init(gnutls_certificate_credentials_t *cred, tcp_tls_config_t *tlsconf);

int tls_auth_client(tcp_client_t *client, int sock, gnutls_alert_description_t *alert, gnutls_certificate_credentials_t server_cred);

#endif  /* TCP_SERVER_TLS_H */
