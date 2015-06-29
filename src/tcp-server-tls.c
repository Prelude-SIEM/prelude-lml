/*****
*
* Copyright (C) 2003-2015 CS-SI. All Rights Reserved.
* Author: Equipe Prelude <contact.prelude@c-s.fr>
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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libprelude/prelude-log.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>

#include "log-entry.h"
#include "lml-options.h"
#include "tcp-server.h"
#include "tcp-server-tls.h"


extern lml_config_t config;
static gnutls_dh_params_t cur_dh_params;
static prelude_bool_t tls_initialized = FALSE;
static prelude_timer_t dh_param_regeneration_timer;
static gnutls_anon_server_credentials_t anoncred;


#define DH_FILENAME LML_RUN_DIR "/tls-parameters.data"



static int dh_check_elapsed(void)
{
        int ret;
        struct stat st;
        struct timeval tv;

        if ( ! config.tls_dh_regenerate )
                return 0;

        ret = stat(DH_FILENAME, &st);
        if ( ret < 0 ) {

                if ( errno == ENOENT )
                        return -1;

                prelude_log(PRELUDE_LOG_ERR, "could not stat %s: %s.\n", DH_FILENAME, strerror(errno));
                return -1;
        }

        gettimeofday(&tv, NULL);

        return ((tv.tv_sec - st.st_mtime) < config.tls_dh_regenerate) ? (tv.tv_sec - st.st_mtime) : -1;
}



static int dh_params_load(gnutls_dh_params_t dh, unsigned int req_bits)
{
        FILE *fd;
        ssize_t size;
        char data[8192];
        gnutls_datum_t dh_data;

        fd = fopen(DH_FILENAME, "r");
        if ( ! fd ) {
                if ( errno != ENOENT )
                        prelude_log(PRELUDE_LOG_ERR, "could not open %s for reading: %s.\n", DH_FILENAME, strerror(errno));

                return -1;
        }

        size = fread(data, 1, sizeof(data), fd);
        fclose(fd);

        if ( size <= 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error reading DH parameters: %s.\n", strerror(errno));
                return -1;
        }

        dh_data.data = (unsigned char *) data;
        dh_data.size = size;

        size = gnutls_dh_params_import_pkcs3(dh, &dh_data, GNUTLS_X509_FMT_PEM);
        if ( size < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error importing DH parameters: %s.\n", gnutls_strerror(errno));
                return -1;
        }

        return 0;
}



static int dh_params_save(gnutls_dh_params_t dh, unsigned int dh_bits)
{
        int ret, fd;
        unsigned char buf[64 * 1024];
        size_t size = sizeof(buf);

        ret = gnutls_dh_params_export_pkcs3(dh, GNUTLS_X509_FMT_PEM, buf, &size);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error exporting Diffie-Hellman parameters: %s.\n", gnutls_strerror(ret));
                return -1;
        }

        fd = open(DH_FILENAME, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR);
        if ( fd < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error opening %s for writing: %s.\n", DH_FILENAME, strerror(errno));
                return -1;
        }

        do {
                ret = write(fd, buf, size);
        } while ( ret < 0 && errno == EINTR );

        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_ERR, "error writing DH data: %s.\n", strerror(errno));

        close(fd);
        return ret;
}



static void dh_params_regenerate(void *data)
{
        int ret;
        gnutls_dh_params_t new, tmp;

        /*
         * generate a new DH key.
         */
        ret = gnutls_dh_params_init(&new);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error initializing dh parameters object: %s.\n", gnutls_strerror(ret));
                return;
        }

        gnutls_dh_params_generate2(new, config.tls_dh_bits);

        tmp = cur_dh_params;
        cur_dh_params = new;

        /*
         * clear the old dh_params.
         */
        gnutls_dh_params_deinit(tmp);

        prelude_log(PRELUDE_LOG_INFO, "Regenerated %d bits Diffie-Hellman key for TLS.\n", config.tls_dh_bits);

        dh_params_save(cur_dh_params, config.tls_dh_bits);
        prelude_timer_set_expire(&dh_param_regeneration_timer, config.tls_dh_regenerate);
        prelude_timer_reset(&dh_param_regeneration_timer);
}


static int get_params(gnutls_session_t session, gnutls_params_type_t type, gnutls_params_st *st)
{
        int ret;
        gnutls_dh_params_t cpy;

        if ( type == GNUTLS_PARAMS_RSA_EXPORT )
                return -1;

        ret = gnutls_dh_params_init(&cpy);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error creating a new dh parameters object: %s.\n", gnutls_strerror(ret));
                return -1;
        }

        ret = gnutls_dh_params_cpy(cpy, cur_dh_params);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "could not copy dh params for sessions: %s.\n", gnutls_strerror(ret));
                gnutls_dh_params_deinit(cpy);
                return -1;
        }

        st->deinit = 1;
        st->type = type;
        st->params.dh = cpy;

        return 0;
}


static int handle_gnutls_error(tcp_client_t *client, gnutls_session_t session, int ret,
                               gnutls_alert_description_t *alert_desc)
{
        int level;
        const char *alert;

        if ( ret == GNUTLS_E_AGAIN ) {
                if ( gnutls_record_get_direction(session) == 1 ) {
                        int fd = client->evio.fd;

                        ev_io_stop(&client->evio);
                        ev_io_set(&client->evio, fd, EV_READ|EV_WRITE);
                }

                return 0;
        }

        else if ( ret == GNUTLS_E_INTERRUPTED )
                return 1;

        else if ( ret == GNUTLS_E_WARNING_ALERT_RECEIVED ) {
                alert = gnutls_alert_get_name(gnutls_alert_get(session));
                lml_log_client(client, PRELUDE_LOG_WARN, "TLS alert from client: %s.\n", alert);
                return 1;
        }

        else if ( ret == GNUTLS_E_FATAL_ALERT_RECEIVED ) {
                alert = gnutls_alert_get_name(gnutls_alert_get(session));
                lml_log_client(client, PRELUDE_LOG_WARN, "TLS fatal alert from client: %s.\n", alert);
        }

        else {
                lml_log_client(client, PRELUDE_LOG_WARN, "TLS error: %s.\n", gnutls_strerror(ret));
                if ( alert_desc && (ret = gnutls_error_to_alert(ret, &level)) > 0 )
                        *alert_desc = (gnutls_alert_description_t) ret;
        }

        return -1;
}



static int bin2sum(char **out, unsigned char *digest, size_t size)
{
        int ret, i;
        prelude_string_t *str;

        ret = prelude_string_new(&str);
        if ( ret < 0 )
                return ret;

        for ( i = 0; i < size; i++ ) {
                if ( prelude_string_get_len(str) > 0 )
                        prelude_string_cat(str, ":");

                ret = prelude_string_sprintf(str, "%.2x", digest[i]);
                if ( ret < 0 ) {
                        prelude_string_destroy(str);
                        return ret;
                }
        }

        ret = prelude_string_get_string_released(str, out);
        prelude_string_destroy(str);

        return ret;
}



static int check_peer_fingerprint(tcp_client_t *client, gnutls_x509_crt_t cert)
{
        int ret;
        size_t size;
        char *fprint;
        prelude_list_t *tmp;
        unsigned char digest[8192];
        tcp_tls_trusted_fingerprint_t *tv;

        prelude_list_for_each(&client->server->trusted_fingerprint, tmp) {
                tv = prelude_linked_object_get_object(tmp);

#ifdef HAVE_GNUTLS_GET_LEN
                if ( gnutls_hash_get_len(tv->algo) > sizeof(digest) ) {
                        prelude_log(PRELUDE_LOG_ERR, "This shouldn't happen, not enough space to store hash.\n");
                        continue;
                }
#endif

                size = sizeof(digest);
                ret = gnutls_x509_crt_get_fingerprint(cert, tv->algo, digest, &size);
                if ( ret < 0 )
                        return ret;

                ret = bin2sum(&fprint, digest, size);
                if ( ret < 0 )
                        return ret;

                ret = strcasecmp(tv->value, fprint);
                free(fprint);

                if ( ret == 0 )
                        return 0;
        }

        return -1;
}



static int check_peer_name(tcp_client_t *client, gnutls_x509_crt_t cert)
{
        int ret;
        prelude_list_t *tmp;
        tcp_tls_trusted_value_t *tv;

        prelude_list_for_each(&client->server->trusted_name, tmp) {
                tv = prelude_linked_object_get_object(tmp);

                /*
                 * gnutls_x509_crt_check_hostname() return a non-zero value on successful match
                 */
                ret = gnutls_x509_crt_check_hostname(cert, tv->value);
                if ( ret != 0 )
                        return 0;
        }

        return -1;
}



static int check_peer_id(tcp_client_t *client, gnutls_session_t session)
{
        int ret;
        unsigned int lsize;
        gnutls_x509_crt_t cert;
        const gnutls_datum_t *cert_list;
        prelude_bool_t no_tfprint, no_tname;

        no_tfprint = prelude_list_is_empty(&client->server->trusted_fingerprint);
        no_tname = prelude_list_is_empty(&client->server->trusted_name);
        if ( no_tfprint && no_tname )
             return 0;

        cert_list = gnutls_certificate_get_peers(session, &lsize);
        if ( lsize < 1 ) {
                lml_log_client(client, PRELUDE_LOG_WARN, "peer didn't provide any certificate.\n");
                return -1;
        }

        /*
         * First certificate is always the direct client.
         */
        ret = gnutls_x509_crt_init(&cert);
        if ( ret < 0 )
                return ret;

        ret = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
        if ( ret < 0 )
                goto err;

        ret = -1;
        if ( ! no_tname )
                ret = check_peer_name(client, cert);

        if ( ! no_tfprint )
                ret = check_peer_fingerprint(client, cert);

err:
        gnutls_x509_crt_deinit(cert);
        return ret;
}



static int verify_certificate(tcp_client_t *client, gnutls_session_t session, gnutls_alert_description_t *alert)
{
        int ret;
        time_t now;
        const char *errstr;
        unsigned int status;
        gnutls_x509_crt_t cert;
        const gnutls_datum_t *cert_list;
        unsigned int i, clist_size = 0;
        prelude_log_t pri = PRELUDE_LOG_WARN;
        gnutls_credentials_type_t ctype;

        if ( client->server->authmode & TCP_SERVER_TLS_AUTH_CLIENT_CERT_OPTIONAL )
                return 0;

        ctype = gnutls_auth_get_type(session);
        if ( ctype == GNUTLS_CRD_ANON )
                return 0;

        if ( ! (client->server->authmode & TCP_SERVER_TLS_AUTH_X509) ) {
                lml_log_client(client, pri, "LML configuration only allow ANON-(EC)DH TLS connection.\n");
                return -1;
        }

        ret = gnutls_certificate_verify_peers2(session, &status);
        if ( ret < 0 ) {
                lml_log_client(client, pri, "error verifying certificate: %s.\n", gnutls_strerror(ret));
                return ret;
        }

        if ( status & GNUTLS_CERT_INVALID ) {
                if ( status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
                        *alert = GNUTLS_A_UNKNOWN_CA;
                        errstr = "client certificate issuer is unknown";
                }

                else if ( status & GNUTLS_CERT_REVOKED ) {
                        *alert = GNUTLS_A_CERTIFICATE_REVOKED;
                        errstr = "client certificate is revoked";
                }

#ifdef GNUTLS_CERT_INSECURE_ALGORITHM
                else if ( status & GNUTLS_CERT_INSECURE_ALGORITHM ) {
                        *alert = GNUTLS_A_INSUFFICIENT_SECURITY;
                        errstr = "client use insecure algorithm";
                }
#endif

                else {
                        *alert = GNUTLS_A_CERTIFICATE_UNKNOWN;
                        errstr = "client certificate is NOT trusted";
                }

                lml_log_client(client, pri, "TLS authentication error: %s.\n", errstr);
                return -1;
        }

        now = time(NULL);

        cert_list = gnutls_certificate_get_peers(client->tls_session, &clist_size);
        for ( i = 0; i < clist_size; i++ ) {
                ret = gnutls_x509_crt_init(&cert);
                if ( ret < 0 ) {
                        lml_log_client(client, PRELUDE_LOG_ERR, "error allocating certificate: %s.\n", gnutls_strerror(ret));
                        return -1;
                }

                ret = gnutls_x509_crt_import(cert, &cert_list[i], GNUTLS_X509_FMT_DER);
                if ( ret < 0 ) {
                        gnutls_x509_crt_deinit(cert);
                        lml_log_client(client, PRELUDE_LOG_ERR, "error importing certificate %d in chain: %s.\n", i, gnutls_strerror(ret));
                        return -1;
                }

                if ( gnutls_x509_crt_get_activation_time(cert) > now ) {
                        *alert = GNUTLS_A_BAD_CERTIFICATE;
                        gnutls_x509_crt_deinit(cert);
                        lml_log_client(client, pri, "TLS authentication error: client certificate %d not yet activated.\n", i);
                        return -1;
                }

                if ( gnutls_x509_crt_get_expiration_time(cert) < now ) {
                        *alert = GNUTLS_A_CERTIFICATE_EXPIRED;
                        gnutls_x509_crt_deinit(cert);
                        lml_log_client(client, pri, "TLS authentication error: client certificate %d expired.\n", i);
                        return -1;
                }

                gnutls_x509_crt_deinit(cert);
        }

        return check_peer_id(client, session);
}



static int set_default_priority(tcp_client_t *client, gnutls_session_t session)
{
        int ret;
        const char *err;

#if defined LIBGNUTLS_VERSION_MAJOR && LIBGNUTLS_VERSION_MAJOR >= 3
# define TLS_DH_STR "+ANON-ECDH:+ANON-DH"
#else
# define TLS_DH_STR "+ANON-DH"
#endif
        const char *pstring = "NORMAL:" TLS_DH_STR;

        gnutls_set_default_priority(session);

        ret = gnutls_priority_set_direct(session, pstring, &err);
        if (ret < 0) {
                fprintf(stderr, "TLS priority syntax error at: %s\n", err);
                return ret;
        }

        if ( client->server->authmode & TCP_SERVER_TLS_AUTH_ANONYMOUS )
                gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred);

        return 0;
}



int tls_auth_client(tcp_client_t *client, int sock, gnutls_alert_description_t *alert, gnutls_certificate_credentials_t server_cred)
{
        int ret;
        gnutls_session_t session;

        /*
         * check if we already have a TLS descriptor
         * associated with this fd (possible because of non blocking mode).
         */
        session = client->tls_session;
        if ( ! session ) {
                union { int fd; void *ptr; } data;

                ret = gnutls_init(&session, GNUTLS_SERVER);
                if ( ret < 0 ) {
                        lml_log_client(client, PRELUDE_LOG_WARN, "error initializing TLS session: %s.\n", gnutls_strerror(ret));
                        return -1;
                }

                set_default_priority(client, session);

                gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, server_cred);
                gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

                data.fd = sock;
                gnutls_transport_set_ptr(session, data.ptr);

                client->tls_session = session;
        }

        do {
                ret = gnutls_handshake(session);
                if ( ret == 0 )
                        ret = 1;

        } while ( ret < 0 && (ret = handle_gnutls_error(client, session, ret, alert)) == 1 );

        if ( ret <= 0 )
                return ret;

        ret = verify_certificate(client, session, alert);
        if ( ret < 0 )
                return -1;

        lml_log_client(client, PRELUDE_LOG_INFO, "TLS authentication succeed.\n");

        return 1;
}



int tls_auth_init(gnutls_certificate_credentials_t *cred, tcp_tls_config_t *tlsconf)
{
        int ret;

        if ( ! tls_initialized )
                tls_auth_global_init();

        ret = gnutls_certificate_allocate_credentials(cred);
        if ( ret < 0 )
                return ret;
        gnutls_certificate_set_dh_params(*cred, cur_dh_params);
        gnutls_certificate_set_params_function(*cred, get_params);

        if ( tlsconf->ca_path != NULL ) {
                ret = gnutls_certificate_set_x509_trust_file(*cred, tlsconf->ca_path, GNUTLS_X509_FMT_PEM);
                if ( ret < 0 )
                        return ret;
        }

        if ( tlsconf->cert_path && tlsconf->key_path ) {
                ret = gnutls_certificate_set_x509_key_file(*cred, tlsconf->cert_path, tlsconf->key_path, GNUTLS_X509_FMT_PEM);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "error initializing x509 key/cert.\n");
                        return ret;
                }
        }

        else if ( ! (tlsconf->authmode & TCP_SERVER_TLS_AUTH_ANONYMOUS) )
                return -1;

        return 0;
}


int tls_auth_global_init(void)
{
        int ret;

        gnutls_global_init();
        gnutls_dh_params_init(&cur_dh_params);

        ret = access(LML_RUN_DIR, R_OK|W_OK);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not open %s for reading/writing.\n", LML_RUN_DIR);
                return prelude_error_from_errno(errno);
        }

        ret = dh_check_elapsed();

        if ( ret != -1 && dh_params_load(cur_dh_params, config.tls_dh_bits) == 0 )
                prelude_timer_set_expire(&dh_param_regeneration_timer, config.tls_dh_regenerate - ret);
        else {
                prelude_log(PRELUDE_LOG_INFO, "Generating %d bits Diffie-Hellman key for TLS...\n", config.tls_dh_bits);

                gnutls_dh_params_generate2(cur_dh_params, config.tls_dh_bits);
                dh_params_save(cur_dh_params, config.tls_dh_bits);

                prelude_timer_set_expire(&dh_param_regeneration_timer, config.tls_dh_regenerate);
        }

        if ( config.tls_dh_regenerate ) {
                prelude_timer_set_callback(&dh_param_regeneration_timer, dh_params_regenerate);
                prelude_timer_init(&dh_param_regeneration_timer);
        }

        gnutls_anon_allocate_server_credentials(&anoncred);
        gnutls_anon_set_server_dh_params(anoncred, cur_dh_params);

        tls_initialized = TRUE;

        return 0;
}
