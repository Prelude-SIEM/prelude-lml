/*****
*
* Copyright (C) 1998 - 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
* All Rights Reserved
*
* This file is part of the Prelude program.
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <time.h>
#include <netdb.h>
#include <assert.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-inet.h>
#include <libprelude/idmef-message-print.h>

#include "libmissing.h"
#include "log-common.h"
#include "lml-alert.h"
#include "lml-options.h"
#include "config.h"


extern lml_config_t config;
static idmef_analyzer_t *idmef_analyzer;


#define ANALYZER_CLASS "HIDS"
#define ANALYZER_MODEL "Prelude LML"
#define ANALYZER_MANUFACTURER "The Prelude Team http://www.prelude-ids.org"



static int resolve_failed_fallback(const log_entry_t *log_entry, idmef_node_t *node)
{
        int ret;
        idmef_address_t *address;
        prelude_string_t *string;
        
        /*
         * we want to know if it's an ip address or an hostname.
         */
        ret = inet_addr(log_entry->target_hostname);
        if ( ret < 0 ) {
                /*
                 * hostname.
                 */
                string = idmef_node_new_name(node);
                prelude_string_set_ref(string, log_entry->target_hostname);
        } else {
                address = idmef_node_new_address(node);
                if ( ! address ) 
                        return -1;

                string = idmef_address_new_address(address);
                prelude_string_set_ref(string, log_entry->target_hostname);
        }

        return 0;
}




static int fill_target(idmef_node_t *node, struct addrinfo *ai) 
{
        char str[128];
        void *in_addr;
        idmef_address_t *addr;
        prelude_string_t *string;

        while ( ai ) {
                if ( ai->ai_flags & AI_CANONNAME ) {
                        string = idmef_node_new_name(node);
                        if ( prelude_string_set_dup(string, ai->ai_canonname) < 0 )
                                return -1;
                }
                
                addr = idmef_node_new_address(node);
                if ( ! addr )
                        return -1;

                in_addr = prelude_inet_sockaddr_get_inaddr(ai->ai_addr);
                assert(in_addr);

                idmef_address_set_category(addr, (ai->ai_family == AF_INET) ?
                                           IDMEF_ADDRESS_CATEGORY_IPV4_ADDR :
                                           IDMEF_ADDRESS_CATEGORY_IPV6_ADDR);
                
                if ( ! prelude_inet_ntop(ai->ai_family, in_addr, str, sizeof(str)) ) {
                        log(LOG_ERR, "inet_ntop returned an error.\n");
                        return -1;
                }

                string = idmef_address_new_address(addr);
                if ( prelude_string_set_dup(string, str) < 0 )
                        return -1;

                ai = ai->ai_next;
        }

        return 0;
}


static int fill_analyzer(const log_entry_t *log_entry, idmef_analyzer_t *analyzer)
{
        int ret;
        idmef_node_t *node;
        idmef_process_t *process;
        prelude_string_t *process_name;

        if ( log_entry->target_process && ! idmef_analyzer_get_process(analyzer) ) {
                process = idmef_analyzer_new_process(analyzer);
                if ( ! process )
                        return -1;

                process_name = idmef_process_new_name(process);
                prelude_string_set_ref(process_name, log_entry->target_process);

                if ( log_entry->target_process_pid )
                        idmef_process_set_pid(process, atoi(log_entry->target_process_pid));
        }

        if ( log_entry->target_hostname && ! idmef_analyzer_get_node(analyzer) ) {
                struct addrinfo *ai, hints;
                
                node = idmef_analyzer_new_node(analyzer);
                if ( ! node ) 
                        return -1;

                memset(&hints, 0, sizeof(hints));
                hints.ai_flags = AI_CANONNAME;
                hints.ai_socktype = SOCK_STREAM;

                ret = getaddrinfo(log_entry->target_hostname, NULL, &hints, &ai);
                if ( ret != 0 ) {
                        log(LOG_ERR, "error resolving \"%s\": %s.\n", log_entry->target_hostname, gai_strerror(ret));
                        return resolve_failed_fallback(log_entry, node);
                }

                fill_target(node, ai);
                freeaddrinfo(ai);
        }

        return 0;
}


static int generate_target(const log_entry_t *log_entry, idmef_alert_t *alert) 
{
        int ret;
        idmef_node_t *node;
        idmef_target_t *target;
        idmef_process_t *process;
        prelude_string_t *process_name;

        target = idmef_alert_get_next_target(alert, NULL);
        if ( ! target ) {
                target = idmef_alert_new_target(alert);
                if ( ! target ) 
                        return -1;
        }

        if ( log_entry->target_process && ! idmef_target_get_process(target) ) {
                process = idmef_target_new_process(target);
                if ( ! process )
                        return -1;

                process_name = idmef_process_new_name(process);
                prelude_string_set_ref(process_name, log_entry->target_process);

                if ( log_entry->target_process_pid )
                        idmef_process_set_pid(process, atoi(log_entry->target_process_pid));
        }
        
        if ( log_entry->target_hostname && ! idmef_target_get_node(target) ) {
                struct addrinfo *ai, hints;
                
                node = idmef_target_new_node(target);
                if ( ! node ) 
                        return -1;

                memset(&hints, 0, sizeof(hints));
                hints.ai_flags = AI_CANONNAME;
                hints.ai_socktype = SOCK_STREAM;

                ret = getaddrinfo(log_entry->target_hostname, NULL, &hints, &ai);
                if ( ret != 0 ) {
                        log(LOG_ERR, "error resolving \"%s\": %s.\n", log_entry->target_hostname, gai_strerror(ret));
                        return resolve_failed_fallback(log_entry, node);
                }

                fill_target(node, ai);
                freeaddrinfo(ai);
        }

        return 0;
}



static int generate_additional_data(idmef_alert_t *alert, const char *meaning, const char *data)
{
        idmef_additional_data_t *adata;
        prelude_string_t *adata_meaning;

        adata = idmef_alert_new_additional_data(alert);
        if ( ! adata )
                return -1;

        adata_meaning = idmef_additional_data_new_meaning(adata);
        prelude_string_set_ref(adata_meaning, meaning);

        return idmef_additional_data_set_string_ref(adata, data);
}



static void insert_analyzer(idmef_alert_t *alert, idmef_analyzer_t *cur_analyzer)
{
        if ( config.dry_run )
                return;
        
        if ( cur_analyzer ) 
                idmef_analyzer_set_analyzer(cur_analyzer, idmef_analyzer_ref(idmef_analyzer));
        else
                cur_analyzer = idmef_analyzer;

        idmef_alert_set_analyzer(alert, idmef_analyzer_ref(cur_analyzer));
}



void lml_emit_alert(const log_entry_t *log_entry, idmef_message_t *message, uint8_t priority)
{
        const char *source;
        idmef_alert_t *alert;
        idmef_time_t *create_time;
        idmef_time_t *detect_time;
        idmef_analyzer_t *cur_analyzer;
        
        alert = idmef_message_get_alert(message);

        create_time = idmef_time_new_from_gettimeofday();
        if ( ! create_time )
                goto error;

        idmef_alert_set_create_time(alert, create_time);
        
        detect_time = idmef_alert_new_detect_time(alert);
        if ( ! detect_time )
                goto error;

        idmef_time_set_from_time(detect_time, (const time_t *) &log_entry->tv.tv_sec);
        idmef_time_set_usec(detect_time, log_entry->tv.tv_usec);

        cur_analyzer = idmef_alert_get_analyzer(alert);
        
        if ( log_entry->target_hostname || log_entry->target_process ) {
                if ( generate_target(log_entry, alert) < 0 )
                        goto error;

                if ( cur_analyzer && fill_analyzer(log_entry, cur_analyzer) < 0 )
                        goto error;
        }

        insert_analyzer(alert, cur_analyzer);

        source = log_source_get_name(log_entry->source);
        if ( generate_additional_data(alert, "Log received from", source) < 0 )
                goto error;
        
        if ( log_entry->original_log ) {
                if ( generate_additional_data(alert, "Original Log", log_entry->original_log) < 0 )
                        goto error;
        }
        
        if ( config.text_output_fd )
                idmef_message_print(message, config.text_output_fd);
        
        if ( ! config.dry_run ) 
                prelude_client_send_idmef(config.lml_client, message);
                
 error:
        idmef_message_destroy(message);
}




int lml_alert_init(prelude_client_t *lml_client) 
{
        prelude_string_t *string;
        
        idmef_analyzer = prelude_client_get_analyzer(lml_client);
        if ( ! idmef_analyzer )
                return -1;
        
        string = idmef_analyzer_new_model(idmef_analyzer);
        prelude_string_set_constant(string, ANALYZER_MODEL);

        string = idmef_analyzer_new_class(idmef_analyzer);
        prelude_string_set_constant(string, ANALYZER_CLASS);

        string = idmef_analyzer_new_manufacturer(idmef_analyzer);
        prelude_string_set_constant(string, ANALYZER_MANUFACTURER);

        string = idmef_analyzer_new_version(idmef_analyzer);
        prelude_string_set_constant(string, VERSION);

        return 0;
}
