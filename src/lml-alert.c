/*****
*
* Copyright (C) 2002 - 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#include "config.h"

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
#include "log-entry.h"
#include "lml-alert.h"
#include "lml-options.h"
#include "config.h"


extern lml_config_t config;
static idmef_analyzer_t *idmef_analyzer;


#define ANALYZER_CLASS "HIDS"
#define ANALYZER_MODEL "Prelude LML"
#define ANALYZER_MANUFACTURER "The Prelude Team http://www.prelude-ids.org"



static int resolve_failed_fallback(const lml_log_entry_t *log_entry, idmef_node_t *node)
{
        int ret;
        const char *hostname;
        idmef_address_t *address;
        prelude_string_t *string;

        hostname = lml_log_entry_get_target_hostname(log_entry);
        
        /*
         * we want to know if it's an ip address or an hostname.
         */
        ret = inet_addr(hostname);
        if ( ret < 0 ) {
                /*
                 * hostname.
                 */
                ret = idmef_node_new_name(node, &string);
                if ( ret < 0 )
                        return -1;
                
                prelude_string_set_ref(string, hostname);
        } else {
                ret = idmef_node_new_address(node, &address, -1);
                if ( ret < 0 ) 
                        return -1;

                ret = idmef_address_new_address(address, &string);
                if ( ret < 0 )
                        return -1;
                
                prelude_string_set_ref(string, hostname);
        }

        return 0;
}




static int fill_target(idmef_node_t *node, struct addrinfo *ai) 
{
        int ret;
        char str[128];
        void *in_addr;
        idmef_address_t *addr;
        prelude_string_t *string;

        while ( ai ) {
                if ( ai->ai_flags & AI_CANONNAME ) {
                        ret = idmef_node_new_name(node, &string);
                        if ( ret < 0 )
                                return -1;
                        
                        if ( prelude_string_set_dup(string, ai->ai_canonname) < 0 )
                                return -1;
                }
                
                ret = idmef_node_new_address(node, &addr, -1);
                if ( ret < 0 )
                        return -1;

                in_addr = prelude_inet_sockaddr_get_inaddr(ai->ai_addr);
                assert(in_addr);

                idmef_address_set_category(addr, (ai->ai_family == AF_INET) ?
                                           IDMEF_ADDRESS_CATEGORY_IPV4_ADDR :
                                           IDMEF_ADDRESS_CATEGORY_IPV6_ADDR);
                
                if ( ! prelude_inet_ntop(ai->ai_family, in_addr, str, sizeof(str)) ) {
                        prelude_log(PRELUDE_LOG_ERR, "inet_ntop returned an error.\n");
                        return -1;
                }

                ret = idmef_address_new_address(addr, &string);
                if ( ret < 0 )
                        return -1;
                
                if ( prelude_string_set_dup(string, str) < 0 )
                        return -1;

                ai = ai->ai_next;
        }

        return 0;
}


static int fill_analyzer(const lml_log_entry_t *log_entry, idmef_analyzer_t *analyzer)
{
        int ret;
        const char *tmp;
        idmef_node_t *node;
        prelude_string_t *str;
        idmef_process_t *process;

        tmp = lml_log_entry_get_target_process(log_entry);

        if ( tmp && ! idmef_analyzer_get_process(analyzer) ) {
                ret = idmef_analyzer_new_process(analyzer, &process);
                if ( ret < 0 )
                        return -1;

                ret = idmef_process_new_name(process, &str);
                if ( ret < 0 )
                        return -1;
                
                prelude_string_set_ref(str, tmp);

                tmp = lml_log_entry_get_target_process_pid(log_entry);
                if ( tmp )
                        idmef_process_set_pid(process, atoi(tmp));
        }

        tmp = lml_log_entry_get_target_hostname(log_entry);
        if ( tmp && ! idmef_analyzer_get_node(analyzer) ) {
                struct addrinfo *ai, hints;
                
                ret = idmef_analyzer_new_node(analyzer, &node);
                if ( ret < 0 ) 
                        return -1;

                memset(&hints, 0, sizeof(hints));
                hints.ai_flags = AI_CANONNAME;
                hints.ai_socktype = SOCK_STREAM;

                ret = getaddrinfo(tmp, NULL, &hints, &ai);
                if ( ret != 0 ) {
                        prelude_log(PRELUDE_LOG_WARN, "error resolving \"%s\": %s.\n", tmp, gai_strerror(ret));
                        return resolve_failed_fallback(log_entry, node);
                }

                fill_target(node, ai);
                freeaddrinfo(ai);
        }

        return 0;
}


static int generate_target(const lml_log_entry_t *log_entry, idmef_alert_t *alert) 
{
        int ret;
        const char *tmp;
        idmef_node_t *node;
        prelude_string_t *str;
        idmef_target_t *target;
        idmef_process_t *process;

        target = idmef_alert_get_next_target(alert, NULL);
        if ( ! target ) {
                ret = idmef_alert_new_target(alert, &target, -1);
                if ( ret < 0 ) 
                        return ret;
        }

        tmp = lml_log_entry_get_target_process(log_entry);
        if ( tmp && ! idmef_target_get_process(target) ) {
                ret = idmef_target_new_process(target, &process);
                if ( ret < 0 )
                        return ret;

                ret = idmef_process_new_name(process, &str);
                if ( ret < 0 )
                        return ret;
                
                prelude_string_set_ref(str, tmp);

                tmp = lml_log_entry_get_target_process_pid(log_entry);
                if ( tmp )
                        idmef_process_set_pid(process, atoi(tmp));
        }

        tmp = lml_log_entry_get_target_hostname(log_entry);
        if ( tmp && ! idmef_target_get_node(target) ) {
                struct addrinfo *ai, hints;
                
                ret = idmef_target_new_node(target, &node);
                if ( ret < 0 ) 
                        return ret;

                memset(&hints, 0, sizeof(hints));
                hints.ai_flags = AI_CANONNAME;
                hints.ai_socktype = SOCK_STREAM;

                ret = getaddrinfo(tmp, NULL, &hints, &ai);
                if ( ret != 0 ) {
                        prelude_log(PRELUDE_LOG_WARN, "error resolving \"%s\": %s.\n", tmp, gai_strerror(ret));
                        return resolve_failed_fallback(log_entry, node);
                }

                fill_target(node, ai);
                freeaddrinfo(ai);
        }

        return 0;
}



static int generate_additional_data(idmef_alert_t *alert, const char *meaning, const char *data)
{
        int ret;
        prelude_string_t *str;
        idmef_additional_data_t *adata;

        ret = idmef_alert_new_additional_data(alert, &adata, -1);
        if ( ret < 0 )
                return ret;

        ret = idmef_additional_data_new_meaning(adata, &str);
        if ( ret < 0 )
                return ret;
        
        prelude_string_set_ref(str, meaning);

        return idmef_additional_data_set_string_ref(adata, data);
}



void lml_alert_emit(const lml_log_source_t *ls, const lml_log_entry_t *log, idmef_message_t *message)
{
        int ret;
        const char *source, *ptr;
        idmef_time_t *time;
        idmef_alert_t *alert;
        idmef_analyzer_t *cur_analyzer;
        
        alert = idmef_message_get_alert(message);
        if ( ! alert )
                goto error;
        
        ret = idmef_time_new_from_gettimeofday(&time);
        if ( ret < 0 )
                goto error;
        idmef_alert_set_create_time(alert, time);
        
        ret = idmef_alert_new_detect_time(alert, &time);
        if ( ret < 0 )
                goto error;

        idmef_time_set_from_timeval(time, lml_log_entry_get_timeval(log));
        
        cur_analyzer = idmef_alert_get_next_analyzer(alert, NULL);
        
        if ( lml_log_entry_get_target_hostname(log) || lml_log_entry_get_target_process(log) ) {
                if ( generate_target(log, alert) < 0 )
                        goto error;

                if ( cur_analyzer && fill_analyzer(log, cur_analyzer) < 0 )
                        goto error;
        }

        if ( idmef_analyzer )
                idmef_alert_set_analyzer(alert, idmef_analyzer_ref(idmef_analyzer), 0);
        
        source = lml_log_source_get_name(ls);
        if ( generate_additional_data(alert, "Log received from", source) < 0 )
                goto error;

        ptr = lml_log_entry_get_original_log(log);
        if ( ptr ) {
                if ( generate_additional_data(alert, "Original Log", ptr) < 0 )
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
        int ret;
        prelude_string_t *string;

        printf("INIT\n");
        
        idmef_analyzer = prelude_client_get_analyzer(lml_client);
        if ( ! idmef_analyzer )
                return -1;
        
        ret = idmef_analyzer_new_model(idmef_analyzer, &string);
        if ( ret < 0 )
                return -1;
        prelude_string_set_constant(string, ANALYZER_MODEL);

        ret = idmef_analyzer_new_class(idmef_analyzer, &string);
        if ( ret < 0 )
                return -1;
        prelude_string_set_constant(string, ANALYZER_CLASS);

        ret = idmef_analyzer_new_manufacturer(idmef_analyzer, &string);
        if ( ret < 0 )
                return -1;
        prelude_string_set_constant(string, ANALYZER_MANUFACTURER);

        ret = idmef_analyzer_new_version(idmef_analyzer, &string);
        if ( ret < 0 )
                return -1;
        prelude_string_set_constant(string, VERSION);

        return 0;
}
