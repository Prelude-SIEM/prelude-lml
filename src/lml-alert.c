/*****
*
* Copyright (C) 1998 - 2003 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <time.h>
#include <netdb.h>
#include <assert.h>

#include <libprelude/list.h>
#include <libprelude/common.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-msg-send.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/sensor.h>
#include <libprelude/prelude-inet.h>

#include "log-common.h"
#include "lml-alert.h"
#include "config.h"


static size_t target_buf_index;
static prelude_msgbuf_t *msgbuf;


#define ANALYZER_CLASS "HIDS"
#define ANALYZER_MODEL "Prelude LML"
#define ANALYZER_MANUFACTURER "The Prelude Team http://www.prelude-ids.org"



static void generate_analyzer(idmef_analyzer_t *analyzer) 
{
        prelude_analyzer_fill_infos(analyzer);
        idmef_string_set_constant(&analyzer->model, ANALYZER_MODEL);
        idmef_string_set_constant(&analyzer->class, ANALYZER_CLASS);
        idmef_string_set_constant(&analyzer->manufacturer, ANALYZER_MANUFACTURER);
        idmef_string_set_constant(&analyzer->version, VERSION);
}



static void send_heartbeat_cb(void *data) 
{
        struct timeval tv;
        idmef_heartbeat_t *hb;
        idmef_message_t *message;
        
        message = idmef_message_new();
        if ( ! message )
                return;
        
        idmef_heartbeat_new(message);
        hb = message->message.heartbeat;

        generate_analyzer(&hb->analyzer);
                
        gettimeofday(&tv, NULL);
        hb->create_time.sec = tv.tv_sec;
        hb->create_time.usec = tv.tv_usec;

        idmef_msg_send(msgbuf, message, PRELUDE_MSG_PRIORITY_MID);
        idmef_message_free(message);
}



static char *keep_buffer(const char *str) 
{
        int ret;
        static char buf[1024], *ptr; 

        /*
         * FIXME: ugly hack because of IDMEF API memory handling uglyness
         */
        ret = snprintf(&buf[target_buf_index], sizeof(buf) - target_buf_index, "%s", str);        
        if ( (ret + target_buf_index) >= sizeof(buf) || ret < 0 )
                return "";

        
        ptr = &buf[target_buf_index];
        target_buf_index += ret + 1;

        return ptr;
}



static int resolve_failed_fallback(const log_container_t *log, idmef_node_t *node) 
{
        int ret;
        idmef_address_t *address;
        
        /*
         * we want to know if it's an Ip address or an hostname.
         */
        ret = inet_addr(log->target_hostname);
        if ( ret < 0 ) {
                /*
                 * hostname.
                 */
                idmef_string_set(&node->name, log->target_hostname);
        } else {
                address = idmef_node_address_new(node);
                if ( ! address ) 
                        return -1;
                
                idmef_string_set(&address->address, log->target_hostname);
        }

        return 0;
}




static int fill_target(idmef_node_t *node, prelude_addrinfo_t *ai) 
{
        char str[128];
        void *in_addr;
        idmef_address_t *addr;

        target_buf_index = 0;
        
        while ( ai ) {

                if ( ai->ai_flags & AI_CANONNAME ) 
                        idmef_string_set(&node->name, keep_buffer(ai->ai_canonname));
                
                addr = idmef_node_address_new(node);
                if ( ! addr )
                        return -1;

                in_addr = prelude_inet_sockaddr_get_inaddr(ai->ai_addr);
                assert(in_addr);
                
                if ( ai->ai_family == AF_INET ) 
                        addr->category = ipv4_addr;
                else
                        addr->category = ipv6_addr;
                
                if ( ! prelude_inet_ntop(ai->ai_family, in_addr, str, sizeof(str)) ) {
                        log(LOG_ERR, "inet_ntop returned an error.\n");
                        return -1;
                }
                
                idmef_string_set(&addr->address, keep_buffer(str));
                
                ai = ai->ai_next;
        }

        return 0;
}



static int generate_target(const log_container_t *log, idmef_alert_t *alert) 
{
        int ret;
        idmef_node_t *node;
        idmef_target_t *target;
        idmef_process_t *process;
        
        target = idmef_alert_target_new(alert);
        if ( ! target ) 
                return -1;

        if ( log->target_program ) {
                process = idmef_target_process_new(target);
                if ( ! process )
                        return -1;
                
                idmef_string_set(&process->name, log->target_program);
        }

        if ( log->target_hostname ) {
                prelude_addrinfo_t *ai, hints;
                
                node = idmef_target_node_new(target);
                if ( ! node ) 
                        return -1;

                memset(&hints, 0, sizeof(hints));
                hints.ai_flags = AI_CANONNAME;
                hints.ai_socktype = SOCK_STREAM;
                
                /* This function conforms to getaddrinfo(3), not a general calling convention in libprelude */
                ret = prelude_inet_getaddrinfo(log->target_hostname, NULL, &hints, &ai);
                if ( ret != 0 ) {
                        log(LOG_ERR, "error resolving \"%s\": %s.\n", log->target_hostname, prelude_inet_gai_strerror(ret));
                        return resolve_failed_fallback(log, node);
                }

                fill_target(node, ai);

                prelude_inet_freeaddrinfo(ai);
        }

        return 0;
}




void lml_emit_alert(const log_container_t *log, idmef_message_t *msg, uint8_t priority)
{
        int ret;
        struct timeval tv;
        idmef_additional_data_t *data;
        idmef_alert_t *alert = msg->message.alert;
        
        gettimeofday(&tv, NULL);
        alert->create_time.sec = tv.tv_sec;
        alert->create_time.usec = tv.tv_usec;
        
        idmef_alert_detect_time_new(alert);
        alert->detect_time->sec = log->tv.tv_sec;
        alert->detect_time->usec = log->tv.tv_usec;
        
        if ( log->target_hostname || log->target_program ) {
                ret = generate_target(log, alert);
                if ( ret < 0 ) {
                      idmef_message_free(msg);
                      return;  
                }
        }        

        generate_analyzer(&alert->analyzer);

        /*
         *
         */
        data = idmef_alert_additional_data_new(alert);
        if ( ! data ) {
                idmef_message_free(msg);
                return;
        }
        
        idmef_string_set_constant(&data->meaning, "Log received from");
        idmef_additional_data_set_data(data, string, log->source, strlen(log->source) + 1);
        
        /*
         *
         */
        if ( log->log ) {
                data = idmef_alert_additional_data_new(alert);
                if ( ! data ) {
                        idmef_message_free(msg);
                        return;
                }
                
                idmef_string_set_constant(&data->meaning, "Original Log");
                idmef_additional_data_set_data(data, string, log->log, strlen(log->log) + 1);
        }
        
        /*
         *
         */
        
        idmef_msg_send(msgbuf, msg, priority);
        idmef_message_free(msg);
}




int lml_alert_init(void) 
{        
        msgbuf = prelude_msgbuf_new(0);
        if ( ! msgbuf ) {
                log(LOG_ERR, "couldn't create a message stream.\n");
                return -1;
        }

        /*
         * setup analyzer node.
         */        
        prelude_heartbeat_register_cb(send_heartbeat_cb, NULL);

        return 0;
}
