#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/utsname.h>

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-msg-send.h>

#include "log-common.h"
#include "lml-alert.h"

static prelude_msgbuf_t *msgbuf;
static idmef_string_t ostype, osversion;

#define ANALYZER_MODEL "Prelude LML"
#define ANALYZER_CLASS "Host based Intrusion Detection System"
#define ANALYZER_MANUFACTURER "The Prelude Team http://www.prelude-ids.org"



static int generate_target(const log_container_t *log, idmef_alert_t *alert) 
{
        int ret;
        idmef_node_t *node;
        idmef_target_t *target;
        idmef_process_t *process;
        idmef_address_t *address;
        
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
                
                node = idmef_target_node_new(target);
                if ( ! node ) 
                        return -1;

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
        }

        return 0;
}





void lml_emit_alert(const log_container_t *log, idmef_message_t *msg, uint8_t priority)
{
        int ret;
        struct timeval tv;
        idmef_additional_data_t *data;
        idmef_alert_t *alert = msg->message.alert;
        idmef_analyzer_t *analyzer = &alert->analyzer;

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
        
        idmef_string_copy(&analyzer->ostype, &ostype);
        idmef_string_copy(&analyzer->osversion, &osversion);
        idmef_string_set_constant(&analyzer->model, ANALYZER_MODEL);
        idmef_string_set_constant(&analyzer->class, ANALYZER_CLASS);
        idmef_string_set_constant(&analyzer->manufacturer, ANALYZER_MANUFACTURER);

        /*
         *
         */
        data = idmef_alert_additional_data_new(alert);
        if ( ! data ) {
                idmef_message_free(msg);
                return;
        }
        
        data->type = string;
        idmef_string_set_constant(&data->meaning, "Log received from");
        idmef_string_set(&data->data, log->source);

        /*
         *
         */
        data = idmef_alert_additional_data_new(alert);
        if ( ! data ) {
                idmef_message_free(msg);
                return;
        }

        data->type = string;
        idmef_string_set_constant(&data->meaning, "Original Log");
        idmef_string_set(&data->data, log->log);
        
        /*
         *
         */
        
        idmef_msg_send(msgbuf, msg, priority);
        idmef_message_free(msg);
}




int lml_alert_init(void) 
{
        int ret;
        static struct utsname buf;

        msgbuf = prelude_msgbuf_new(0);
        if ( ! msgbuf ) {
                log(LOG_ERR, "couldn't create a message stream.\n");
                return -1;
        }
        
        ret = uname(&buf);
        if ( ret < 0 ) {
                log(LOG_ERR, "uname returned an error.\n");
                return -1;
        }
        
        idmef_string_set(&ostype, buf.sysname);
        idmef_string_set(&osversion, buf.release);

        return 0;
}



