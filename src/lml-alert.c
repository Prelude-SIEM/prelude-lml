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


void lml_emit_alert(const log_container_t *log, idmef_message_t *msg, uint8_t priority)
{
        idmef_node_t *node;
        idmef_target_t *target;
        idmef_address_t *address;
        idmef_additional_data_t *data;
        idmef_alert_t *alert = msg->message.alert;
        idmef_analyzer_t *analyzer = &alert->analyzer;

        target = idmef_alert_target_new(alert);
        if ( ! target ) {
                idmef_message_free(msg);
                return;
        }

        node = idmef_target_node_new(target);
        if ( ! node ) {
                idmef_message_free(msg);
                return;
        }

        address = idmef_node_address_new(node);
        if ( ! address ) {
                idmef_message_free(msg);
                return;
        }

        idmef_string_set(&address->address, log->source);
        
        idmef_string_copy(&analyzer->ostype, &ostype);
        idmef_string_copy(&analyzer->osversion, &osversion);
        idmef_string_set_constant(&analyzer->model, ANALYZER_MODEL);
        idmef_string_set_constant(&analyzer->class, ANALYZER_CLASS);
        idmef_string_set_constant(&analyzer->manufacturer, ANALYZER_MANUFACTURER);

        data = idmef_alert_additional_data_new(alert);
        if ( ! data ) {
                idmef_message_free(msg);
                return;
        }

        data->type = string;
        idmef_string_set_constant(&data->meaning, "Source Log");
        idmef_string_set(&data->data, log->log);

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



