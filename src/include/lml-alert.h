#include <libprelude/prelude-client.h>


int lml_alert_init(prelude_client_t *lml_client);

void lml_emit_alert(const log_container_t *log, idmef_message_t *msg, uint8_t priority);
