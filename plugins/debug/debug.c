#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <assert.h>
#include <sys/time.h>

#include <libprelude/idmef.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/prelude-getopt.h>

#include "log-common.h"
#include "log.h"
#include "lml-alert.h"


typedef struct {
        int out_stderr;
} debug_plugin_t;



static plugin_log_t plugin;




static void debug_run(prelude_plugin_instance_t *pi, const log_container_t *log)
{
	idmef_alert_t *alert;
	idmef_message_t *message;
	idmef_analyzer_t *analyzer;
	idmef_string_t *analyzer_model, *analyzer_class;
	idmef_additional_data_t *adata;
	idmef_string_t *adata_meaning;
	idmef_data_t *data;
        debug_plugin_t *plugin;

        plugin = prelude_plugin_instance_get_data(pi);

	message = idmef_message_new();
	assert(message);

	alert = idmef_message_new_alert(message);
	assert(alert);

	analyzer = idmef_alert_new_analyzer(alert);
	assert(analyzer);

	analyzer_model = idmef_analyzer_new_model(analyzer);
	idmef_string_set_constant(analyzer_model, "Prelude-LML Debug Plugin");

	analyzer_class = idmef_analyzer_new_class(analyzer);
	idmef_string_set_constant(analyzer_class, "An alert for any log received");

	adata = idmef_alert_new_additional_data(alert);
	assert(adata);

	idmef_additional_data_set_type(adata, IDMEF_ADDITIONAL_DATA_TYPE_STRING);

	adata_meaning = idmef_additional_data_new_meaning(adata);
	idmef_string_set_constant(adata_meaning, "log message");

	data = idmef_additional_data_new_data(adata);
	idmef_data_set_ref(data, log->log, strlen(log->log) + 1);

	lml_emit_alert(log, message, PRELUDE_MSG_PRIORITY_LOW);

	if ( plugin->out_stderr )
		fprintf(stderr, "Debug: log received, log=%s\n", log->log);
}



static int debug_activate(prelude_plugin_instance_t *pi, prelude_option_t *opt, const char *optarg)
{
        debug_plugin_t *new;
                
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return prelude_option_error;
        }

        prelude_plugin_instance_set_data(pi, new);
        
	return prelude_option_success;
}




static void debug_destroy(prelude_plugin_instance_t *pi)
{
        debug_plugin_t *debug = prelude_plugin_instance_get_data(pi);
        
        free(debug);
}



static int debug_get_output_stderr(prelude_plugin_instance_t *pi, char *buf, size_t size)
{
        debug_plugin_t *plugin = prelude_plugin_instance_get_data(pi);
        
	snprintf(buf, size, "%s", plugin->out_stderr ? "enabled" : "disabled");

	return prelude_option_success;
}



static int debug_set_output_stderr(prelude_plugin_instance_t *pi, prelude_option_t *opt, const char *optarg)
{
        debug_plugin_t *plugin = prelude_plugin_instance_get_data(pi);
        
	plugin->out_stderr = ! plugin->out_stderr;

        return prelude_option_success;
}



prelude_plugin_generic_t *prelude_plugin_init(void)
{
	prelude_option_t *opt;

	opt = prelude_plugin_option_add(NULL, CLI_HOOK | CFG_HOOK, 0, "debug",
                                        "Debug plugin option", optionnal_argument,
                                        debug_activate, NULL);

        prelude_plugin_set_activation_option((void *) &plugin, opt, NULL);
        
	prelude_plugin_option_add(opt, CLI_HOOK | CFG_HOOK, 's', "stderr",
                                  "Output to stderr when plugin is called",
                                  no_argument, debug_set_output_stderr, debug_get_output_stderr);
        
	prelude_plugin_set_name(&plugin, "Debug");
	prelude_plugin_set_author(&plugin, "Pierre-Jean Turpeau");
	prelude_plugin_set_contact(&plugin, "Pierre-Jean.Turpeau@enseirb.fr");
	prelude_plugin_set_desc(&plugin, "Send an alert for each log.");
	prelude_plugin_set_running_func(&plugin, debug_run);
        prelude_plugin_set_destroy_func(&plugin, debug_destroy);
        
	return (void *) &plugin;
}
