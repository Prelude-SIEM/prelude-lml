#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <assert.h>
#include <sys/time.h>

#include <libprelude/list.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-message-send.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/prelude-getopt.h>

#include "log-common.h"
#include "log.h"
#include "lml-alert.h"


static int is_enabled = 0;
static int out_stderr = 0;
static plugin_log_t plugin;


static void debug_run(const log_container_t *log)
{
	idmef_alert_t *alert;
	idmef_message_t *message;
	idmef_analyzer_t *analyzer;
	idmef_string_t *analyzer_model, *analyzer_class;
	idmef_additional_data_t *adata;
	idmef_string_t *adata_meaning;
	idmef_data_t *data;

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

	idmef_additional_data_set_type(adata, string);

	adata_meaning = idmef_additional_data_new_meaning(adata);
	idmef_string_set_constant(adata_meaning, "log message");

	data = idmef_additional_data_new_data(adata);
	idmef_data_set_ref(data, log->log, strlen(log->log) + 1);

	lml_emit_alert(log, message, PRELUDE_MSG_PRIORITY_LOW);

	if ( out_stderr )
		fprintf(stderr, "Debug: log received, log=%s\n", log->log);
}



static int set_debug_state(prelude_option_t *opt, const char *optarg)
{
	int ret;

	if ( is_enabled ) {
		ret = plugin_unsubscribe((plugin_generic_t *) & plugin);
		if (ret < 0)
			return prelude_option_error;

		is_enabled = 0;
	}

	else {
		ret = plugin_subscribe((plugin_generic_t *) & plugin);
		if (ret < 0)
			return prelude_option_error;

		is_enabled = 1;
	}

	return prelude_option_success;
}



static int get_debug_state(char *buf, size_t size)
{
	snprintf(buf, size, "%s",
		 is_enabled ? "enabled" : "disabled");

	return prelude_option_success;
}



static int get_output(char *buf, size_t size)
{
	snprintf(buf, size, "%s", out_stderr ? "enabled" : "disabled");

	return prelude_option_success;
}



static int set_output(prelude_option_t *opt, const char *optarg)
{
	/*
	 * enable or disable depending on the current value.
	 */
	out_stderr = ! out_stderr;
	return prelude_option_success;
}



plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt;

	opt = prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 0, "debug",
				 "Debug plugin option", no_argument,
				 set_debug_state, get_debug_state);

	prelude_option_add(opt, CLI_HOOK | CFG_HOOK, 'p', "print",
			   "Output to stderr when plugin is called",
			   no_argument, set_output, get_output);

	plugin_set_name(&plugin, "Debug");
	plugin_set_author(&plugin, "Pierre-Jean Turpeau");
	plugin_set_contact(&plugin, "Pierre-Jean.Turpeau@ENSEIRB.fr");
	plugin_set_desc(&plugin, "Send an alert for each log.");
	plugin_set_running_func(&plugin, debug_run);

	return (plugin_generic_t *) & plugin;
}
