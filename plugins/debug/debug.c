#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-msg-send.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/prelude-getopt.h>

#include "log-common.h"
#include "log.h"

static plugin_log_t plugin;

static int is_enabled = 0;
static int out_stderr = 0;

static void debug_run(const log_container_t * log)
{
	idmef_alert_t *alert;
	prelude_msgbuf_t *msgbuf;
	idmef_additional_data_t *additional;

	idmef_message_t *message = idmef_message_new();
	assert(message);

	msgbuf = prelude_msgbuf_new(0);
	assert(msgbuf);

	idmef_alert_new(message);
	alert = message->message.alert;

	idmef_string_set_constant(&alert->analyzer.model,
				  "Prelude-LML Debug Plugin");
	idmef_string_set_constant(&alert->analyzer.class,
				  "An alert for any log received");

	additional = idmef_alert_additional_data_new(alert);
	assert(additional);

	additional->type = string;
	idmef_string_set_constant(&additional->meaning, "log message");
	idmef_string_set(&additional->data, log->log);

	idmef_msg_send(msgbuf, message, PRELUDE_MSG_PRIORITY_MID);
	idmef_message_free(message);
	prelude_msgbuf_close(msgbuf);

	if (out_stderr)
		fprintf(stderr, "Debug: log received, log=%s\n", log->log);
}



static int set_debug_state(const char *optarg)
{
	int ret;

	if (is_enabled == 1) {
		ret = plugin_unsubscribe((plugin_generic_t *) & plugin);
		if (ret < 0)
			return prelude_option_error;

		is_enabled = 0;
	} else {
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
		 (is_enabled == 1) ? "enabled" : "disabled");
	return prelude_option_success;
}

static int get_output(char *buf, size_t size)
{
	snprintf(buf, size, "%s", (out_stderr) ? "enabled" : "disabled");
	return prelude_option_success;
}


static int set_output(const char *optarg)
{
	/*
	 * enable or disable depending on the current value.
	 */
	out_stderr = !out_stderr;
	return prelude_option_success;
}

plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt;

	opt =
	    prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 0, "debug",
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
