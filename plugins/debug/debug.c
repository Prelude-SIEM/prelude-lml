#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <sys/time.h>

#include <libprelude/prelude.h>

#include "libmissing.h"
#include "log-common.h"
#include "log.h"
#include "lml-alert.h"


prelude_plugin_generic_t *debug_LTX_prelude_plugin_init(void);


typedef struct {
        int out_stderr;
} debug_plugin_t;



static plugin_log_t plugin;
extern prelude_option_t *lml_root_optlist;



static void debug_run(prelude_plugin_instance_t *pi, const log_entry_t *log_entry)
{
        idmef_alert_t *alert;
        idmef_message_t *message;
        idmef_analyzer_t *analyzer;
        prelude_string_t *analyzer_model, *analyzer_class;
        idmef_additional_data_t *adata;
        prelude_string_t *adata_meaning;
        debug_plugin_t *plugin;

        plugin = prelude_plugin_instance_get_data(pi);

        message = idmef_message_new();
        assert(message);

        alert = idmef_message_new_alert(message);
        assert(alert);

        analyzer = idmef_alert_new_analyzer(alert);
        assert(analyzer);

        analyzer_model = idmef_analyzer_new_model(analyzer);
        prelude_string_set_constant(analyzer_model, "Prelude-LML Debug Plugin");

        analyzer_class = idmef_analyzer_new_class(analyzer);
        prelude_string_set_constant(analyzer_class, "An alert for any log received");

        adata = idmef_alert_new_additional_data(alert);
        assert(adata);

        idmef_additional_data_set_type(adata, IDMEF_ADDITIONAL_DATA_TYPE_STRING);

        adata_meaning = idmef_additional_data_new_meaning(adata);
        prelude_string_set_constant(adata_meaning, "log message");

        idmef_additional_data_set_string_ref(adata, log_entry->original_log);

        lml_emit_alert(log_entry, message, PRELUDE_MSG_PRIORITY_LOW);

        if ( plugin->out_stderr )
                fprintf(stderr, "Debug: log received, log=%s\n", log_entry->original_log);
}



static int debug_activate(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        debug_plugin_t *new;
                
        new = calloc(1, sizeof(*new));
        if ( ! new ) 
                return prelude_error_from_errno(errno);

        prelude_plugin_instance_set_data(context, new);
        
        return 0;
}




static void debug_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        debug_plugin_t *debug = prelude_plugin_instance_get_data(pi);
        free(debug);
}



static int debug_get_output_stderr(void *context, prelude_option_t *opt, prelude_string_t *out)
{
        debug_plugin_t *plugin = prelude_plugin_instance_get_data(context);
        return prelude_string_sprintf(out, "%s", plugin->out_stderr ? "true" : "false");
}



static int debug_set_output_stderr(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        debug_plugin_t *plugin = prelude_plugin_instance_get_data(context);
        
        plugin->out_stderr = ! plugin->out_stderr;

        return 0;
}



prelude_plugin_generic_t *debug_LTX_prelude_plugin_init(void)
{
        prelude_option_t *opt;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;
        
        opt = prelude_option_add(lml_root_optlist, hook, 0, "debug", "Debug plugin option",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, debug_activate, NULL);

        prelude_plugin_set_activation_option((void *) &plugin, opt, NULL);
        
        prelude_option_add(opt, hook, 's', "stderr",
                           "Output to stderr when plugin is called", PRELUDE_OPTION_ARGUMENT_NONE,
                           debug_set_output_stderr, debug_get_output_stderr);
        
        prelude_plugin_set_name(&plugin, "Debug");
        prelude_plugin_set_author(&plugin, "Pierre-Jean Turpeau");
        prelude_plugin_set_contact(&plugin, "Pierre-Jean.Turpeau@enseirb.fr");
        prelude_plugin_set_desc(&plugin, "Send an alert for each log.");
        prelude_plugin_set_running_func(&plugin, debug_run);
        prelude_plugin_set_destroy_func(&plugin, debug_destroy);
        
        return (void *) &plugin;
}
