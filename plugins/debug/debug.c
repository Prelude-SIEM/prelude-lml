/*****
*
* Copyright (C) 2002 - 2005 Yoann Vandoorselaere <yoann@prelude-ids.org>
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


int debug_LTX_lml_plugin_init(prelude_plugin_generic_t **pret, void *data);


typedef struct {
        int out_stderr;
} debug_plugin_t;



static plugin_log_t plugin;
extern prelude_option_t *lml_root_optlist;



static void debug_run(prelude_plugin_instance_t *pi, const log_entry_t *log_entry)
{
        int ret;
        debug_plugin_t *plugin;
        idmef_alert_t *alert;
        prelude_string_t *str;
        idmef_message_t *message;
        idmef_analyzer_t *analyzer;
        idmef_additional_data_t *adata;

        plugin = prelude_plugin_instance_get_data(pi);

        ret = idmef_message_new(&message);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating idmef message");
                return;
        }

        ret = idmef_message_new_alert(message, &alert);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating idmef alert");
                goto err;
        }

        ret = idmef_alert_new_analyzer(alert, &analyzer);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating idmef analyzer");
                goto err;
        }

        ret = idmef_analyzer_new_model(analyzer, &str);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating model string");
                goto err;
        }
        prelude_string_set_constant(str, "Prelude-LML Debug Plugin");

        ret = idmef_analyzer_new_class(analyzer, &str);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating class string");
                goto err;
        }
        prelude_string_set_constant(str, "An alert for any log received");

        ret = idmef_alert_new_additional_data(alert, &adata);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating idmef additional data");
                goto err;
        }
        idmef_additional_data_set_type(adata, IDMEF_ADDITIONAL_DATA_TYPE_STRING);

        ret = idmef_additional_data_new_meaning(adata, &str);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating meaning string");
                goto err;
        }
        prelude_string_set_constant(str, "log message");
        idmef_additional_data_set_string_ref(adata, log_entry->original_log);
        
        lml_emit_alert(log_entry, message, PRELUDE_MSG_PRIORITY_LOW);

        if ( plugin->out_stderr )
                fprintf(stderr, "Debug: log received, log=%s\n", log_entry->original_log);

 err:
        idmef_message_destroy(message);
}



static int debug_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
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



static int debug_get_output_stderr(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        debug_plugin_t *plugin = prelude_plugin_instance_get_data(context);
        return prelude_string_sprintf(out, "%s", plugin->out_stderr ? "true" : "false");
}



static int debug_set_output_stderr(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        debug_plugin_t *plugin = prelude_plugin_instance_get_data(context);
        
        plugin->out_stderr = ! plugin->out_stderr;

        return 0;
}



int debug_LTX_lml_plugin_init(prelude_plugin_generic_t **pret, void *lml_root_optlist)
{
        int ret;
        prelude_option_t *opt;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        *pret = (void *) &plugin;
        
        ret = prelude_option_add(lml_root_optlist, &opt, hook, 0, "debug", "Debug plugin option",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, debug_activate, NULL);

        prelude_plugin_set_activation_option((void *) &plugin, opt, NULL);
        
        prelude_option_add(opt, NULL, hook, 's', "stderr",
                           "Output to stderr when plugin is called", PRELUDE_OPTION_ARGUMENT_NONE,
                           debug_set_output_stderr, debug_get_output_stderr);
        
        prelude_plugin_set_name(&plugin, "Debug");
        prelude_plugin_set_author(&plugin, "Yoann Vandoorselaere");
        prelude_plugin_set_desc(&plugin, "Send an alert for each log.");
        prelude_plugin_set_running_func(&plugin, debug_run);
        prelude_plugin_set_destroy_func(&plugin, debug_destroy);
        
        return 0;
}
