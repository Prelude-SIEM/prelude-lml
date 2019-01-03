/*****
*
* Copyright (C) 2002-2019 CS-SI. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-LML program.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libprelude/prelude.h>

#include "prelude-lml.h"


int debug_LTX_prelude_plugin_version(void);
int debug_LTX_lml_plugin_init(prelude_plugin_entry_t *pe, void *data);


typedef struct {
        int out_stderr;
} debug_plugin_t;



static lml_log_plugin_t plugin;
extern prelude_option_t *lml_root_optlist;



static void debug_run(prelude_plugin_instance_t *pi, const lml_log_source_t *ls, lml_log_entry_t *log_entry)
{
        int ret;
        debug_plugin_t *plugin;
        idmef_alert_t *alert;
        prelude_string_t *str;
        idmef_message_t *message;
        idmef_classification_t *class;

        plugin = prelude_plugin_instance_get_plugin_data(pi);

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

        ret = idmef_alert_new_classification(alert, &class);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating idmef analyzer");
                goto err;
        }

        ret = idmef_classification_new_text(class, &str);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating model string");
                goto err;
        }
        prelude_string_set_constant(str, "LML debug Alert");

        lml_alert_emit(ls, log_entry, message);

        if ( plugin->out_stderr )
                fprintf(stderr, "Debug: log received, log=%s\n", lml_log_entry_get_original_log(log_entry));

 err:
        idmef_message_destroy(message);
}



static int debug_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        debug_plugin_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        prelude_plugin_instance_set_plugin_data(context, new);

        return 0;
}




static void debug_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        debug_plugin_t *debug = prelude_plugin_instance_get_plugin_data(pi);
        free(debug);
}



static int debug_get_output_stderr(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        debug_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        return prelude_string_sprintf(out, "%s", plugin->out_stderr ? "true" : "false");
}



static int debug_set_output_stderr(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        debug_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        plugin->out_stderr = ! plugin->out_stderr;

        return 0;
}



int debug_LTX_lml_plugin_init(prelude_plugin_entry_t *pe, void *lml_root_optlist)
{
        prelude_option_t *opt;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG;

        prelude_option_add(lml_root_optlist, &opt, hook, 0, "debug", "Debug plugin option",
                           PRELUDE_OPTION_ARGUMENT_OPTIONAL, debug_activate, NULL);

        prelude_plugin_set_activation_option(pe, opt, NULL);

        prelude_option_add(opt, NULL, hook, 's', "stderr",
                           "Output to stderr when plugin is called", PRELUDE_OPTION_ARGUMENT_NONE,
                           debug_set_output_stderr, debug_get_output_stderr);

        plugin.run = debug_run;
        prelude_plugin_set_name(&plugin, "Debug");
        prelude_plugin_set_destroy_func(&plugin, debug_destroy);

        prelude_plugin_entry_set_plugin(pe, (void *) &plugin);

        return 0;
}



int debug_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}

