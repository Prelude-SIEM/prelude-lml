#ifndef PLUGIN_LOG_H
#define PLUGIN_LOG_H

typedef struct {
	PRELUDE_PLUGIN_GENERIC;
	void (*run)(prelude_plugin_instance_t *pi, const log_container_t * log);
} plugin_log_t;



#define plugin_run_func(p) (p)->run
#define prelude_plugin_set_running_func(p, func) plugin_run_func(p) = (func)

#endif				/* PLUGIN_LOG_H */
