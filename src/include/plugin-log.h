#ifndef PLUGIN_LOG_H
#define PLUGIN_LOG_H

typedef struct {
	PLUGIN_GENERIC;
	int (*opt) (int argc, char **argv);
	void (*run) (const log_container_t * log);
} plugin_log_t;


#define plugin_subscribtion(p) (p)->subscribtion
#define plugin_run_func(p) (p)->run

#define plugin_set_subscribtion(p, s) plugin_subscribtion(p) = (s)
#define plugin_set_running_func(p, func) plugin_run_func(p) = (func)

/*
 * Plugin initialisation function.
 */
plugin_generic_t *plugin_init(int argc, char **argv);

#endif				/* PLUGIN_LOG_H */
