plugin_container_t *log_plugin_register(const char *pname);
void log_plugin_run(plugin_container_t *pc, log_container_t *log);
int log_plugins_init(const char *dirname, int argc, char **argv);
