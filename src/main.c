#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/sensor.h>

#include "config.h"
#include "common.h"
#include "queue.h"
#include "udp-server.h"
#include "regex.h"
#include "log-common.h"
#include "plugin-log.h"
#include "pconfig.h"

Pconfig_t config;
#define MAXPLUG 1024



static void sig_handler(int signum)
{
	fprintf(stderr, "\n\nCaught signal %d.\n", signum);
	signal(signum, SIG_DFL);
	exit(2);
}



static void message_reader(queue_t *queue, const char *str, const char *from)
{
	time_t t;
	log_container_t *log;

        log = malloc(sizeof(*log));
	if ( ! log ) {
                log(LOG_ERR, "memory exhausted.\n");
                return;
        }

	log->log = strdup(str);
	log->source = strdup(from);
	t = time(NULL), localtime_r(&t, &log->time_received);

        dprint("[MSGRD] received <%s> from %s\n", str, from);

        queue_push(queue, log);
}




static void object_dump(void *object)
{
	char *s = object;
	printf("[%s]\n", s);
}




static void dispatcher(regex_list_t *list, queue_t *myqueue)
{
        int ret, i;
        log_container_t *log;
        char *plugins[MAXPLUG];
        
	while ( 1 ) {

		log = (log_container_t *) queue_pop(myqueue);
                if ( ! log )
                        continue;

                dprint("[DSPTC] dispatching object: <%s> from %s at %02d:%02d:%02d %04d/%02d/%02d\n",
                       log->log, log->source,
                       log->time_received.tm_hour,
                       log->time_received.tm_min,
                       log->time_received.tm_sec,
                       log->time_received.tm_year + 1900,
                       log->time_received.tm_mon + 1,
                       log->time_received.tm_mday);

                ret = regex_exec(list, log->log, plugins, MAXPLUG);
                for (i = 0; i < ret; i++)
                        log_plugins_run(plugins[i], log);

                log_container_delete(log);
	}
}




int main(int argc, char **argv)
{
	udp_server_t *myudp;
	queue_t *myqueue;
	regex_list_t *regex_list;
	int ret;

	ret = log_plugins_init(LOG_PLUGIN_DIR, argc, argv);
	if (ret < 0) {
		log(LOG_INFO, "error initializing logs plugins.\n");
		return -1;
	}
	log(LOG_INFO, "- Initialized %d logs plugins.\n", ret);

        myqueue = queue_new(NULL);
        if ( ! myqueue )
                exit(1);
        
        ret = file_server_new(myqueue);
        if ( ret < 0 )
                exit(1);
        
	if (pconfig_set(argc, argv) < 0)
		exit(1);

	regex_list = regex_init(REGEX_CONF);
        
	myudp = udp_server_new(514, message_reader, myqueue);
        if ( ! myudp )
                exit(1);
        
        udp_server_start(myudp);

	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGQUIT, sig_handler);
	signal(SIGABRT, sig_handler);

	dispatcher(regex_list, myqueue);

	return 0;
}
