#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>

#include "queue.h"
#include "common.h"
#include "log-common.h"
#include "server-logic.h"
#include "file-server.h"


typedef struct {
        SERVER_LOGIC_CLIENT_OBJECT;
        char *file;
} monitor_fd_t;



static server_logic_t *fserver;


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



static int read_file(void *sdata, server_logic_client_t *client) 
{
        int ret;
        char buf[8192];
        monitor_fd_t *fd = (monitor_fd_t *) client;
        
        ret = prelude_io_read(fd->fd, buf, sizeof(buf));

        printf("read ret %d\n", ret);
        
        if ( ret == 0 ) {
                sleep(1);
                return 0;
        }

        else if ( ret < 0 )
                return -1;

        message_reader(sdata, buf, fd->file);

        return ret;
}



static int close_file(void *sdata, server_logic_client_t *client)
{
        monitor_fd_t *fd = (monitor_fd_t *) client;

        free(fd->file);
        prelude_io_close(fd->fd);
        prelude_io_destroy(fd->fd);
        free(fd);

        return 0;
}




int file_server_monitor_file(const char *file) 
{
        int fd, ret;
        monitor_fd_t *new;

        fd = open(file, O_RDONLY|O_NONBLOCK);
        if ( fd < 0 ) {
                log(LOG_ERR, "couln't open %s for reading.\n", file);
                return -1;
        }
        
        ret = lseek(fd, 0, SEEK_END);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't seek to the end of the file.\n");
                close(fd);
                return -1;
        }
        
        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                close(fd);
                return -1;
        }        

        new->file = strdup(file);
        
        new->fd = prelude_io_new();
        if ( ! new->fd ) {
                free(new);
                close(fd);
                return -1;
        }
        
        prelude_io_set_sys_io(new->fd, fd);

        ret = server_logic_process_requests(fserver, (server_logic_client_t *) new);
        if ( ret < 0 ) {
                free(new);
                prelude_io_close(new->fd);
                prelude_io_destroy(new->fd);
                return -1;
        }
        
        return 0;
}




int file_server_new(queue_t *queue) 
{
        fserver = server_logic_new(queue, read_file, close_file);
        if ( ! fserver )
                return -1;

        return 0;
}

