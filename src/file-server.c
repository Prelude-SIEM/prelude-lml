#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>

#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>

#include "queue.h"
#include "regex.h"
#include "common.h"
#include "log-common.h"
#include "file-server.h"

#define MAX_FD 1024

typedef struct {
        FILE *fd;
        char *file;
        time_t last_modified;
} monitor_fd_t;


static int fd_index = 0;
static monitor_fd_t *fd_tbl[MAX_FD];



int file_server_wake_up(regex_list_t *list, queue_t *queue) 
{
        int i, ret;
        char buf[8192];
        struct stat st;
        monitor_fd_t *monitor;
        
        for ( i = 0; i < fd_index; i++ ) {
                               
                monitor = fd_tbl[i];

                ret = fstat(fileno(monitor->fd), &st);
                if ( ret < 0 ) {
                        log(LOG_ERR, "couldn't fstat '%s'.\n", monitor->file);
                        continue;
                }

                if ( st.st_mtime == monitor->last_modified )
                        continue;

                monitor->last_modified = st.st_mtime;

                if ( ! fgets(buf, sizeof(buf), monitor->fd) )
                        continue;
                
                lml_dispatch_log(list, queue, buf, monitor->file);
        }

        return 0;
}




int file_server_monitor_file(const char *file, int fd) 
{
        int ret;
        struct stat st;
        monitor_fd_t *new;
        
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

        ret = fstat(fd, &st);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't stat '%s'.\n", file);
                free(new);
                close(fd);
                return -1;
        }
        
        new->fd = fdopen(fd, "r");
        new->last_modified = st.st_mtime;
        new->file = strdup(file);
        fd_tbl[fd_index++] = new;
        
        return 0;
}





int file_server_standalone(regex_list_t *list, queue_t *queue) 
{
        /*
         * there is no way for select / read to block on EOF
         * for regular file, so we end up doing a sleep and
         * comparing modification time (as tail does).
         */
        while ( 1 ) {
                file_server_wake_up(list, queue);
                sleep(1);
        }
}













