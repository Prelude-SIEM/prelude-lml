/*****
*
* Copyright (C) 1998 - 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
        int index;
        char buf[1024];
        int need_more_read;
        time_t last_modified;
} monitor_fd_t;


static int fd_index = 0;
static monitor_fd_t *fd_tbl[MAX_FD];



static int read_logfile(monitor_fd_t *fd) 
{
        int ret;
        
        while ( 1 ) {

                /*
                 * check if our buffer isn't big enough,
                 * and truncate if it is.
                 */
                if ( fd->index == sizeof(fd->buf) ) {
                        fd->buf[fd->index - 1] = '\0';
                        fd->need_more_read = 1;
                        break;
                }

                /*
                 * as we use -D_REENTRANT, libc will use locked stdio function.
                 * Override this by using *_unlocked() variant.
                 */
                ret = getc_unlocked(fd->fd);
                if ( ret == EOF ) {
                        if ( fd->index != 0 )
                                /*
                                 * missing end of line (\n).
                                 */
                                fd->need_more_read = 1;

                        return -1;
                }
                
                if ( ret == '\n' ) {
                        fd->buf[fd->index] = '\0';
                        fd->need_more_read = 0;
                        break;
                }

                fd->buf[fd->index++] = (char) ret;
        }
        
        fd->index = 0;
        
        return 0;
}




int file_server_wake_up(regex_list_t *list, queue_t *queue) 
{
        int i, ret;
        struct stat st;
        monitor_fd_t *monitor;

        /*
         * this function is called every second,
         * as we're not using prelude-async, we have to wake possibly
         * existing timer manually.
         */
        prelude_wake_up_timer();
        
        for ( i = 0; i < fd_index; i++ ) {
                               
                monitor = fd_tbl[i];

                ret = fstat(fileno(monitor->fd), &st);
                if ( ret < 0 ) {
                        log(LOG_ERR, "couldn't fstat '%s'.\n", monitor->file);
                        continue;
                }
                
                if ( ! monitor->need_more_read && st.st_mtime == monitor->last_modified ) 
                        continue;

                monitor->last_modified = st.st_mtime;

                while ( read_logfile(monitor) != -1 ) 
                        lml_dispatch_log(list, queue, monitor->buf, monitor->file);
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













