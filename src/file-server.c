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

#include <libprelude/timer.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>

#include "queue.h"
#include "regex.h"
#include "common.h"
#include "log-common.h"
#include "file-server.h"

typedef struct {
        FILE *fd;
        char *file;
        int index;
        char buf[1024];
        int need_more_read;
        time_t last_size;
        struct list_head list;
} monitor_fd_t;


static LIST_HEAD(active_fd_list);
static LIST_HEAD(inactive_fd_list);



static int read_logfile(monitor_fd_t *fd) 
{
        int ret, len = 0;
        
        while ( 1 ) {

                /*
                 * check if our buffer isn't big enough,
                 * and truncate if it is.
                 */
                if ( fd->index == sizeof(fd->buf) ) {
                        fd->buf[fd->index - 1] = '\0';
                        break;
                }

                /*
                 * as we use -D_REENTRANT, libc will use locked stdio function.
                 * Override this by using *_unlocked() variant.
                 */
                ret = getc_unlocked(fd->fd);
                if ( ret == EOF ) {                        
			clearerr_unlocked(fd->fd);
                        return -1;
                }

                len++;
                
                if ( ret == '\n' ) {
                        fd->buf[fd->index] = '\0';
                        break;
                }

                fd->buf[fd->index++] = (char) ret;
        }
        
        fd->index = 0;
        
        return len;
}



static void try_reopening_inactive_fd(void) 
{
        int ret;
        struct stat st;
        monitor_fd_t *monitor;
        struct list_head *tmp, *bkp;

        list_for_each_safe(tmp, bkp, &inactive_fd_list) {

                monitor = list_entry(tmp, monitor_fd_t, list);
                
                monitor->fd = fopen(monitor->file, "r");
                if ( ! monitor->fd )
                        continue;

                monitor->index = 0;
                monitor->last_size = 0;
                monitor->need_more_read = 0;
                
                list_del(&monitor->list);
                list_add_tail(&monitor->list, &active_fd_list);
                
                log(LOG_INFO, "Re-opened monitor for '%s'.\n", monitor->file);
        }
}




int file_server_wake_up(regex_list_t *list, queue_t *queue) 
{
        int ret, len;
        struct stat st;
        monitor_fd_t *monitor;
        struct list_head *tmp, *bkp;
        
        /*
         * this function is called every second,
         * as we're not using prelude-async, we have to wake possibly
         * existing timer manually.
         */
        prelude_wake_up_timer();

        /*
         * try to open inactive fd (file was not existing previously).
         */
        try_reopening_inactive_fd();

        list_for_each_safe(tmp, bkp, &active_fd_list) {
                               
                monitor = list_entry(tmp, monitor_fd_t, list);

                ret = fstat(fileno(monitor->fd), &st);
                if ( ret < 0 ) {
                        log(LOG_ERR, "couldn't fstat '%s'.\n", monitor->file);
                        continue;
                }
                
                if ( st.st_nlink == 0 ) {
                        /*
                         * This file doesn't exist on the file system anymore.
                         */
			fclose(monitor->fd);
                        list_del(&monitor->list);
                        list_add_tail(&monitor->list, &inactive_fd_list);
                        continue;
                }
                
                if ( ! monitor->need_more_read && st.st_size == monitor->last_size ) 
                        continue;
                
                len = (st.st_size - monitor->last_size) + monitor->need_more_read;
                monitor->last_size = st.st_size;

                while ( (ret = read_logfile(monitor)) != -1 ) {
                        len -= ret;
                        lml_dispatch_log(list, queue, monitor->buf, monitor->file);
                }

                /*
                 * if len isn't 0, it mean we got EOF before reading
                 * every new byte, we want to retry reading even if st_size isn't
                 * modified then.
                 */
                monitor->need_more_read = len;
        }

        return 0;
}




int file_server_monitor_file(const char *file) 
{
        int ret;
        struct stat st;
        monitor_fd_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        new->fd = fopen(file, "r");
        if ( ! new->fd ) {
                list_add_tail(&new->list, &inactive_fd_list);
                return 0;
        }
        
        ret = fseek(new->fd, 0, SEEK_END);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't seek to the end of the file.\n");
                fclose(new->fd);
                return -1;
        }
        
        ret = fstat(fileno(new->fd), &st);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't stat '%s'.\n", file);
                free(new);
                fclose(new->fd);
                return -1;
        }
        
        new->last_size = st.st_size;
        new->file = strdup(file);

        list_add_tail(&new->list, &active_fd_list);
        
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













