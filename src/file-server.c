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
#include <assert.h>

#include <libprelude/timer.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>
#include <libprelude/prelude-message.h>

#include "queue.h"
#include "regex.h"
#include "common.h"
#include "log-common.h"
#include "file-server.h"
#include "lml-alert.h"

#define LOGFILE_DELETION_CLASS "Logfile deletion"
#define LOGFILE_DELETION_IMPACT "An attacker might have erased the logfile,"              \
                                "or a log rotation program may have rotated the logfile "

#define LOGFILE_MODIFICATION_CLASS "Logfile inconsistency"
#define LOGFILE_MODIFICATION_IMPACT "An attacker might have modified the logfile in order " \
                                    "to remove the trace he left"



typedef struct {
        FILE *fd;
        char *file;
        int index;
        char buf[1024];
        int need_more_read;
        off_t last_size;
        time_t last_mtime;
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
			clearerr(fd->fd);
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

                ret = fstat(fileno(monitor->fd), &st);
                if ( ret < 0 ) {
                        log(LOG_ERR, "stat: error on file %s.\n", monitor->file);
                        continue;
                }
                
                monitor->index = 0;
                monitor->last_size = 0; /* re-read every file entry */
                monitor->last_mtime = st.st_mtime;
                monitor->need_more_read = 0;
                
                list_del(&monitor->list);
                list_add_tail(&monitor->list, &active_fd_list);
                
                log(LOG_INFO, "Re-opened monitor for '%s'.\n", monitor->file);
        }
}



static void logfile_alert(monitor_fd_t *fd, struct stat *st,
                          idmef_classification_t *cl, idmef_impact_t *impact)
{
        char buf[256], *ptr;
        idmef_file_t *f;
        idmef_time_t *time;
        idmef_inode_t *inode;
        log_container_t *log;
        idmef_alert_t *alert;
        idmef_target_t *target;
        idmef_message_t *message;
        idmef_classification_t *class;
        idmef_assessment_t *assessment;
        
        log = log_container_new(NULL, fd->file);
        if ( ! log )
                return;
        
        message = idmef_message_new();
        if ( ! message )
                return;

        /*
         * Initialize the idmef structures
         */
        idmef_alert_new(message);
        alert = message->message.alert;

        target = idmef_alert_target_new(alert);
        if ( ! target )
                goto err;

        f = idmef_target_file_new(target);
        if ( ! f ) 
                goto err;

        f->data_size = st->st_size;

        inode = idmef_file_inode_new(f);
        if ( ! inode )
                goto err;

        inode->number = st->st_ino;
        strncpy(buf, fd->file, sizeof(buf));
        
        ptr = strrchr(buf, '/');
        if ( ptr ) {
                *ptr = '\0';
                idmef_string_set(&f->name, ptr + 1);
        }
        
        idmef_string_set(&f->path, buf);

        time = idmef_file_access_time_new(f);
        if ( ! time )
                goto err;
        
        time->sec = st->st_atime;

        time = idmef_file_modify_time_new(f);
        if ( ! time )
                goto err;

        time->sec = st->st_mtime;
        
        idmef_alert_assessment_new(alert);
        assessment = alert->assessment;

        idmef_assessment_impact_new(assessment);
        memcpy(assessment->impact, impact, sizeof(*assessment->impact));
        
        class = idmef_alert_classification_new(alert);
        if ( ! class )
                goto err;
        
        class->origin = cl->origin;
        idmef_string_copy(&class->url, &cl->url);
        idmef_string_copy(&class->name, &cl->name);
               
        lml_emit_alert(log, message, PRELUDE_MSG_PRIORITY_HIGH);

        log_container_delete(log);
        
        return;
        
 err:
        log_container_delete(log);
        idmef_message_free(message);
}



/*
 * This won't protect against replacement of log entry by garbage,
 * Unfortunnaly, there is no way it can be done cleanly, or it would
 * cause heavy performance problem. The best solution may be to centralize
 * the logging on a remote host.
 */
static void check_modification_time(monitor_fd_t *fd, struct stat *st) 
{
        idmef_impact_t impact;
        idmef_classification_t class;
        time_t old_mtime = fd->last_mtime;
        
        fd->last_mtime = st->st_mtime;
        
        if ( st->st_mtime == old_mtime ) {
                assert(st->st_size == fd->last_size);
                return; /* everythings sound okay */
        }
        
        if ( st->st_size > fd->last_size ) 
                return;
                
        memset(&class, 0, sizeof(class));
        memset(&impact, 0, sizeof(impact));
        
        class.origin = origin_unknown;
        idmef_string_set_constant(&class.name, LOGFILE_MODIFICATION_CLASS);

        impact.type = file;
        impact.completion = succeeded;
        impact.severity = impact_high;
        idmef_string_set_constant(&impact.description, LOGFILE_MODIFICATION_IMPACT);
        
        logfile_alert(fd, st, &class, &impact);
}




static int is_file_already_used(monitor_fd_t *monitor, struct stat *st)
{
        idmef_impact_t impact;
        idmef_classification_t class;
        
        if ( st->st_nlink > 0 )
                return 0;
        
        /*
         * This file doesn't exist on the file system anymore.
         */
        fclose(monitor->fd);
        list_del(&monitor->list);
        list_add_tail(&monitor->list, &inactive_fd_list);

        log(LOG_INFO, "logfile %s reached 0 hard link.\n", monitor->file);

        memset(&class, 0, sizeof(class));
        memset(&impact, 0, sizeof(impact));
        
        class.origin = origin_unknown;
        idmef_string_set_constant(&class.name, LOGFILE_DELETION_CLASS);

        impact.type = file;
        impact.completion = succeeded;
        impact.severity = impact_medium;
        idmef_string_set_constant(&impact.description, LOGFILE_DELETION_IMPACT);
        
        logfile_alert(monitor, st, &class, &impact);
        
        return -1;
}





static void process_logfile(regex_list_t *list, lml_queue_t *queue, monitor_fd_t *monitor, struct stat *st) 
{
        int len, ret;
        
        if ( ! monitor->need_more_read && st->st_size == monitor->last_size ) 
                return;
        
        len = (st->st_size - monitor->last_size) + monitor->need_more_read;
        monitor->last_size = st->st_size;

        while ( (ret = read_logfile(monitor)) != -1 ) {
                len -= ret;
                lml_dispatch_log(list, queue, monitor->buf, monitor->file);
        }

        /*
         * if len isn't 0, it mean we got EOF before reading every new byte,
         * we want to retry reading even if st_size isn't modified then.
         */
        monitor->need_more_read = len;
}



int file_server_wake_up(regex_list_t *list, lml_queue_t *queue) 
{
        int ret;
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
                
                ret = is_file_already_used(monitor, &st);
                if ( ret < 0 )
                        continue;

                /*
                 * check mtime consistency.
                 */ 
                check_modification_time(monitor, &st);

                /*
                 * read and analyze available data. 
                 */
                process_logfile(list, queue, monitor, &st);
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

        new->file = strdup(file);
        if ( ! new->file ) {
                log(LOG_ERR, "memory exhausted.\n");
                free(new);
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
                free(new->file);
                free(new);
                return -1;
        }
        
        ret = fstat(fileno(new->fd), &st);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't stat '%s'.\n", file);
                fclose(new->fd);
                free(new->file);
                free(new);
                return -1;
        }
        
        new->last_size = st.st_size;
        new->last_mtime = st.st_mtime;
        
        list_add_tail(&new->list, &active_fd_list);
        
        return 0;
}





int file_server_standalone(regex_list_t *list, lml_queue_t *queue) 
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













