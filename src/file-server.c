/*****
*
* Copyright (C) 1998 - 2003 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <sys/uio.h>

#include "config.h"

#ifdef HAVE_FAM 
 #include <fam.h>

 #define FAM_FILENAME "testfam.tmp"
 #define FAM_STRING "test string\n"
#endif

#include <libprelude/timer.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>
#include <libprelude/prelude-message.h>

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

#ifdef HAVE_FAM
        FAMRequest fam_request;
#endif
        
} monitor_fd_t;


#ifdef HAVE_FAM

static int fam_setup_monitor(monitor_fd_t *monitor);
static FAMConnection fc;

#endif


static int fam_initialized = 0;
static LIST_HEAD(active_fd_list);
static LIST_HEAD(inactive_fd_list);



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
        snprintf(buf, sizeof(buf), "%s", fd->file);

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




static void check_logfile_data(regex_list_t *list, monitor_fd_t *monitor, struct stat *st) 
{
        int len, ret;
        
        if ( ! monitor->need_more_read && st->st_size == monitor->last_size ) 
                return;
        
        len = (st->st_size - monitor->last_size) + monitor->need_more_read;
        monitor->last_size = st->st_size;

        while ( (ret = read_logfile(monitor)) != -1 ) {
                len -= ret;                
                lml_dispatch_log(list, monitor->buf, monitor->file);
        }

        /*
         * if len isn't 0, it mean we got EOF before reading every new byte,
         * we want to retry reading even if st_size isn't modified then.
         */
        monitor->need_more_read = len;
}




static monitor_fd_t *monitor_new(const char *file) 
{
        monitor_fd_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->file = strdup(file);
        if ( ! new->file ) {
                log(LOG_ERR, "memory exhausted.\n");
                free(new);
                return NULL;
        }

        list_add(&new->list, &inactive_fd_list);

        return new;
}




static void monitor_destroy(monitor_fd_t *monitor) 
{
        if ( monitor->fd )
                fclose(monitor->fd);
        
        list_del(&monitor->list);

        free(monitor->file);
        
        free(monitor);
}




static int monitor_open(monitor_fd_t *monitor, int start_from_zero) 
{
        int ret;
        struct stat st;
        
#ifdef HAVE_FAM
        ret = fam_setup_monitor(monitor);
        if ( ret < 0 )
                return -1;
#endif
        
        monitor->fd = fopen(monitor->file, "r");
        if ( ! monitor->fd )
                return -1;
        
        monitor->index = 0;
        monitor->need_more_read = 0;
        
        if ( start_from_zero )                 
                monitor->last_size = 0;
        else {
                ret = fseek(monitor->fd, 0, SEEK_END);
                if ( ret < 0 ) {
                        log(LOG_ERR, "couldn't seek to the end of the file.\n");
                        monitor_destroy(monitor);
                        return -1;
                }
        }
        
        list_del(&monitor->list);
        list_add_tail(&monitor->list, &active_fd_list);
        
        ret = fstat(fileno(monitor->fd), &st);
        if ( ret < 0 ) {
                log(LOG_ERR, "stat: error on file %s.\n", monitor->file);
                return -1;
        }
                
        monitor->last_size = (start_from_zero) ? 0 : st.st_size;
        monitor->last_mtime = st.st_mtime;

        return 0;
}




static void try_reopening_inactive_monitor(void) 
{
        struct list_head *tmp, *bkp;

        list_for_each_safe(tmp, bkp, &inactive_fd_list) 
                monitor_open(list_entry(tmp, monitor_fd_t, list), 1);
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
        
        if ( st->st_mtime >= old_mtime && st->st_size >= fd->last_size ) 
                return; /* everythings sound okay */
        
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




#ifdef HAVE_FAM

static int get_expected_event(FAMConnection *fc, int eventno)
{
	int ret;
	fd_set fds;
	FAMEvent event;
	struct timeval tv;

	FD_ZERO(&fds);
	FD_SET(fc->fd, &fds);

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	while ( ! FAMPending(fc) ) {
                ret = select(fc->fd + 1, &fds, NULL, NULL, &tv);
		if ( ret <= 0 )
			return -1;
	}

	/*
	 * Wait for the notification started event.
	 */
	ret = FAMNextEvent(fc, &event);
        if ( ret < 0 || event.code != eventno ) 
                return -1;

	return 0;
}



static int check_fam_writev_bug(FAMConnection *fc)
{
	int ret, fd;
	FAMRequest fr;
        char buf[1024];
	struct iovec iov[1];

        snprintf(buf, sizeof(buf), "%s/testfam.XXXXXX", P_tmpdir);

        ret = mkstemp(buf);        
        if ( ret < 0 ) {
                log(LOG_ERR, "error creating unique temporary filename.\n");
                return -1;
        }
        
	fd = open(buf, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);
	if ( fd < 0 ) {
		log(LOG_ERR, "error opening %s for writing.\n", buf);
		return -1;
	}
        
	ret = FAMMonitorFile(fc, buf, &fr, NULL);
	if ( ret < 0 ) {
                log(LOG_ERR, "error creating FAM monitor for %s: %s.\n", buf, FamErrlist[FAMErrno]);
                close(fd);
                return -1;
	}

	ret = get_expected_event(fc, FAMExists);
	if ( ret < 0 )
		goto err;

	ret = get_expected_event(fc, FAMEndExist);
	if ( ret < 0 )
                goto err;

	iov[0].iov_len = sizeof(FAM_STRING);
	iov[0].iov_base = FAM_STRING;
        
	ret = writev(fd, iov, 1);
	if ( ret != sizeof(FAM_STRING) ) {
		log(LOG_ERR, "error writing test string to %s: %s.\n", buf);
		goto err;
	}
	
	ret = get_expected_event(fc, FAMChanged);
	if ( ret < 0 )
                goto err;
        
 err:
        FAMCancelMonitor(fc, &fr);
        get_expected_event(fc, FAMAcknowledge);        

        close(fd);
        unlink(buf);

        return ret;
}



static int initialize_fam(void) 
{
        if ( fam_initialized != 0 )
                return fam_initialized;
        
        fam_initialized = FAMOpen(&fc);
        if ( fam_initialized < 0 ) {
                log(LOG_ERR, "error initializing FAM: %s.\n", FamErrlist[FAMErrno]);
                return -1;
        }

        log(LOG_INFO, "- Checking for FAM writev() bug...\n");
        
        fam_initialized = check_fam_writev_bug(&fc);
        if ( fam_initialized < 0 ) {
                FAMClose(&fc);
                
                log(LOG_INFO, "- An OS bug prevent FAM from monitoring writev() file modification: disabling FAM.\n");
                return -1;
        }

        log(LOG_INFO, "- FAM working nicely, enabling.\n");
        
        fam_initialized = 1;

        return 0;
}



static int fam_setup_monitor(monitor_fd_t *monitor)
{
        int ret;

        ret = initialize_fam();
        if ( ret < 0 )
                return 0;
        
        ret = FAMMonitorFile(&fc, monitor->file, &monitor->fam_request, monitor);
        if ( ret < 0 ) {
                log(LOG_ERR, "error creating FAM monitor for %s: %s.\n", monitor->file, FamErrlist[FAMErrno]);
                return -1;
        }
        
        return 0;
}



static int fam_process_event(regex_list_t *list, FAMEvent *event) 
{
        int ret = 0;
        struct stat st;
        monitor_fd_t *monitor = event->userdata;

        ret = fstat(fileno(monitor->fd), &st);
        if ( ret < 0 )
                log(LOG_ERR, "fstat returned an error.\n");
        
        switch (event->code) {

        case FAMCreated:
                monitor_open(monitor, 1);
                break;
                
        case FAMChanged:                
                /*
                 * check mtime consistency.
                 */ 
                check_modification_time(monitor, &st);
        
                /*
                 * read and analyze available data. 
                 */
                check_logfile_data(list, monitor, &st);
                break;
                
        case FAMDeleted:
                ret = is_file_already_used(monitor, &st);
                break;

        case FAMExists:
        case FAMEndExist:
                /*
                 * This happen when a monitor is created.
                 */
                return 0;
                
        default:
                return -1;
        }

        return ret;
}




static int fam_process_queued_events(regex_list_t *list) 
{
        int ret;
        FAMEvent event;
        
        while ( FAMPending(&fc) ) {

                ret = FAMNextEvent(&fc, &event);
                if ( ret < 0 ) {
                        log(LOG_ERR, "error while getting FAM event: %s.\n", FamErrlist[FAMErrno]);
                        return -1;
                }

                fam_process_event(list, &event);
        }

        return 0;
}
#endif



static int process_file_event(regex_list_t *list, monitor_fd_t *monitor) 
{
        int ret;
        struct stat st;
        
        ret = fstat(fileno(monitor->fd), &st);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't fstat '%s'.\n", monitor->file);
                return -1;
        }
        
        ret = is_file_already_used(monitor, &st);
        if ( ret < 0 )
                return -1;
        
        /*
         * check mtime consistency.
         */ 
        check_modification_time(monitor, &st);
        
        /*
         * read and analyze available data. 
         */
        check_logfile_data(list, monitor, &st);

        return 0;
}




int file_server_monitor_file(const char *file) 
{
        int ret;
        monitor_fd_t *new;

        new = monitor_new(file);
        if ( ! new )
                return -1;

        ret = monitor_open(new, 0);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't open %s.\n", file);
                return -1;
        }
        
        if ( ! new->fd )
                return 0;
        
        return 0;
}



int file_server_wake_up(regex_list_t *list) 
{
        monitor_fd_t *monitor;
        struct list_head *tmp, *bkp;
        
        if ( fam_initialized != 1 ) {
                /*
                 * try to open inactive fd (file was not existing previously).
                 */
                try_reopening_inactive_monitor();
                
                list_for_each_safe(tmp, bkp, &active_fd_list) {
                        monitor = list_entry(tmp, monitor_fd_t, list);
                        process_file_event(list, monitor);
                }
        }
        
#ifdef HAVE_FAM
        else 
                return fam_process_queued_events(list);
#endif
        
        return 0;
}




int file_server_get_event_fd(void) 
{
#ifdef HAVE_FAM
        if ( fam_initialized == 1 )
                return FAMCONNECTION_GETFD(&fc);
#endif
        
        return -1;
}


















