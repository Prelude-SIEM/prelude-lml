/*****
*
* Copyright (C) 1998 - 2003 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <time.h>
#include <sys/uio.h>

#include "config.h"

#ifdef HAVE_FAM 
 #include <fam.h>
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


#define MIN(x, y) ( ((x) < (y)) ? (x) : (y) )
#define MAX(x, y) ( ((x) > (y)) ? (x) : (y) )



#define STDIN_FILENAME "stdin"


/*
 * If we get more than ROTATION_MAX_DIFFERENCE seconds
 * of difference between the time the logfile is rotated,
 * and a third rotation, issue an alert.
 */
#define DEFAULT_ROTATION_INTERVAL_MAX_DIFFERENCE 1800


/*
 * Logfile metadata stuff.
 */
#define METADATA_MAXSIZE 8192
#define METADATA_DIR     CONFIG_DIR"/metadata"


#define LOGFILE_DELETION_CLASS "Logfile deletion"
#define LOGFILE_DELETION_IMPACT "An attacker might have erased the logfile,"               \
                                "or a log rotation program may have rotated the logfile."

#define LOGFILE_DELETION_IMPACT_HIGH "An attacker seems to have erased the logfile, "      \
                                     "and the change doesn't seem to be related to a log " \
                                     "rotation program." 

#define LOGFILE_MODIFICATION_CLASS "Logfile inconsistency"
#define LOGFILE_MODIFICATION_IMPACT "An attacker might have modified the logfile in order " \
                                    "to remove the trace he left."



typedef struct {
        FILE *fd;
        FILE *metadata_fd;

        time_t last_rotation;
        time_t rotation_average;
        
        char *file;
        int index;
        char buf[1024];

        off_t need_more_read;
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
static int rotation_interval_max_difference = DEFAULT_ROTATION_INTERVAL_MAX_DIFFERENCE;



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





static void logfile_modified_alert(monitor_fd_t *monitor, struct stat *st) 
{
        idmef_impact_t impact;
        idmef_classification_t class;

        memset(&class, 0, sizeof(class));
        memset(&impact, 0, sizeof(impact));
        
        class.origin = origin_unknown;
        idmef_string_set_constant(&class.name, LOGFILE_MODIFICATION_CLASS);
        
        impact.type = file;
        impact.completion = succeeded;
        impact.severity = impact_high;
        idmef_string_set_constant(&impact.description, LOGFILE_MODIFICATION_IMPACT);
        
        logfile_alert(monitor, st, &class, &impact);
}




static int file_metadata_read(monitor_fd_t *monitor, off_t *start, char **sumline)
{
        int line = 0;
        char buf[METADATA_MAXSIZE], *offptr;

        rewind(monitor->metadata_fd);

        *start = 0;
        *sumline = NULL;
        
        if ( ! fgets(buf, sizeof(buf), monitor->metadata_fd) )
                return 0;
        
        offptr = strchr(buf, ':');
        if ( ! offptr ) {
                log(LOG_ERR, "%s: Invalid metadata file.\n", monitor->file, line);
                return ftruncate(fileno(monitor->metadata_fd), 0);
        }

        *offptr++ = '\0';

        *start = strtoull(buf, NULL, 10);
        *sumline = offptr;

        return 0;
}




static int file_metadata_save(monitor_fd_t *monitor, off_t offset) 
{
        int len, ret;
        char buf[METADATA_MAXSIZE];
        
        len = snprintf(buf, sizeof(buf), "%llu:%s\n", offset, monitor->buf);
        if ( len >= sizeof(buf) || len < 0 )
                return -1;
        
        rewind(monitor->metadata_fd);

        ret = ftruncate(fileno(monitor->metadata_fd), 0);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't truncate metadata file.\n");
                return -1;
        }
        
        ret = fwrite(buf, 1, len, monitor->metadata_fd);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't write out metadata.\n");
                return -1;
        }
        
        return 0;
}



static int file_metadata_get_position(monitor_fd_t *monitor) 
{
        off_t offset;
        struct stat st;
        char buf[1024], *sumline;
        int ret, have_metadata = 0;
        
        ret = file_metadata_read(monitor, &offset, &sumline);
        if ( ret == 0 && (offset || sumline) )
                have_metadata = 1;
        
        ret = fstat(fileno(monitor->fd), &st);
        if ( ret < 0 ) {
                log(LOG_ERR, "stat: error on file %s.\n", monitor->file);
                return -1;
        }
        
        monitor->last_mtime = st.st_mtime;

        if ( ! have_metadata ) {
                log(LOG_INFO, "- %s: No metadata available.\n", monitor->file);
                monitor->last_size = st.st_size;
                return fseek(monitor->fd, st.st_size, SEEK_SET);;
        }

        if ( st.st_size < offset ) {
                log(LOG_INFO, "- %s: Metadata available, but logfile got rotated, starting at 0.\n", monitor->file);
                logfile_modified_alert(monitor, &st);
                return 0;
        }
        
        ret = fseek(monitor->fd, offset, SEEK_SET);
        if ( ret < 0 ) {
                log(LOG_ERR, "- %s: couldn't seek to byte %llu.\n", monitor->file, offset);
                return -1; 
        }
        
        if ( ! fgets(buf, sizeof(buf), monitor->fd) || strcmp(buf, sumline) != 0 ) {
                log(LOG_INFO, "- %s: Metadata available, but checksum is invalid, starting at 0.\n", monitor->file);
                logfile_modified_alert(monitor, &st);
                return fseek(monitor->fd, 0, SEEK_SET);
        }
                
        monitor->last_size = offset + strlen(sumline);
        log(LOG_INFO, "- %s: Metadata available, starting log analyzis at offset %llu.\n", monitor->file, monitor->last_size);
        
        return 0;
}




static int file_metadata_open(monitor_fd_t *monitor) 
{
        int ret;
        char file[FILENAME_MAX], path[FILENAME_MAX], *ptr;

        strncpy(file, monitor->file, sizeof(file));

        while ( (ptr = strchr(file, '/')) )
                *ptr = '-'; /* strip */

        snprintf(path, sizeof(path), "%s/%s", METADATA_DIR, file);        

        ret = open(path, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
        if ( ret < 0 && errno != EEXIST ) {
                log(LOG_ERR, "error creating %s.\n", path);
                return -1;
        }

        monitor->metadata_fd = fdopen(ret, "r+");
        if ( ! monitor->metadata_fd ) {
                log(LOG_ERR, "fdopen failed.\n");
                return -1;
        }

        return 0;
}




/*
 * This function return -1 if it couldn't read a full syslog line.
 *
 * The size of the whole syslog line is returned otherwise (not only what
 * has been read uppon this call).
 *
 * rlen is always updated to reflect how many byte has been read.
 */
static off_t read_logfile(monitor_fd_t *fd, off_t available, off_t *rlen) 
{
        int ret, len, i = 0;

        if ( available == 0 ) {
                *rlen = 0;
                return -1;
        }
        
        len = fd->index;
        
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
                        *rlen = i;
                        clearerr(fd->fd);
                        return -1;
                }

                i++;
                len++;
                
                if ( ret == '\n' ) {
                        fd->buf[fd->index] = '\0';
                        break;
                }
                
                fd->buf[fd->index++] = (char) ret;
                
                if ( i == available ) {
                        *rlen = i;
                        return -1;
                }
        }

        /*
         * sucess.
         */
        *rlen = i;
        fd->index = 0;
        
        return len;        
}




static void check_logfile_data(regex_list_t *list, monitor_fd_t *monitor, struct stat *st) 
{
        off_t len, ret, rlen;
        
        if ( ! monitor->need_more_read && st->st_size == monitor->last_size ) 
                return;

        if ( st->st_size < monitor->last_size ) {
                monitor->last_size = 0;
                rewind(monitor->fd);
        }
        
        len = (st->st_size - monitor->last_size) + monitor->need_more_read;
        monitor->last_size = st->st_size;
        
        while ( (ret = read_logfile(monitor, len, &rlen)) != -1 ) {

                lml_dispatch_log(list, monitor->buf, monitor->file);
                file_metadata_save(monitor, st->st_size - len);
                
                len -= rlen;
        }

        /*
         * if len isn't 0, it mean we got EOF before reading every new byte,
         * we want to retry reading even if st_size isn't modified then.
         */
        monitor->need_more_read = len - rlen;
        
        if ( monitor->need_more_read ) {
                log(LOG_INFO,
                    "If you hit this point, please contact the Prelude mailing list\n" \
                    "and include the following information in your report: st_size=%llu\n" \
                    "remaining=%llu, rlen=%llu, len=%llu\n",
                    st->st_size, monitor->need_more_read, rlen, len);

                abort();
        }
}




static monitor_fd_t *monitor_new(const char *file) 
{
        int ret;
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

        ret = file_metadata_open(new);
        if ( ret < 0 ) {
                free(new->file);
                free(new);
                return NULL;
        }
        
        list_add(&new->list, &inactive_fd_list);

        return new;
}



#if 0
static void monitor_destroy(monitor_fd_t *monitor) 
{
        if ( monitor->fd )
                fclose(monitor->fd);
        
        list_del(&monitor->list);

        free(monitor->file);
        
        free(monitor);
}
#endif



static int monitor_open(monitor_fd_t *monitor) 
{
        int ret;
        
#ifdef HAVE_FAM
        ret = fam_setup_monitor(monitor);
        if ( ret < 0 )
                return -1;
#endif
        
        if ( strcmp(monitor->file, STDIN_FILENAME) == 0 )
                monitor->fd = stdin;
        else {
                monitor->fd = fopen(monitor->file, "r");
                if ( ! monitor->fd )
                        return -1;

                ret = file_metadata_get_position(monitor);
                if ( ret < 0 )
                        return -1;
        }
        
        monitor->index = 0;
        monitor->need_more_read = 0;
        
        list_del(&monitor->list);
        list_add_tail(&monitor->list, &active_fd_list);

        return 0;
}




static void try_reopening_inactive_monitor(void) 
{
        struct list_head *tmp, *bkp;

        list_for_each_safe(tmp, bkp, &inactive_fd_list) 
                monitor_open(list_entry(tmp, monitor_fd_t, list));
}




/*
 * This won't protect against replacement of log entry by garbage,
 * Unfortunnaly, there is no way it can be done cleanly, or it would
 * cause heavy performance problem. The best solution may be to centralize
 * the logging on a remote host.
 */
static void check_modification_time(monitor_fd_t *monitor, struct stat *st) 
{
        time_t old_mtime = monitor->last_mtime;

        monitor->last_mtime = st->st_mtime;
        
        if ( st->st_mtime >= old_mtime && st->st_size >= monitor->last_size ) 
                return; /* everythings sound okay */

        logfile_modified_alert(monitor, st);
}




static int is_normal_log_rotation(monitor_fd_t *monitor, struct stat *st)
{
        int ret = 0;
        time_t diff, now, rtt;
              
        now = time(NULL);
        diff = now - monitor->last_rotation;
        
        rtt = MAX(monitor->rotation_average, diff) - MIN(monitor->rotation_average, diff);
              
        if ( monitor->rotation_average && rtt > rotation_interval_max_difference )
                ret = -1;

        if ( monitor->last_rotation )
                monitor->rotation_average = diff;
        
        monitor->last_rotation = now;
        
        return ret;
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
        monitor->fd = NULL;
        
        list_del(&monitor->list);
        list_add_tail(&monitor->list, &inactive_fd_list);

        log(LOG_INFO, "logfile %s reached 0 hard link.\n", monitor->file);

        memset(&class, 0, sizeof(class));
        memset(&impact, 0, sizeof(impact));
        
        class.origin = origin_unknown;
        idmef_string_set_constant(&class.name, LOGFILE_DELETION_CLASS);

        impact.type = file;
        impact.completion = succeeded;

        if ( is_normal_log_rotation(monitor, st) == 0 ) {
                impact.severity = impact_medium;
                idmef_string_set_constant(&impact.description, LOGFILE_DELETION_IMPACT);
        } else {
                impact.severity = impact_high;
                idmef_string_set_constant(&impact.description, LOGFILE_DELETION_IMPACT_HIGH);
        }
                
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
        char teststring[] = "testfam";

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

	iov[0].iov_len = sizeof(teststring);
	iov[0].iov_base = teststring;
        
	ret = writev(fd, iov, 1);
	if ( ret != sizeof(teststring) ) {
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

        if ( ! monitor->fd ) {
                if ( event->code == FAMCreated )  
                        return monitor_open(monitor);
                else
                        /*
                         * sometime it happen that FAM notify us
                         * several time for FAMDeleted event. Which would
                         * result in a crash without this check.
                         */
                        return -1;
        }

        ret = fstat(fileno(monitor->fd), &st);
        if ( ret < 0 )
                log(LOG_ERR, "fstat returned an error.\n");
        
        switch (event->code) {
                
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
        monitor_fd_t *new;
        
        /*
         * Don't open the monitor right now,
         * we want all unread bytes to be processed before activating
         * FAM notification (if enabled).
         */
        
        new = monitor_new(file);
        if ( ! new )
                return -1;
        
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




void file_server_set_rotation_interval_max_difference(int val) 
{
        rotation_interval_max_difference = val;
}




void file_server_start_monitoring(regex_list_t *list)
{
        /*
         * Initialize everythings once by calling file_server_wake_up().
         */
        file_server_wake_up(list);
}
