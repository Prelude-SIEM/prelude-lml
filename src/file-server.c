/*****
*
* Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-LML program.
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
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/uio.h>

#include "config.h"
#include "libmissing.h"

#ifdef HAVE_FAM 
 #include <fam.h>
#endif

#include <libprelude/prelude.h>
#include <libprelude/prelude-timer.h>
#include <libprelude/prelude-log.h>

#include "prelude-lml.h"
#include "regex.h"
#include "common.h"
#include "log-entry.h"
#include "file-server.h"
#include "lml-alert.h"


#define MIN(x, y) ( ((x) < (y)) ? (x) : (y) )
#define MAX(x, y) ( ((x) > (y)) ? (x) : (y) )



#define STDIN_FILENAME "-"


/*
 * If we get more than ROTATION_MAX_DIFFERENCE seconds/size
 * of difference between different logfile rotation, issue an alert.
 */
#define DEFAULT_MAX_ROTATION_SIZE_OFFSET     1024
#define DEFAULT_MAX_ROTATION_TIME_OFFSET     (5 * 60)


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
        prelude_list_t list;
        
        lml_log_source_t *source;
        
        FILE *fd;
        FILE *metadata_fd;

        off_t last_rotation_size;
        time_t last_rotation_time;
        time_t last_rotation_time_interval;
        
        int index;
        char buf[1024];

        off_t need_more_read;
        off_t last_size;

        time_t last_mtime;
        
#ifdef HAVE_FAM
        FAMRequest fam_request;
#endif

        regex_list_t *regex_list;
} monitor_fd_t;




#ifdef HAVE_FAM

static int fam_setup_monitor(monitor_fd_t *monitor);
static FAMConnection fc;

#endif



static int batch_mode = 0;
static int fam_initialized = 0;
static int ignore_metadata = 0;
static PRELUDE_LIST(active_fd_list);
static PRELUDE_LIST(inactive_fd_list);
static unsigned int max_rotation_size_offset = DEFAULT_MAX_ROTATION_SIZE_OFFSET;
static unsigned int max_rotation_time_offset = DEFAULT_MAX_ROTATION_TIME_OFFSET;



static void logfile_alert(monitor_fd_t *fd, struct stat *st,
                          idmef_classification_t *classification, idmef_impact_t *impact)
{
        int ret;
        char buf[256], *ptr;
        idmef_file_t *file;
        idmef_time_t *time;
        idmef_inode_t *inode;
        lml_log_entry_t *log_entry;
        idmef_alert_t *alert;
        idmef_target_t *target;
        idmef_message_t *message;
        idmef_assessment_t *assessment;
        prelude_string_t *string;
        
        log_entry = lml_log_entry_new();
        if ( ! log_entry )
                return;
        
        ret = idmef_message_new(&message);
        if ( ret < 0 ) {
                lml_log_entry_destroy(log_entry);
                return;
        }

        /*
         * Initialize the idmef structures
         */
        ret = idmef_message_new_alert(message, &alert);
        if ( ret < 0 )
                goto err;

        ret = idmef_alert_new_target(alert, &target, -1);
        if ( ret < 0 )
                goto err;

        ret = idmef_target_new_file(target, &file, -1);
        if ( ret < 0 ) 
                goto err;

        idmef_file_set_category(file, IDMEF_FILE_CATEGORY_CURRENT);
        idmef_file_set_data_size(file, st->st_size);

        ret = idmef_file_new_inode(file, &inode);
        if ( ret < 0 )
                goto err;

        idmef_inode_set_number(inode, st->st_ino);
        snprintf(buf, sizeof(buf), "%s", lml_log_source_get_name(fd->source));

        ptr = strrchr(buf, '/');
        if ( ptr ) {
                *ptr = '\0';

                ret = idmef_file_new_name(file, &string);
                if ( ret < 0 )
                        goto err;
                
                prelude_string_set_ref(string, ptr + 1);
        }

        ret = idmef_file_new_path(file, &string);
        if ( ret < 0 )
                goto err;
        prelude_string_set_ref(string, buf);

        ret = idmef_file_new_access_time(file, &time);
        if ( ret < 0 )
                goto err;
        
        idmef_time_set_sec(time, st->st_atime);

        ret = idmef_file_new_modify_time(file, &time);
        if ( ret < 0 )
                goto err;

        idmef_time_set_sec(time, st->st_mtime);

        ret = idmef_alert_new_assessment(alert, &assessment);
        if ( ret < 0 )
                goto err;
        
        idmef_assessment_set_impact(assessment, impact);
        idmef_alert_set_classification(alert, classification);
        
        lml_alert_emit(fd->source, log_entry, message);
        
        lml_log_entry_destroy(log_entry);
        
        return;
        
 err:
        lml_log_entry_destroy(log_entry);
        idmef_message_destroy(message);
}





static void logfile_modified_alert(monitor_fd_t *monitor, struct stat *st) 
{
        int ret;
        prelude_string_t *str;
        idmef_impact_t *impact;
        idmef_classification_t *classification;
        
        ret = idmef_impact_new(&impact);
        if ( ret < 0 )
                return;
        
        ret = idmef_classification_new(&classification);
        if ( ret < 0 ) {
                idmef_impact_destroy(impact);
                return;
        }
        
        ret = idmef_classification_new_text(classification, &str);
        if ( ret < 0 ) {
                idmef_impact_destroy(impact);
                idmef_classification_destroy(classification);
                return;
        }
        
        prelude_string_set_constant(str, LOGFILE_MODIFICATION_CLASS);
        
        idmef_impact_set_type(impact, IDMEF_IMPACT_TYPE_FILE);
        idmef_impact_set_completion(impact, IDMEF_IMPACT_COMPLETION_SUCCEEDED);
        idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_HIGH);
        
        ret = idmef_impact_new_description(impact, &str);
        if ( ret < 0 ) {
                idmef_impact_destroy(impact);
                idmef_classification_destroy(classification);
                return;
        }
        prelude_string_set_constant(str, LOGFILE_MODIFICATION_IMPACT);
        
        logfile_alert(monitor, st, classification, impact);
}




static int file_metadata_read(monitor_fd_t *monitor, off_t *start, char **sumline, size_t size)
{
        int line = 0, ret;
        char *offptr, *buf;

        if ( ignore_metadata )
                return 0;

        rewind(monitor->metadata_fd);

        *start = 0;
        buf = *sumline;
        *sumline = NULL;
        
        if ( ! fgets(buf, size, monitor->metadata_fd) )
                return -1;
        
        offptr = strchr(buf, ':');
        if ( ! offptr ) {
                prelude_log(PRELUDE_LOG_WARN, "%s: Invalid metadata file.\n", lml_log_source_get_name(monitor->source), line);
                ftruncate(fileno(monitor->metadata_fd), 0);
                return -1;
        }

        *offptr++ = '\0';

        ret = sscanf(buf, "%" SCNu64, start);
        if ( ret != 1 ) {
                prelude_log(PRELUDE_LOG_WARN, "error reading metadata file offset.\n");
                return -1;
        }
        
        *sumline = offptr;

        return 0;
}




static int file_metadata_save(monitor_fd_t *monitor, off_t offset) 
{
        int len, ret;
        char buf[METADATA_MAXSIZE];

        if ( ignore_metadata )
                return 0;
        
        len = snprintf(buf, sizeof(buf), "%" PRELUDE_PRIu64 ":%s\n", offset, monitor->buf);
        if ( len >= sizeof(buf) || len < 0 )
                return -1;
        
        rewind(monitor->metadata_fd);

        ret = ftruncate(fileno(monitor->metadata_fd), 0);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't truncate metadata file.\n");
                return -1;
        }
        
        ret = fwrite(buf, 1, len, monitor->metadata_fd);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't write out metadata.\n");
                return -1;
        }
        
        return 0;
}



static int file_metadata_get_position(monitor_fd_t *monitor) 
{
        off_t offset;
        struct stat st;
        const char *filename;
        int ret, have_metadata = 0;
        char buf[1024], sumline[METADATA_MAXSIZE], *sumptr;

        if ( ignore_metadata )
                return 0;

        sumptr = sumline;
        filename = lml_log_source_get_name(monitor->source);
        
        ret = file_metadata_read(monitor, &offset, &sumptr, sizeof(sumline));
        if ( ret == 0 )
                have_metadata = 1;
        
        ret = fstat(fileno(monitor->fd), &st);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "stat: error on file %s.\n", filename);
                return -1;
        }

        monitor->last_size = st.st_size;
        monitor->last_mtime = st.st_mtime;

        if ( ! have_metadata ) {
                prelude_log(PRELUDE_LOG_INFO, "- %s: No metadata available.\n", filename);
                return fseek(monitor->fd, st.st_size, SEEK_SET);;
        }

        if ( st.st_size < offset ) {
                prelude_log(PRELUDE_LOG_INFO, "- %s: Metadata available, but logfile got rotated, starting at 0.\n", filename);
                monitor->last_size = 0;
                return 0;
        }
        
        ret = fseek(monitor->fd, offset, SEEK_SET);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "- %s: couldn't seek to byte %" PRELUDE_PRIu64 ".\n", filename, offset);
                return -1; 
        }

        if ( ! fgets(buf, sizeof(buf), monitor->fd) || strcmp(buf, sumptr) != 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "- %s: Metadata available, but checksum is invalid, starting at 0.\n", filename);
                logfile_modified_alert(monitor, &st);
                monitor->last_size = 0;
                return fseek(monitor->fd, 0, SEEK_SET);
        }
                
        monitor->last_size = offset;
        monitor->last_size += strlen(sumptr);
        
        prelude_log(PRELUDE_LOG_INFO, "- %s: Metadata available, starting log analyzis at offset %" PRELUDE_PRIu64 ".\n",
                    filename, monitor->last_size);
        
        return 0;
}




static int file_metadata_open(monitor_fd_t *monitor) 
{
        int ret;
        char file[FILENAME_MAX], path[FILENAME_MAX], *ptr;

        if ( ignore_metadata )
                return 0;

        strncpy(file, lml_log_source_get_name(monitor->source), sizeof(file));

        while ( (ptr = strchr(file, '/')) )
                *ptr = '-'; /* strip */

        snprintf(path, sizeof(path), "%s/%s", METADATA_DIR, file);        

        ret = open(path, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
        if ( ret < 0 && errno != EEXIST ) {
                prelude_log(PRELUDE_LOG_ERR, "error creating %s.\n", path);
                return -1;
        }

        monitor->metadata_fd = fdopen(ret, "r+");
        if ( ! monitor->metadata_fd ) {
                prelude_log(PRELUDE_LOG_ERR, "fdopen failed.\n");
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
                        prelude_log(PRELUDE_LOG_WARN, "line too long (syslog specify 1024 characters max).\n");
                        break;
                }

                ret = getc(fd->fd);
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




static int check_logfile_data(monitor_fd_t *monitor, struct stat *st) 
{
        int eventno = 0;
        off_t len, ret, rlen;
        
        if ( ! monitor->need_more_read && st->st_size == monitor->last_size ) 
                return 0;

        if ( st->st_size < monitor->last_size ) {
                monitor->last_size = 0;
                rewind(monitor->fd);
        }
        
        len = (st->st_size - monitor->last_size) + monitor->need_more_read;
        monitor->last_size = st->st_size;
        
        while ( (ret = read_logfile(monitor, len, &rlen)) != -1 ) {
                eventno++;
                lml_dispatch_log(monitor->regex_list, monitor->source, monitor->buf, ret);
                file_metadata_save(monitor, st->st_size - len);
                
                len -= rlen;
        }

        /*
         * if len isn't 0, it mean we got EOF before reading every new byte,
         * we want to retry reading even if st_size isn't modified then.
         */
        monitor->need_more_read = len - rlen;
        
        if ( monitor->need_more_read ) {
                prelude_log(PRELUDE_LOG_WARN,
                            "If you hit this point, please contact the Prelude mailing list\n"            \
                            "and include the following information in your report: st_size=%" PRELUDE_PRIu64 "\n" \
                            "remaining=%" PRELUDE_PRIu64 ", rlen=%" PRELUDE_PRIu64 ", len=%" PRELUDE_PRIu64 "\n",
                            st->st_size, monitor->need_more_read, rlen, len);

                abort();
        }

        return eventno;
}




static monitor_fd_t *monitor_new(lml_log_source_t *ls) 
{
        int ret;
        monitor_fd_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->source = ls;

        ret = file_metadata_open(new);
        if ( ret < 0 ) {
                free(new);
                return NULL;
        }
    
#ifdef HAVE_FAM
        ret = fam_setup_monitor(new);
        if ( ret < 0 )
                return NULL;
#endif
            
        prelude_list_add(&inactive_fd_list, &new->list);

        return new;
}



#if 0
static void monitor_destroy(monitor_fd_t *monitor) 
{
        if ( monitor->fd )
                fclose(monitor->fd);
        
        prelude_list_del(&monitor->list);

        free(monitor->file);
        
        free(monitor);
}
#endif



static int monitor_open(monitor_fd_t *monitor) 
{
        int ret;
        const char *filename;

        filename = lml_log_source_get_name(monitor->source);
        
        if ( strcmp(filename, STDIN_FILENAME) == 0 )
                monitor->fd = stdin;
        else {
                monitor->fd = fopen(filename, "r");
                if ( ! monitor->fd ) 
                        return -1;

                ret = file_metadata_get_position(monitor);
                if ( ret < 0 )
                        return -1;
        }
        
        monitor->index = 0;
        monitor->need_more_read = 0;
        
        prelude_list_del(&monitor->list);
        prelude_list_add_tail(&active_fd_list, &monitor->list);

        return 0;
}



static void monitor_close(monitor_fd_t *monitor)
{
        fclose(monitor->fd);
        monitor->fd = NULL;
        prelude_list_del(&monitor->list);
        prelude_list_add_tail(&inactive_fd_list, &monitor->list);
}



static void try_reopening_inactive_monitor(void) 
{
        prelude_list_t *tmp, *bkp;

        prelude_list_for_each_safe(&inactive_fd_list, tmp, bkp) 
                monitor_open(prelude_list_entry(tmp, monitor_fd_t, list));
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


static int get_rotation_size_offset(monitor_fd_t *monitor, struct stat *st)
{
        off_t diff;
        int prev = 0;
        
        diff = MAX(monitor->last_rotation_size, st->st_size) - 
               MIN(monitor->last_rotation_size, st->st_size);
      
        if ( monitor->last_rotation_size )
                prev = 1;
        
        monitor->last_rotation_size = st->st_size;
        
        return prev ? diff : 0;
}


static int get_rotation_time_offset(monitor_fd_t *monitor, struct stat *st)
{
        int prev = 0;
        time_t interval, now, offset;
              
        now = time(NULL);
        interval = now - monitor->last_rotation_time;
        
        offset = MAX(monitor->last_rotation_time_interval, interval) - 
                 MIN(monitor->last_rotation_time_interval, interval);

        if ( monitor->last_rotation_time ) {
                prev = 1;
                monitor->last_rotation_time_interval = interval;
        }
        
        monitor->last_rotation_time = now;
        
        return prev ? offset : 0;
}



static int is_file_already_used(monitor_fd_t *monitor, struct stat *st)
{
        int ret;
        char buf[1024];
        int toff, soff;
        struct stat st_new;
        const char *filename;
        idmef_impact_t *impact;
        idmef_classification_t *classification;
        prelude_string_t *str;
        
        filename = lml_log_source_get_name(monitor->source);
        
        /*
         * test if the file has been removed
         */
        if ( st->st_nlink > 0 ) {
                if ( stat(filename, &st_new) == 0 ) {
                        /*
                         * test if the file has been renamed
                         */
                        if ( st->st_ino == st_new.st_ino ) 
                                return 0;
                       
                        fclose(monitor->fd);
                        monitor_open(monitor);
                } 
                else monitor_close(monitor);
                prelude_log(PRELUDE_LOG_INFO, "- logfile %s has been renamed.\n", filename);
        } else {
                prelude_log(PRELUDE_LOG_INFO, "- logfile %s reached 0 hard link.\n", filename);
                monitor_close(monitor);
        }
        
        ret = idmef_classification_new(&classification);
        if ( ret < 0 )
                return -1;
        
        ret = idmef_impact_new(&impact);
        if ( ret < 0 ) {
                idmef_classification_destroy(classification);
                return -1;
        }
        
        ret = idmef_classification_new_text(classification, &str);
        if ( ret < 0 ) {
                idmef_impact_destroy(impact);
                idmef_classification_destroy(classification);
                return -1;
        }
        prelude_string_set_constant(str, LOGFILE_DELETION_CLASS);
        
        idmef_impact_set_type(impact, IDMEF_IMPACT_TYPE_FILE);
        idmef_impact_set_completion(impact, IDMEF_IMPACT_COMPLETION_SUCCEEDED);

        soff = get_rotation_size_offset(monitor, st);
        toff = get_rotation_time_offset(monitor, st);
                
        if ( toff <= max_rotation_time_offset|| soff <= max_rotation_size_offset ) {
                idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_INFO);
                ret = idmef_impact_new_description(impact, &str);
                prelude_string_set_constant(str, LOGFILE_DELETION_IMPACT);
        } else {
                idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_HIGH);
                ret = idmef_impact_new_description(impact, &str);
                snprintf(buf, sizeof(buf), "An inconsistency has been observed in file rotation: "
                        "The differences between the previously observed rotation time and size are higher "
                        "than the allowed limits: size difference=%u bytes allowed=%u bytes, time "
                        "difference=%u seconds allowed=%u seconds", soff, max_rotation_size_offset, 
                         toff, max_rotation_time_offset);
                prelude_string_set_ref(str, buf);
        }

        logfile_alert(monitor, st, classification, impact);
        
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
                prelude_log(PRELUDE_LOG_ERR, "error creating unique temporary filename.\n");
                return -1;
        }
        
        fd = open(buf, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);
        if ( fd < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error opening %s for writing.\n", buf);
                return -1;
        }
        
        ret = FAMMonitorFile(fc, buf, &fr, NULL);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error creating FAM monitor for %s: %s.\n", buf, FamErrlist[FAMErrno]);
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
                prelude_log(PRELUDE_LOG_ERR, "error writing test string to %s: %s.\n", buf);
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
        int ret;
        
        if ( fam_initialized != 0 )
                return fam_initialized;

        fam_initialized = -1;
        
        ret = FAMOpen(&fc);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error initializing FAM: %s.\n", FamErrlist[FAMErrno]);
                return -1;
        }

        prelude_log(PRELUDE_LOG_INFO, "- Checking for FAM writev() bug...\n");
        
        ret = check_fam_writev_bug(&fc);
        if ( ret < 0 ) {
                FAMClose(&fc);
                
                prelude_log(PRELUDE_LOG_INFO, "- An OS bug prevent FAM from monitoring writev() file modification: disabling FAM.\n");
                return -1;
        }

        prelude_log(PRELUDE_LOG_INFO, "- FAM working nicely, enabling.\n");
        
        fam_initialized = 1;

        return 0;
}



static int fam_setup_monitor(monitor_fd_t *monitor)
{
        int ret;
        const char *filename;

        if ( batch_mode )
                return 0;
        
        ret = initialize_fam();
        if ( ret < 0 )
                return 0;

        filename = lml_log_source_get_name(monitor->source);
        
        ret = FAMMonitorFile(&fc, filename, &monitor->fam_request, monitor);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error creating FAM monitor for %s: %s.\n", filename, FamErrlist[FAMErrno]);
                return -1;
        }
        
        return 0;
}



static int fam_process_event(FAMEvent *event) 
{
        int ret = 0;
        struct stat st;
        monitor_fd_t *monitor = event->userdata;

        switch (event->code) {
        case FAMCreated:
        case FAMChanged:
                if ( ! monitor->fd && monitor_open(monitor) < 0 )
                        return -1;
                
        case FAMDeleted:
                ret = fstat(fileno(monitor->fd), &st);
                if ( ret < 0 )
                        prelude_log(PRELUDE_LOG_ERR, "fstat returned an error.\n");

                /*
                 * check mtime consistency.
                 */
                check_modification_time(monitor, &st);
        
                /*
                 * read and analyze available data. 
                 */
                check_logfile_data(monitor, &st);
        
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




static int fam_process_queued_events(void) 
{
        int ret;
        FAMEvent event;
        
        while ( FAMPending(&fc) ) {
                ret = FAMNextEvent(&fc, &event);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_WARN, "error while getting FAM event: %s.\n", FamErrlist[FAMErrno]);
                        return -1;
                }

                fam_process_event(&event);
        }

        return 0;
}
#endif



static int process_file_event(monitor_fd_t *monitor) 
{
        int ret;
        struct stat st;

        ret = fstat(fileno(monitor->fd), &st);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't fstat '%s'.\n", lml_log_source_get_name(monitor->source));
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
        return check_logfile_data(monitor, &st);
}




int file_server_monitor_file(regex_list_t *rlist, lml_log_source_t *ls) 
{
        monitor_fd_t *new;
        
        /*
         * Don't open the monitor right now,
         * we want all unread bytes to be processed before activating
         * FAM notification (if enabled).
         */
        
        new = monitor_new(ls);
        if ( ! new )
                return -1;

#if 0
        ret = monitor_open(new);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't open %s for reading.\n", log_source_get_name(ls));
                free(new);
                return -1;
        }
#endif
        
        new->regex_list = rlist;
        
        return 0;
}



int file_server_wake_up(void) 
{
        int ret = -1, event;
        monitor_fd_t *monitor;
        prelude_list_t *tmp, *bkp;
        
        if ( fam_initialized != 1 || batch_mode ) {
                /*
                 * try to open inactive fd (file was not existing previously).
                 */
                try_reopening_inactive_monitor();
                
                prelude_list_for_each_safe(&active_fd_list, tmp, bkp) {
                        monitor = prelude_list_entry(tmp, monitor_fd_t, list);                        

                        event = process_file_event(monitor);
                        if ( event > 0 )
                                ret = event;
                }
        }
        
#ifdef HAVE_FAM
        else 
                return fam_process_queued_events();
#endif
        
        return ret;
}




int file_server_get_event_fd(void) 
{
#ifdef HAVE_FAM
        if ( fam_initialized == 1 )
                return FAMCONNECTION_GETFD(&fc);
#endif
        
        return -1;
}




void file_server_set_max_rotation_time_offset(unsigned int val) 
{
        max_rotation_time_offset = val;
}



unsigned int file_server_get_max_rotation_time_offset(void)
{
        return max_rotation_time_offset;
}



void file_server_set_max_rotation_size_offset(unsigned int val)
{
        max_rotation_size_offset = val;
}


unsigned int file_server_get_max_rotation_size_offset(void)
{
        return max_rotation_size_offset;
}


void file_server_start_monitoring(void)
{
        /*
         * Initialize everythings once by calling file_server_wake_up().
         */
        if ( fam_initialized == 1 )
                try_reopening_inactive_monitor();
        
        file_server_wake_up();        
}


void file_server_set_ignore_metadata(void)
{
        ignore_metadata = 1;
}


void file_server_set_batch_mode(void)
{
        batch_mode = 1;
}
