/*****
*
* Copyright (C) 1998-2015 CS-SI. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <gcrypt.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "ev.h"

#include <libprelude/prelude.h>
#include <libprelude/prelude-timer.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-extract.h>

#include "prelude-lml.h"
#include "regex.h"
#include "common.h"
#include "log-entry.h"
#include "file-server.h"
#include "lml-alert.h"
#include "lml-options.h"
#include "pathmax.h"


#ifndef MIN
 #define MIN(x, y) ( ((x) < (y)) ? (x) : (y) )
#endif

#ifndef MAX
 #define MAX(x, y) ( ((x) > (y)) ? (x) : (y) )
#endif


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
#define METADATA_CHECKSUM_SIZE 4
#define METADATA_SIZE (sizeof(off_t) + METADATA_CHECKSUM_SIZE)
#define METADATA_CHECKSUM_TYPE GCRY_MD_CRC32

#define LOGFILE_RENAME_CLASS   "Log file rename"
#define LOGFILE_DELETION_CLASS "Log file deletion"
#define LOGFILE_DELETION_IMPACT "An attacker might have erased the logfile, "               \
                                "or a log rotation program may have rotated the logfile."

#define LOGFILE_MODIFICATION_CLASS "Log file inconsistency"
#define LOGFILE_MODIFICATION_IMPACT "An attacker might have modified the log file in order " \
                                    "to remove the trace he left."


typedef struct {
        prelude_list_t list;

        lml_log_source_t *source;

        FILE *fd;
        FILE *metadata_fd;
        prelude_bool_t need_position;

        off_t last_rotation_size;
        time_t last_rotation_time;
        time_t last_rotation_time_interval;

        prelude_string_t *buf;

        off_t need_more_read;
        off_t last_size;
        size_t current_line_len;

        union {
                ev_stat st;
                ev_io io;
        } event;

        int prev_errno;
} monitor_fd_t;


static void libev_io_cb(ev_io *io, int revents);
static void libev_stat_cb(ev_stat *st, int revents);
void _lml_handle_signal_if_needed(void);

extern lml_config_t config;


static PRELUDE_LIST(active_fd_list);
static PRELUDE_LIST(inactive_fd_list);
static unsigned int max_rotation_time_offset = DEFAULT_MAX_ROTATION_TIME_OFFSET;
static unsigned int max_rotation_size_offset = DEFAULT_MAX_ROTATION_SIZE_OFFSET;
static file_server_metadata_flags_t metadata_flags = FILE_SERVER_METADATA_FLAGS_LAST;



static int stat_to_file(monitor_fd_t *fd, ev_statdata *st, idmef_target_t *target, idmef_file_category_t category)
{
        int ret;
        idmef_time_t *time;
        idmef_file_t *file;
        idmef_inode_t *inode;
        prelude_string_t *string;
        const char *fname, *fptr;

        ret = idmef_target_new_file(target, &file, -1);
        if ( ret < 0 )
                return -1;

        idmef_file_set_category(file, category);
        idmef_file_set_data_size(file, st->st_size);

        ret = idmef_file_new_inode(file, &inode);
        if ( ret < 0 )
                return -1;

        idmef_inode_set_number(inode, st->st_ino);

        ret = idmef_file_new_name(file, &string);
        if ( ret < 0 )
                return -1;

        fname = lml_log_source_get_name(fd->source);
        fptr = strrchr(fname, '/');
        prelude_string_set_ref(string, (fptr) ? (fptr + 1) : fname);

        ret = idmef_file_new_path(file, &string);
        if ( ret < 0 )
                return -1;
        prelude_string_set_ref(string, fname);

        ret = idmef_file_new_access_time(file, &time);
        if ( ret < 0 )
                return -1;

        idmef_time_set_sec(time, st->st_atime);

        ret = idmef_file_new_modify_time(file, &time);
        if ( ret < 0 )
                return -1;

        idmef_time_set_sec(time, st->st_mtime);

        return 0;
}


static void logfile_alert(monitor_fd_t *fd, ev_statdata *st_old, ev_statdata *st_new,
                          idmef_classification_t *classification, idmef_impact_t *impact)
{
        int ret;
        lml_log_entry_t *log_entry;
        idmef_alert_t *alert;
        idmef_target_t *target;
        idmef_message_t *message;
        idmef_assessment_t *assessment;

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

        if ( st_old && stat_to_file(fd, st_old, target, IDMEF_FILE_CATEGORY_ORIGINAL) < 0 )
                goto err;

        if ( st_new && stat_to_file(fd, st_new, target, IDMEF_FILE_CATEGORY_CURRENT) < 0 )
                goto err;

        ret = idmef_alert_new_assessment(alert, &assessment);
        if ( ret < 0 )
                goto err;

        idmef_assessment_set_impact(assessment, impact);
        idmef_alert_set_classification(alert, classification);

        lml_alert_emit(fd->source, log_entry, message);

 err:
        lml_log_entry_destroy(log_entry);
        idmef_message_destroy(message);
}



static void logfile_modified_alert(monitor_fd_t *monitor, ev_statdata *st_old, struct stat *st_new)
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

        logfile_alert(monitor, st_old, st_new, classification, impact);
}


/*
 * This function return -2 if it couldn't read a full syslog line,
 * or -1 if an error occured.
 *
 * The number of character that has been read is returned otherwise.
 */
static off_t read_logfile(monitor_fd_t *fd, off_t *available)
{
        int ret;
        off_t i = 0;

        while ( 1 ) {
                ret = getc(fd->fd);
                if ( ret == EOF ) {
                        clearerr(fd->fd);
                        *available -= i;
                        return -1;
                }

                i++;
                fd->current_line_len++;

                if ( ret == '\n' )
                        break;

                if ( fd->current_line_len <= config.log_max_length ) {
                        ret = prelude_string_ncat(fd->buf, (const char *) &ret, 1);
                        if ( ret < 0 )
                                prelude_log(PRELUDE_LOG_ERR, "error buffering input: %s.\n", prelude_strerror(ret));
                }

                else if ( fd->current_line_len == config.log_max_length + 1 )
                        prelude_log(PRELUDE_LOG_WARN, "line too long (configured limit of %u characters).\n", config.log_max_length);

                if ( i == *available ) {
                        *available = 0;
                        return -2;
                }
        }

        *available -= i;
        return i;
}



static int file_metadata_read(monitor_fd_t *monitor, off_t *start, unsigned char **buf)
{
        ssize_t ret;
        struct stat st;

        if ( fstat(fileno(monitor->metadata_fd), &st) < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "fstat failed : %s.\n", strerror(errno));
                return -1;
        }

        if ( st.st_size != METADATA_SIZE ) {
                /* old format, truncate. */
                ftruncate(fileno(monitor->metadata_fd), 0);
                return -1;
        }

        rewind(monitor->metadata_fd);

        ret = fread(*buf, 1, METADATA_SIZE, monitor->metadata_fd);
        if ( ret != METADATA_SIZE )
                return -1;

        memcpy(start, *buf, sizeof(*start));
        *buf = *buf + sizeof(off_t);

        return 0;
}


static int file_metadata_save(monitor_fd_t *monitor, off_t offset)
{
        int ret;
        unsigned char buf[METADATA_SIZE];

        if ( metadata_flags & FILE_SERVER_METADATA_FLAGS_NO_WRITE )
                return 0;

        assert(gcry_md_get_algo_dlen(METADATA_CHECKSUM_TYPE) + sizeof(offset) == sizeof(buf));

        memcpy(buf, &offset, sizeof(offset));
        gcry_md_hash_buffer(METADATA_CHECKSUM_TYPE, buf + sizeof(offset),
                            prelude_string_get_string(monitor->buf),
                            prelude_string_get_len(monitor->buf));

        rewind(monitor->metadata_fd);

        ret = fwrite(buf, 1, sizeof(buf), monitor->metadata_fd);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not write metadata file: %s.\n", strerror(errno));
                return -1;
        }

        return 0;
}



static int verify_metadata_checksum(prelude_string_t *log, unsigned char *metadata_sum)
{
        unsigned char sum[METADATA_CHECKSUM_SIZE];

        assert(gcry_md_get_algo_dlen(METADATA_CHECKSUM_TYPE) == sizeof(sum));
        gcry_md_hash_buffer(METADATA_CHECKSUM_TYPE, sum, prelude_string_get_string(log), prelude_string_get_len(log));

        return memcmp(sum, metadata_sum, sizeof(sum));
}

static int file_metadata_get_position(monitor_fd_t *monitor)
{
        struct stat st;
        const char *filename;
        int ret, have_metadata = 0;
        off_t offset = 0, available = 65535;
        unsigned char msum[METADATA_SIZE], *sumptr = msum;

        filename = lml_log_source_get_name(monitor->source);

        ret = file_metadata_read(monitor, &offset, &sumptr);
        if ( ret == 0 )
                have_metadata = 1;

        ret = fstat(fileno(monitor->fd), &st);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "stat: error on file %s: %s.\n", filename, strerror(errno));
                return -1;
        }

        monitor->last_size = st.st_size;

        if ( ! have_metadata ) {
                prelude_log(PRELUDE_LOG_INFO, "%s: No metadata available, starting from tail.\n", filename);
                return fseeko(monitor->fd, st.st_size, SEEK_SET);
        }

        if ( st.st_size < offset ) {
                prelude_log(PRELUDE_LOG_INFO, "%s: log file was rotated, starting from head.\n", filename);
                monitor->last_size = 0;
                return 0;
        }

        ret = fseeko(monitor->fd, offset, SEEK_SET);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "%s: error seeking to offset %" PRELUDE_PRIu64 ": %s.\n",
                            filename, offset, strerror(errno));
                return -1;
        }

        /*
         * If the metadata checksum does not match, the file was probably rotated.
         */
        if ( read_logfile(monitor, &available) < 0 || verify_metadata_checksum(monitor->buf, sumptr) != 0 ) {
                prelude_log(PRELUDE_LOG_INFO, "%s: log file was rotated, starting from head.\n", filename);
                monitor->last_size = 0;
                monitor->current_line_len = 0;
                prelude_string_clear(monitor->buf);
                return fseeko(monitor->fd, 0, SEEK_SET);
        }

        prelude_string_clear(monitor->buf);
        monitor->last_size = offset + monitor->current_line_len;
        monitor->current_line_len = 0;

        prelude_log(PRELUDE_LOG_INFO, "%s: resuming log analyzis at offset %" PRELUDE_PRIu64 ".\n",
                    filename, monitor->last_size);

        return 0;
}




static int file_metadata_open(monitor_fd_t *monitor)
{
        int fd;
        char file[PATH_MAX], path[PATH_MAX], *ptr;

        strncpy(file, lml_log_source_get_name(monitor->source), sizeof(file));

        while ( (ptr = strchr(file, '/')) )
                *ptr = '-'; /* strip */

        snprintf(path, sizeof(path), "%s/%s", METADATA_DIR, file);

        fd = open(path, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
        if ( fd < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error creating %s: %s.\n", path, strerror(errno));
                return -1;
        }

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

        monitor->metadata_fd = fdopen(fd, "r+");
        if ( ! monitor->metadata_fd ) {
                prelude_log(PRELUDE_LOG_ERR, "fdopen failed: %s.\n", strerror(errno));
                close(fd);
                return -1;
        }

        return 0;
}


static int check_logfile_data(monitor_fd_t *monitor, struct stat *st)
{
        off_t len, ret;
        int eventno = 0;
        size_t slen = 0;

        if ( ! monitor->need_more_read && st->st_size == monitor->last_size )
                return 0;

        len = (st->st_size - monitor->last_size) + monitor->need_more_read;
        monitor->last_size = st->st_size;

        while ( len && (ret = read_logfile(monitor, &len)) >= 0 ) {

                eventno++;

                /*
                 * If the line we read only contained a '\n', string and len will be 0.
                 */
                if ( (slen = prelude_string_get_len(monitor->buf)) ) {
                        lml_dispatch_log(monitor->source, prelude_string_get_string(monitor->buf), slen);
                        file_metadata_save(monitor, ftello(monitor->fd) - monitor->current_line_len);
                }

                monitor->current_line_len = 0;

                prelude_string_clear(monitor->buf);
                _lml_handle_signal_if_needed();
        }

        /*
         * if len is not 0, we got EOF before reading every new byte, we
         * will try reading the data on next invocation, even if st_size
         * isn't modified.
         */
        monitor->need_more_read = len;
        return eventno;
}


static int check_stdin_data(monitor_fd_t *monitor)
{
        size_t slen;
        off_t ret, len;
        int eventno = 0, bytes;

        if ( config.batch_mode )
                len = (off_t) config.log_max_length;
        else {
                ret = ioctl(STDIN_FILENO, FIONREAD, &bytes);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "FIONREAD failed on stdin: %s.\n", strerror(errno));
                        return -1;
                }

                len = (off_t) bytes;
        }

        while ( len && (ret = read_logfile(monitor, &len)) >= 0 ) {

                eventno++;

                /*
                 * If the line we read only contained a '\n', string and len will be 0.
                 */
                if ( (slen = prelude_string_get_len(monitor->buf)) ) {
                        lml_dispatch_log(monitor->source, prelude_string_get_string(monitor->buf), slen);
                }

                prelude_string_clear(monitor->buf);
                _lml_handle_signal_if_needed();
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
        new->need_position = TRUE;

        ret = file_metadata_open(new);
        if ( ret < 0 ) {
                free(new);
                return NULL;
        }

        if ( strcmp(lml_log_source_get_name(ls), STDIN_FILENAME) != 0 ) {
                ev_stat_init(&new->event.st, libev_stat_cb, lml_log_source_get_name(new->source), 1);
                new->event.st.data = new;
                ev_stat_start(&new->event.st);
        } else {
                ev_io_init(&new->event.io, libev_io_cb, STDIN_FILENO, EV_READ);
                new->event.io.data = new;
                ev_io_start(&new->event.io);
        }

        prelude_list_add(&inactive_fd_list, &new->list);

        return new;
}



static int monitor_set_position(monitor_fd_t *monitor, const char *filename)
{
        int ret = 0;

        if ( ! monitor->need_position )
                return 0;

        monitor->need_position = FALSE;

        if ( metadata_flags & FILE_SERVER_METADATA_FLAGS_LAST )
                return file_metadata_get_position(monitor) >= 0 ? 1 : -1;

        else if ( metadata_flags & FILE_SERVER_METADATA_FLAGS_HEAD ) {
                prelude_log(PRELUDE_LOG_INFO, "%s: user requested starting from head.\n", filename);
                ret = fseeko(monitor->fd, 0, SEEK_SET);
        }

        else if ( metadata_flags & FILE_SERVER_METADATA_FLAGS_TAIL ) {
                prelude_log(PRELUDE_LOG_INFO, "%s: user requested starting from tail.\n", filename);
                ret = fseeko(monitor->fd, 0, SEEK_END);
        }

        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "%s: error seeking to the %s of the file: %s.\n",
                            filename, (metadata_flags & FILE_SERVER_METADATA_FLAGS_TAIL) ? "tail" : "head",
                            strerror(errno));
                return -1;
        }

        return 1;
}


static int monitor_open(monitor_fd_t *monitor)
{
        int ret, fd;
        const char *filename = lml_log_source_get_name(monitor->source);

        ret = prelude_string_new(&monitor->buf);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not create string object: %s.\n", prelude_strerror(ret));
                return ret;
        }

        if ( strcmp(filename, STDIN_FILENAME) == 0 )
                monitor->fd = stdin;
        else {
                monitor->fd = fopen(filename, "r");
                if ( ! monitor->fd ) {
                        if ( errno == ENOENT && monitor->prev_errno != errno )
                                prelude_log(PRELUDE_LOG_WARN, "%s does not exist.\n", filename);

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
                        else if ( errno == EACCES && monitor->prev_errno != errno )
                                prelude_log(PRELUDE_LOG_WARN, "%s is not available for reading to uid %d/gid %d.\n",
                                            filename, getuid(), getgid());
#endif

                        monitor->prev_errno = errno;
                        prelude_string_destroy(monitor->buf);
                        return -1;
                }

                fd = fileno(monitor->fd);

#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
                fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

                ret = monitor_set_position(monitor, filename);
                if ( ret < 0 ) {
                        prelude_string_destroy(monitor->buf);
                        return -1;
                }

                if ( ret == 0 )
                        prelude_log(PRELUDE_LOG_INFO, "%s: now available for monitoring.\n", filename);
        }

        monitor->need_more_read = 0;
        prelude_list_del(&monitor->list);
        prelude_list_add_tail(&active_fd_list, &monitor->list);

        return 0;
}



static void monitor_close(monitor_fd_t *monitor)
{
        prelude_string_destroy(monitor->buf);

        fclose(monitor->fd);
        monitor->fd = NULL;
        monitor->last_size = 0;
        monitor->current_line_len = 0;

        prelude_list_del(&monitor->list);
        prelude_list_add_tail(&inactive_fd_list, &monitor->list);
}



/*
 * This won't protect against replacement of log entry by garbage,
 * Unfortunnaly, there is no way it can be done cleanly, or it would
 * cause heavy performance problem. The best solution may be to centralize
 * the logging on a remote host.
 */
static void check_modification_time(monitor_fd_t *monitor, ev_statdata *prev, struct stat *st)
{
        int ret;
        const char *filename;

        if ( st->st_mtime >= prev->st_mtime && st->st_size >= monitor->last_size )
                return; /* everythings sound okay */

        filename = lml_log_source_get_name(monitor->source);

        prelude_log(PRELUDE_LOG_INFO, "%s: has been %s.\n", filename, (st->st_size >= monitor->last_size) ? "modidifed" : "truncated");
        logfile_modified_alert(monitor, prev, st);

        /*
         * If the logfile has been modified, we reposition the current
         * descriptor to EOF, and start analyzing from this place.
         */
        if ( st->st_size < monitor->last_size ) {
                ret = fseeko(monitor->fd, 0, SEEK_END);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "%s: error seeking to end of file: %s.\n", filename, strerror(errno));
                        return;
                }

                monitor->need_more_read = 0;
                monitor->last_size = st->st_size;
                monitor->current_line_len = 0;
        }
}


static off_t get_rotation_size_offset(monitor_fd_t *monitor, ev_statdata *st)
{
        off_t diff = 0;

        if ( monitor->last_rotation_size )
                diff = (off_t) imaxabs((intmax_t) monitor->last_rotation_size - st->st_size);

        monitor->last_rotation_size = st->st_size;

        return diff;
}


static time_t get_rotation_time_offset(monitor_fd_t *monitor)
{
        time_t interval = 0, diff = 0, now = time(NULL);

        if ( monitor->last_rotation_time )
                interval = now - monitor->last_rotation_time;

        if ( interval && monitor->last_rotation_time_interval )
                diff = (time_t) imaxabs((intmax_t) monitor->last_rotation_time_interval - interval);

        monitor->last_rotation_time = now;
        monitor->last_rotation_time_interval = interval;

        return diff;
}


static int is_file_already_used(monitor_fd_t *monitor, ev_statdata *st_prev, ev_statdata *st_cur, struct stat *st_now)
{
        int ret;
        char buf[1024];
        off_t soff;
        time_t toff;
        const char *filename, *ctxt;
        idmef_impact_t *impact;
        idmef_classification_t *classification;
        prelude_string_t *str;
        prelude_bool_t is_deleted;

        filename = lml_log_source_get_name(monitor->source);

        /*
         * rename = 1 - 0
         * rename + re-create = 1 - 1 - !=
         * delete = 0 - 0
         * delete + re-create = 0 - 1
         */
        if ( st_now->st_nlink > 0 && st_cur->st_nlink > 0 && st_now->st_ino == st_cur->st_ino )
                return 0;

        /*
         * test if the file has been removed
         */
        if ( st_now->st_nlink > 0 ) {
                prelude_log(PRELUDE_LOG_INFO, "%s: has been renamed.\n", filename);
                ctxt = LOGFILE_RENAME_CLASS;
                is_deleted = FALSE;
        } else {
                prelude_log(PRELUDE_LOG_INFO, "%s: has been deleted.\n", filename);
                ctxt = LOGFILE_DELETION_CLASS;
                is_deleted = TRUE;
        }

        /*
         * Before closing the monitor, handle any unread data.
         */
        if ( st_now->st_size > monitor->last_size )
                check_logfile_data(monitor, st_now);

        monitor_close(monitor);

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
        prelude_string_set_ref(str, ctxt);

        idmef_impact_set_type(impact, IDMEF_IMPACT_TYPE_FILE);
        idmef_impact_set_completion(impact, IDMEF_IMPACT_COMPLETION_SUCCEEDED);

        soff = get_rotation_size_offset(monitor, st_now);
        toff = get_rotation_time_offset(monitor);

        if ( toff <= max_rotation_time_offset || soff <= max_rotation_size_offset ) {
                idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_INFO);
                ret = idmef_impact_new_description(impact, &str);
                if ( ret < 0 )
                        return ret;
                prelude_string_set_constant(str, LOGFILE_DELETION_IMPACT);
        } else {
                idmef_impact_set_severity(impact, IDMEF_IMPACT_SEVERITY_HIGH);
                ret = idmef_impact_new_description(impact, &str);
                if ( ret < 0 )
                        return ret;
                snprintf(buf, sizeof(buf), "An inconsistency has been observed in file rotation: "
                        "the differences between the previously observed rotation size and time are higher "
                        "than allowed limits: %" PRELUDE_PRIu64 " bytes difference (%" PRELUDE_PRIu64" allowed), "
                        "%" PRELUDE_PRIu64 " seconds difference (%" PRELUDE_PRIu64" allowed)",
                         (intmax_t) soff, (intmax_t) max_rotation_size_offset,
                         (intmax_t) toff, (intmax_t) max_rotation_time_offset);
                prelude_string_set_ref(str, buf);
        }

        if ( is_deleted )
                logfile_alert(monitor, st_now, NULL, classification, impact);
        else
                logfile_alert(monitor, st_prev, st_now, classification, impact);

        return -1;
}


static void libev_io_cb(ev_io *io, int revents)
{
        int ret;

        ret = check_stdin_data(io->data);
        if ( ret <= 0 )
                ev_io_stop(io);
}


static void libev_stat_cb(ev_stat *st, int revents)
{
        int ret;
        struct stat fst;
        monitor_fd_t *monitor = st->data;

        if ( ! monitor->fd )
                if ( monitor_open(monitor) < 0 )
                        return;

        /*
         * Do not rely on libev statistics gathered by stat().
         *
         * If a file is written then deleted, but re-created very fast,
         * only fstat() can report an st_nlink of 0.
         *
         * If a file is deleted from libev point of view, only fstat()
         * will be able to provide latest information about the stat of
         * the file.
         */
        fstat(fileno(monitor->fd), &fst);

        ret = is_file_already_used(monitor, &st->prev, &st->attr, &fst);
        if ( ret < 0 ) {
                if ( st->attr.st_nlink == 0 )
                        return;
                else {
                        /*
                         * The file has been deleted then created again: trigger opening/reading of the new dfile.
                         */
                        return libev_stat_cb(st, revents);
                }
        }

        /*
         * check mtime/size consistency.
         */
        check_modification_time(monitor, &st->prev, &fst);


        /*
         * read and analyze available data.
         */
        check_logfile_data(monitor, &fst);
}


int file_server_monitor_file(lml_log_source_t *ls)
{
        monitor_fd_t *new;

        new = monitor_new(ls);
        if ( ! new )
                return -1;

        return 0;
}


int file_server_read_once(void)
{
        int ret = -1, event;
        monitor_fd_t *monitor;
        prelude_list_t *tmp, *bkp;

        prelude_list_for_each_safe(&active_fd_list, tmp, bkp) {
                monitor = prelude_list_entry(tmp, monitor_fd_t, list);

                if ( monitor->fd != stdin )
                        event = check_logfile_data(monitor, &monitor->event.st.attr);
                else
                        event = check_stdin_data(monitor);

                if ( event > 0 )
                        ret = event;
        }

        return ret;
}



void file_server_set_max_rotation_time_offset(time_t val)
{
        max_rotation_time_offset = val;
}



time_t file_server_get_max_rotation_time_offset(void)
{
        return max_rotation_time_offset;
}



void file_server_set_max_rotation_size_offset(off_t val)
{
        max_rotation_size_offset = val;
}


off_t file_server_get_max_rotation_size_offset(void)
{
        return max_rotation_size_offset;
}


int file_server_start_monitoring(void)
{
        monitor_fd_t *monitor;
        prelude_list_t *tmp, *bkp;
        int cnt = 0, failed_cnt = 0, ret;

        prelude_list_for_each_safe(&inactive_fd_list, tmp, bkp) {
                monitor = prelude_list_entry(tmp, monitor_fd_t, list);

                cnt++;

                ret = monitor_open(monitor);
                if ( ret < 0 )
                        failed_cnt++;
        }

        return (failed_cnt < cnt) ? 0 : -1;
}


void file_server_set_metadata_flags(file_server_metadata_flags_t flags)
{
        if ( ! (flags & (FILE_SERVER_METADATA_FLAGS_HEAD|
                         FILE_SERVER_METADATA_FLAGS_LAST|
                         FILE_SERVER_METADATA_FLAGS_TAIL)) )
                flags |= FILE_SERVER_METADATA_FLAGS_LAST;

        metadata_flags = flags;
}
