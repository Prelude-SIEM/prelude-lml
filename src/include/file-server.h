/*****
*
* Copyright (C) 1998-2012 CS-SI. All Rights Reserved.
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


typedef enum {
        FILE_SERVER_METADATA_FLAGS_HEAD     = 0x01,
        FILE_SERVER_METADATA_FLAGS_TAIL     = 0x02,
        FILE_SERVER_METADATA_FLAGS_LAST     = 0x04,
        FILE_SERVER_METADATA_FLAGS_NO_WRITE = 0x08
} file_server_metadata_flags_t;


void file_server_set_metadata_flags(file_server_metadata_flags_t flags);

int file_server_read_once(void);

int file_server_monitor_file(lml_log_source_t *ls);

int file_server_start_monitoring(void);

time_t file_server_get_max_rotation_time_offset(void);

void file_server_set_max_rotation_time_offset(time_t val);

off_t file_server_get_max_rotation_size_offset(void);

void file_server_set_max_rotation_size_offset(off_t val);
