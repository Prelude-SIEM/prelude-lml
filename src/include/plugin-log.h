/*****
*
* Copyright (C) 2002 - 2005 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#ifndef PLUGIN_LOG_H
#define PLUGIN_LOG_H

typedef struct {
	PRELUDE_PLUGIN_GENERIC;
	void (*run)(prelude_plugin_instance_t *pi, const log_entry_t * log);
} plugin_log_t;



#define plugin_run_func(p) (p)->run
#define prelude_plugin_set_running_func(p, func) plugin_run_func(p) = (func)

#endif				/* PLUGIN_LOG_H */
