/*****
*
* Copyright (C) 2009-2016 CS-SI. All Rights Reserved.
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

#ifndef LML_CHARSET_H
#define LML_CHARSET_H

typedef struct lml_charset lml_charset_t;

int lml_charset_open(lml_charset_t **lc, const char *from);

int lml_charset_convert(lml_charset_t *lc, const char *in, size_t inlen, char **out, size_t *outlen);

int lml_charset_detect(const char *in, size_t inlen, const char **out, int *confidence);

int lml_charset_close(lml_charset_t *lc);

#endif
