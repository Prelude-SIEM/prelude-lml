/*****
*
* Copyright (C) 1998 - 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

/*
 * we can store up to 64 reference value in a rule
 * it should be large enough
 */
#define MAX_REFERENCE_PER_RULE 64


typedef struct {
        uint16_t id;
        uint16_t revision;

        prelude_bool_t last;
        prelude_bool_t chained;
        unsigned int required_goto;
        unsigned int refcount;

        unsigned int min_optgoto_match;
        unsigned int min_optregex_match;
        
        prelude_list_t rule_list;
        prelude_list_t regex_list;
        
        rule_object_list_t *object_list;
} pcre_rule_t;



typedef struct {
        prelude_list_t list;

        pcre_rule_t *rule;
        prelude_bool_t optional;
} pcre_rule_container_t;
