#ifndef HASH_H
#define HASH_H

/* Polymorphic hash table with key
   Copyright (C) 1993, 1996, 1999 Laboratoire Bordelais de Recherche en
   Informatique. 
   
   Author: Robert Strandh

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

typedef struct hash_table *hash_table;

/* Create a hash table.  The argument hash is a function that returns
   a an integer when applied to a key of the hash table.  The argument
   equal() is a function that returns a true value if key arguments
   are considered equal, 0 otherwise. */

extern hash_table
hash_create(int (*hash) (void *key), int (*equal) (void *k1, void *k2));

/* destroy a hash table. */

extern void hash_destroy(hash_table ht);

/* The hash table has the notion of a cursor.  This function positions
   the cursor to a key equal() to the one given as argument, if such a
   key exists.  In that case a true value is returned.  If no key
   equal() to the one given exists in the table, a 0 is returned, and
   the cursor is positioned to a place where insertion of the new
   object should take place.  A typical call would be
   	
		if(!hash_position(t, k)) hash_insert(t, k);
   
   that is, first position to the place where object associated to key k
   ought to be located.  If it is not in the table, then cursor is
   positioned where it should be inserted, thus you can immediately insert
   it. */

extern int hash_position(hash_table ht, void *key);

/* Insert an object into a hash table.  Before insertion,
   hash_position() must have been called and must have returned
   0. Otherwise the result of the insertion is undefined. 
   Each object inserted in the hash table must have only one and single
   key */

extern void hash_insert(hash_table, void *key, void *object);

/* Delete an object from a hash table.  Before deletion,
   hash_position() must have been called and must have returned a a
   true value.  Otherwise the result of the deletion is undefined. */

extern void hash_delete(hash_table ht);

/* Map any function over all the elements of the hash table.  The
   function is applied to each of the objects in some arbitrary
   order. */

typedef void (*hash_map_fun) (void *object);

extern void hash_map(hash_table ht, hash_map_fun fun);

/* Get an object from a hash table.  Before this function is called,
   hash_position() must have been called and must have returned a true
   value.  Otherwise the result of the call is undefined. */

extern void *hash_get(hash_table ht);

/* Get the current number of elements in the hash table. */

extern int hash_size(hash_table ht);

#endif				/* HASH_H */
