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

#include "hashkey.h"
#include <stdlib.h>

typedef struct hash_binding *hash_binding;

struct hash_table {
	int hash_table_size;
	int number_of_bindings;
	hash_binding *hash_table;
	hash_binding *cursor;
	int (*equal) (void *k1, void *k2);
	int (*hash) (void *key);
};

struct hash_binding {
	int hashval;
	void *obj;
	void *key;
	hash_binding next;
};

/* minimum hash table size in pointers */
#define MIN_HASH_TABLE_SIZE 3

#define MAX_FILL_DEGREE 5
#define MIN_FILL_DEGREE 1

hash_table
hash_create(int (*hash) (void *key), int (*equal) (void *k1, void *k2))
{
	hash_table temp;
	int i;
	temp = malloc(sizeof(struct hash_table));
	temp->hash_table_size = MIN_HASH_TABLE_SIZE;
	temp->number_of_bindings = 0;
	temp->hash_table =
	    malloc(MIN_HASH_TABLE_SIZE * sizeof(hash_binding));
	for (i = 0; i < MIN_HASH_TABLE_SIZE; i++)
		temp->hash_table[i] = NULL;
	temp->cursor = NULL;
	temp->equal = equal;
	temp->hash = hash;
	return temp;
}

void hash_destroy(hash_table ht)
{
	hash_binding bind, temp;
	int i;
	for (i = 0; i < ht->hash_table_size; i++) {
		for (bind = ht->hash_table[i]; bind;) {
			temp = bind->next;
			free(bind);
			bind = temp;
		}
	}
	free(ht->hash_table);
}

int hash_position(hash_table ht, void *key)
{
	int index = (*(ht->hash)) (key) % ht->hash_table_size;
	hash_binding *bind = &(ht->hash_table[index]);
	for (; *bind; bind = &((*bind)->next)) {
		if ((*(ht->equal)) ((*bind)->key, key)) {
			ht->cursor = bind;
			return 1;
		}
	}
	ht->cursor = bind;
	return 0;
}

static void possibly_increase_size(hash_table ht)
{
	if ((ht->number_of_bindings)
	    > (ht->hash_table_size) * MAX_FILL_DEGREE) {
		int i;
		int new_hash_table_size = (ht->hash_table_size) * 2 + 1;
		hash_binding *new_hash_table =
		    malloc(new_hash_table_size * sizeof(hash_binding));
		for (i = 0; i < new_hash_table_size; i++)
			new_hash_table[i] = NULL;
		for (i = 0; i < ht->hash_table_size; i++) {
			hash_binding bind, temp;
			for (bind = ht->hash_table[i]; bind;) {
				int index =
				    bind->hashval % new_hash_table_size;
				temp = bind->next;
				bind->next = new_hash_table[index];
				new_hash_table[index] = bind;
				bind = temp;
			}
		}
		free(ht->hash_table);
		ht->hash_table = new_hash_table;
		ht->hash_table_size = new_hash_table_size;
	}
}

static void possibly_decrease_size(hash_table ht)
{
	if ((ht->number_of_bindings)
	    < (ht->hash_table_size) * MIN_FILL_DEGREE
	    && ht->hash_table_size > MIN_HASH_TABLE_SIZE) {
		int i;
		int new_hash_table_size = ((ht->hash_table_size) - 1) / 2;
		hash_binding *new_hash_table =
		    malloc(new_hash_table_size * sizeof(hash_binding));
		for (i = 0; i < new_hash_table_size; i++)
			new_hash_table[i] = NULL;
		for (i = 0; i < ht->hash_table_size; i++) {
			hash_binding bind, temp;
			for (bind = ht->hash_table[i]; bind;) {
				int index =
				    bind->hashval % new_hash_table_size;
				temp = bind->next;
				bind->next = new_hash_table[index];
				new_hash_table[index] = bind;
				bind = temp;
			}
		}
		free(ht->hash_table);
		ht->hash_table = new_hash_table;
		ht->hash_table_size = new_hash_table_size;
	}
}

void hash_insert(hash_table ht, void *key, void *obj)
{
	hash_binding old = *(ht->cursor);
	(*(ht->cursor)) = malloc(sizeof(struct hash_binding));
	(*(ht->cursor))->hashval = (*(ht->hash)) (key);
	(*(ht->cursor))->next = old;
	(*(ht->cursor))->obj = obj;
	(*(ht->cursor))->key = key;
	(ht->number_of_bindings)++;
	possibly_increase_size(ht);
}

void hash_delete(hash_table ht)
{
	hash_binding old = *(ht->cursor);
	*(ht->cursor) = old->next;
	free(old);
	(ht->number_of_bindings)--;
	possibly_decrease_size(ht);
}

void hash_map(hash_table ht, void (*fun) (void *object))
{
	int i;
	hash_binding bind;
	for (i = 0; i < ht->hash_table_size; i++) {
		for (bind = ht->hash_table[i]; bind; bind = bind->next)
			(*fun) (bind->obj);
	}
}

void *hash_get(hash_table ht)
{
	return (*(ht->cursor))->obj;
}

int hash_size(hash_table ht)
{
	return (ht->number_of_bindings);
}
