/* Thread safe polymorphic queue.
  
   Author: Pierre-Jean Turpeau */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <assert.h>

#include <libprelude/prelude-log.h>

#include "common.h"
#include "queue.h"

typedef struct queue_entry {
	struct queue_entry *next;
	void *object;
} queue_entry_t;

struct queue {
	queue_entry_t *head;
	queue_entry_t *tail;
	int entries;
	queue_object_fun_t *delete_fun;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};



queue_t *queue_new(queue_object_fun_t *delete_fun)
{
	queue_t *queue;

        queue = malloc(sizeof(*queue));
        if ( ! queue ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
	queue->entries = 0;
	queue->head = NULL;
	queue->tail = NULL;
	queue->delete_fun = delete_fun;

	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->cond, NULL);

	return queue;
}



void queue_delete(queue_t *queue)
{
	queue_entry_t *entry = queue->head;

	while ( entry != NULL) {
		queue_entry_t *tmp = entry->next;

                if ( queue->delete_fun )
			queue->delete_fun(entry->object);
                
		free(entry);
		entry = tmp;
	}
}



inline static queue_entry_t *queue_entry_new(void)
{
	queue_entry_t *new_entry;

        new_entry = malloc(sizeof(*new_entry));
	if ( ! new_entry ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

	new_entry->next = NULL;
	new_entry->object = NULL;

	return new_entry;
}




void queue_push(queue_t *queue, void *object)
{
	queue_entry_t *new_entry;

        new_entry = queue_entry_new();
        if ( ! new_entry ) {
                log(LOG_ERR, "memory exhausted.\n");
                return;
        }
        
	new_entry->object = object;
	pthread_mutex_lock(&queue->mutex);

	if ( queue->tail ) {
		queue->tail->next = new_entry;
		queue->tail = new_entry;
	} else {
		queue->head = new_entry;
		queue->tail = new_entry;
	}

	queue->entries++;

	dprint("[QUEUE] new object pushed %p\n", object);

	if ( queue->entries == 1 )
		pthread_cond_broadcast(&queue->cond);

	pthread_mutex_unlock(&queue->mutex);
}



int queue_empty(queue_t *queue)
{
	int ret;
        
	assert(queue);
	pthread_mutex_lock(&queue->mutex);
	ret = (queue->entries <= 0 || NULL == queue->head) ? 1 : 0;
	pthread_mutex_unlock(&queue->mutex);
        
	return ret;
}



void *queue_pop(queue_t *queue)
{
	void *object;
	queue_entry_t *tmp;

	assert(queue);

	do {
		pthread_mutex_lock(&queue->mutex);
		if (queue->entries <= 0 || queue->head == NULL ) {
			pthread_cond_wait(&queue->cond, &queue->mutex);
			pthread_mutex_unlock(&queue->mutex);

		} else
			break;
	} while ( 1 );

	object = queue->head->object;
	tmp = queue->head->next;
	free(queue->head);
	queue->head = tmp;

	if ( ! queue->head )
		queue->tail = NULL;

	queue->entries--;
	dprint("[QUEUE] object popped %p\n", object);

	pthread_mutex_unlock(&queue->mutex);

	return object;
}




void queue_dump(queue_t *queue, queue_object_fun_t *dump_object)
{
	int entries = 0;
	queue_entry_t *entry = queue->head;

	printf("=======================================================\n");

        while ( entry != NULL ) {
		printf("Object #%d - ", entries);
		if ( dump_object )
			dump_object(entry->object);
		else
			printf(" dump function is NULL\n");
		entries++;
		entry = entry->next;
	}
	printf("%d entrie(s) registered - %d entries in queue\n",
	       queue->entries, entries);

        printf("=======================================================\n");
}
