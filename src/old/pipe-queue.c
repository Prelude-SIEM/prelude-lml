/*
  Thread safe polymorphic queue using pipes.
  
  Author: Pierre-Jean Turpeau
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include "common.h"
#include "pipe-queue.h"

struct queue {
	queue_object_fun_t *delete_fun;
	int pipe[2];
	pthread_mutex_t mutex;
};

#define READ  0
#define WRITE 1

queue_t *queue_new(queue_object_fun_t * delete_fun)
{
	queue_t *queue = malloc(sizeof(*queue));
	assert(queue);

	queue->delete_fun = delete_fun;
	pthread_mutex_init(&queue->mutex, NULL);
	assert((pipe(queue->pipe) != -1));

	return queue;
}

void queue_delete(queue_t * queue)
{
	int ret = 0;

	do {
		void *object;
		ret = read(queue->pipe[READ], &object, sizeof(*object));
		queue->delete_fun(object);
	} while (ret >= 0);
	close(queue->pipe[WRITE]);
	close(queue->pipe[READ]);
	free(queue);
}

void queue_push(queue_t * queue, void **object)
{
	assert(queue);

	pthread_mutex_lock(&queue->mutex);

	write(queue->pipe[WRITE], object, sizeof(*object));
	dprint("[QUEUE] new object pushed %p\n", *object);

	pthread_mutex_unlock(&queue->mutex);
}

void queue_pop(queue_t * queue, void **object)
{
	int ret;
	assert(queue);

	pthread_mutex_lock(&queue->mutex);

	ret = read(queue->pipe[READ], object, sizeof(*object));
	if (ret >= 0) {
		dprint("[QUEUE] object popped %p\n", *object);
	} else {
		*object = NULL;
	}

	pthread_mutex_unlock(&queue->mutex);
}

void queue_dump(queue_t * queue, queue_object_fun_t * dump_object)
{
	int ret = 0;
	int entries = 1;

	printf
	    ("=======================================================\n");
	do {
		void *object;

		printf("Object #%d - ", entries);
		ret = read(queue->pipe[READ], &object, sizeof(*object));
		dump_object(object);
		entries++;
	}
	while (ret >= 0);
	printf
	    ("=======================================================\n");
}

int queue_get_read_fd(queue_t * queue)
{
	return queue->pipe[READ];
}
