#ifndef PIPE_QUEUE_H
#define PIPE_QUEUE_H
/*
  Thread safe polymorphic queue using pipes.
  
  Author: Pierre-Jean Turpeau
 */

typedef struct queue queue_t;

typedef void (queue_object_fun_t) (void *object);

queue_t *queue_new(queue_object_fun_t * delete_fun);
void queue_delete(queue_t * queue);
void queue_dump(queue_t * queue, queue_object_fun_t * dump_object);
void queue_push(queue_t * queue, void **object);
void queue_pop(queue_t * queue, void **object);
int queue_get_read_fd(queue_t * queue);

#endif				/* PIPE_QUEUE_H */
