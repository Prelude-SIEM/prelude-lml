#ifndef QUEUE_H
#define QUEUE_H
/* Thread safe polymorphic queue.
  
   Author: Pierre-Jean Turpeau */

typedef struct queue lml_queue_t;

typedef void (queue_object_fun_t) (void *object);

/* Create a queue. The argument delete_fun is a function used by
   queue_delete() to delete queued object. If NULL, objects are not
   freed by queue_delete(). */
lml_queue_t *queue_new(queue_object_fun_t * delete_fun);

/* Destroy a queue */
void queue_delete(lml_queue_t * queue);

/* Print on stdout the content of the queue. The argument dump_object
   is a function used to dump each object. */
void queue_dump(lml_queue_t * queue, queue_object_fun_t * dump_object);

/* return 1 is the queue is empty. return 0 if not. */
int queue_empty(lml_queue_t * queue);

/* Push the object pointer in the tail of the queue. */
void queue_push(lml_queue_t * queue, void *object);

/* Pop the pointer at the head of the queue. It's a blocking operation
   if the queue is empty. */
void *queue_pop(lml_queue_t * queue);

#endif				/* QUEUE_H */
