#ifndef UDP_SERVER_H
#define UDP_SERVER_H

/* Trivial UDP server  
   Author: Pierre-Jean Turpeau */

typedef struct udp_server udp_server_t;

/*
 * Type definition of a message reader function. The str argument is
 * the raw UDP datas and the from argument is the IP address of the
 * sender.
 */
typedef void (udp_server_msg_reader_t)(lml_queue_t *queue,
                                       const char *str, const char *from);

/*
 * Creates a new UDP socket.
 */
udp_server_t *udp_server_new(const char *addr, uint16_t port);

/*
 * Start the server within a thread. When a UDP packet is received,
 * it's transmited to the udp_server_msg_reader_t function provided
 * during creation of the server by a statically allocated string
 * buffer.
 */
void udp_server_start(udp_server_t *server, regex_list_t *list, lml_queue_t *queue);

void udp_server_close(udp_server_t *server);

#endif				/* UDP_SERVER_H */
