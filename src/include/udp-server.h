#ifndef UDP_SERVER_H
#define UDP_SERVER_H

/* Trivial UDP server  
   Author: Pierre-Jean Turpeau */

typedef struct udp_server udp_server_t;


void udp_server_process_event(udp_server_t *server, regex_list_t *list);

/*
 * Creates a new UDP socket.
 */
udp_server_t *udp_server_new(const char *addr, uint16_t port);

void udp_server_close(udp_server_t *server);

int udp_server_get_event_fd(udp_server_t *srvr);

#endif				/* UDP_SERVER_H */
