#ifndef UDP_SERVER_H
#define UDP_SERVER_H

/* Trivial UDP server
  
   Author: Pierre-Jean Turpeau */

#define ETHERNET_LEN 1500
#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN 32	/* if no options in the IP datagram */
#define UDP_HEADER_LEN 8

/* we suppose we are on an ethernet network */
#define MAX_UDP_DATA_SIZE ( ETHERNET_LEN		\
			    - ETHERNET_HEADER_LEN	\
			    - IP_HEADER_LEN		\
			    - UDP_HEADER_LEN )

typedef struct udp_server udp_server_t;

/* Type definition of a message reader function. The str argument is
   the raw UDP datas and the from argument is the IP address of the
   sender. */
typedef void (udp_server_msg_reader_t) (queue_t * queue,
					const char *str, const char *from);

/* Creates a new UDP socket. */
udp_server_t *udp_server_new(uint16_t port,
			     udp_server_msg_reader_t * mreader,
			     queue_t * queue);

/* Start the server within a thread. When a UDP packet is received,
   it's transmited to the udp_server_msg_reader_t function provided
   during creation of the server by a statically allocated string
   buffer.  */
void udp_server_start(udp_server_t * server);

void udp_server_close(udp_server_t * server);

#endif				/* UDP_SERVER_H */
