/* Trivial UDP server
  
   Author: Pierre-Jean Turpeau */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>

#include <libprelude/common.h>
#include <libprelude/prelude-log.h>

#include "common.h"
#include "queue.h"
#include "udp-server.h"

struct udp_server {
	int sockfd;
	struct sockaddr_in saddr;
	udp_server_msg_reader_t *mreader;

	pthread_t thread;
	queue_t *queue;
};

udp_server_t *udp_server_new(uint16_t port,
			     udp_server_msg_reader_t * mreader,
			     queue_t * queue)
{
	udp_server_t *server;

	server = malloc(sizeof(*server));
	assert(server);

	server->mreader = mreader;
	server->queue = queue;

	server->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (server->sockfd == -1) {
		log(LOG_ERR, "couldn't create socket.\n");
		return NULL;
	}

	server->saddr.sin_family = AF_INET;
	server->saddr.sin_port = htons(port);
	server->saddr.sin_addr.s_addr = INADDR_ANY;	/* automatically fill with my IP */
	memset(&(server->saddr.sin_zero), '\0', 8);	/* zero the rest of the struct */

	if (bind
	    (server->sockfd, (struct sockaddr *) &server->saddr,
	     sizeof(struct sockaddr)) == -1) {
		log(LOG_ERR, "couldn't bind to socket.\n");
		return NULL;
	}

	dprint("[UDP  ] Server created on port %d, fd %d\n", port,
	       server->sockfd);

	return server;
}

static void udp_server_standalone(udp_server_t * server)
{
	struct sockaddr_in addr;
	int addr_len, numbytes;
	char buf[MAX_UDP_DATA_SIZE];

	while (1) {
		addr_len = sizeof(struct sockaddr);
		numbytes =
		    recvfrom(server->sockfd, buf, MAX_UDP_DATA_SIZE - 1, 0,
			     (struct sockaddr *) &addr, &addr_len);
		buf[MAX_UDP_DATA_SIZE - 1] = '\0';

		if (numbytes == -1) {
			log(LOG_ERR, "couldn't receive on socket.\n");
			exit(1);
		}

		dprint
		    ("[UDP  ] on fd %d got packet from %s:%d - packet is %d bytes long\n",
		     server->sockfd, inet_ntoa(addr.sin_addr),
		     addr.sin_port, numbytes);
		buf[numbytes] = '\0';
		server->mreader(server->queue, buf,
				inet_ntoa(addr.sin_addr));
	}

}

void udp_server_start(udp_server_t * server)
{
	pthread_t thread;

	if (NULL == server)
		return;
	pthread_create(&thread, NULL, (void *) &udp_server_standalone,
		       server);
}

void udp_server_close(udp_server_t * server)
{
	close(server->sockfd);
	free(server);
}
