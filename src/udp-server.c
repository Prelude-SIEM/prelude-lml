/* Trivial UDP server
  
   Author: Pierre-Jean Turpeau */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>

#include <libprelude/common.h>
#include <libprelude/prelude-log.h>

#include "common.h"
#include "queue.h"
#include "regex.h"
#include "udp-server.h"
#include "file-server.h"


/*
 * From RFC 3164, section 4.1:
 *
 * The full format of a syslog message seen on the wire has three
 * discernable parts.  The first part is called the PRI, the second part
 * is the HEADER, and the third part is the MSG.  The total length of
 * the packet MUST be 1024 bytes or less.
 */
#define SYSLOG_MSG_MAX_SIZE 1024


struct udp_server {
	int sockfd;
	pthread_t thread;
	struct sockaddr_in saddr;

        lml_queue_t *queue;
        regex_list_t *list;
};




static void udp_server_standalone(udp_server_t *server)
{
        int len, ret;
        fd_set fds, rfds;
        struct sockaddr_in addr;
        struct timeval now, last, timeout;
        char buf[SYSLOG_MSG_MAX_SIZE], *ptr;
        
        FD_ZERO(&fds);
        FD_SET(server->sockfd, &fds);
        
        gettimeofday(&last, NULL);
        
	while ( 1 ) {
                
                rfds = fds;
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                
                ret = select(server->sockfd + 1, &rfds, NULL, NULL, &timeout);
                if ( ret < 0 ) {
                        log(LOG_ERR, "select returned an error.\n");
                        return;
                }
                
                gettimeofday(&now, NULL);
                if ( (now.tv_sec - last.tv_sec) > 1 ) {
                        file_server_wake_up(server->list, server->queue);
                        gettimeofday(&last, NULL);
                }
                
                if ( ret != 1 )
                        continue;
                
                len = sizeof(struct sockaddr);

                ret = recvfrom(server->sockfd, buf, sizeof(buf), 0, (struct sockaddr *) &addr, &len);
                if ( ret < 0 ) {
                        log(LOG_ERR, "error receiving syslog message.\n");
                        continue;
                }
                
		dprint("[UDP  ] on fd %d got packet from %s:%d - packet is %d bytes long\n",
                       server->sockfd, inet_ntoa(addr.sin_addr), addr.sin_port, ret);
                
                buf[ret] = '\0';

                /*
                 * we don't care about syslog priority / facility.
                 */
                ptr = strchr(buf, '>');
                if ( ! ptr )
                        ptr = buf;
                
                lml_dispatch_log(server->list, server->queue, ptr, inet_ntoa(addr.sin_addr));
	}
}




void udp_server_start(udp_server_t *server, regex_list_t *list, lml_queue_t *queue)
{
	pthread_t thread;

	if ( ! server )
		return;

        server->list = list;
        server->queue = queue;
	pthread_create(&thread, NULL, (void *) &udp_server_standalone, server);
}



void udp_server_close(udp_server_t *server)
{
	close(server->sockfd);
	free(server);
}



udp_server_t *udp_server_new(const char *addr, uint16_t port)
{
        int ret;
	udp_server_t *server;

        server = malloc(sizeof(*server));
        if ( ! server ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
	server->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if ( server->sockfd < 0 ) {
		log(LOG_ERR, "couldn't create socket.\n");
                free(server);
                return NULL;
	}

        /*
         * resolve provided address, or use INADDR_ANY if no address
         * were provided.
         */
        if ( addr ) {
                ret = prelude_resolve_addr(addr, &server->saddr.sin_addr);
                if ( ret < 0 ) {
                        log(LOG_INFO, "couldn't resolve %s.\n", addr);
                        return NULL;
                }
        } else
                server->saddr.sin_addr.s_addr = INADDR_ANY;
        
        server->saddr.sin_family = AF_INET;
        server->saddr.sin_port = htons(port);
        memset(server->saddr.sin_zero, 0, sizeof(server->saddr));                

        ret = bind(server->sockfd, (struct sockaddr *) &server->saddr, sizeof(struct sockaddr));
        if ( ret < 0 ) {
		log(LOG_ERR, "couldn't bind to socket.\n");
                close(server->sockfd);
                free(server);
                return NULL;
	}
        
	dprint("[UDP ] Server created on %s:%d, fd %d\n", addr, port, server->sockfd);
        
	return server;
}



