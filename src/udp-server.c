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

#include <libprelude/common.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-list.h>

#include "common.h"
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
        log_source_t *ls;
        regex_list_t *rlist;
	struct sockaddr_in saddr;
};



void udp_server_process_event(udp_server_t *server)
{
        int len, ret;
        char src[512];
        struct sockaddr_in addr;
        char buf[SYSLOG_MSG_MAX_SIZE], *ptr;
        
        len = sizeof(struct sockaddr);

        ret = recvfrom(server->sockfd, buf, sizeof(buf), 0, (struct sockaddr *) &addr, &len);
        if ( ret < 0 ) {
                log(LOG_ERR, "error receiving syslog message.\n");
                return;
        }

        buf[ret] = '\0';
        
        snprintf(src, sizeof(src), "%s:%d", inet_ntoa(addr.sin_addr), addr.sin_port);        
        log_source_set_name(server->ls, src);

        /*
         * we don't care about syslog priority / facility.
         */
        ptr = strchr(buf, '>');
        if ( ptr )
                ptr++;
        else 
                ptr = buf;
        
        lml_dispatch_log(server->rlist, server->ls, ptr);
}



void udp_server_close(udp_server_t *server)
{
	close(server->sockfd);
	free(server);
}



int udp_server_get_event_fd(udp_server_t *server) 
{
        if ( ! server )
                return -1;
        
        return server->sockfd;
}



udp_server_t *udp_server_new(regex_list_t *rlist, const char *addr, uint16_t port)
{
        int ret;
	udp_server_t *server;

        server = malloc(sizeof(*server));
        if ( ! server ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        server->rlist = rlist;
        
        server->ls = log_source_new();
        if ( ! server->ls )
                return NULL;
        
	server->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if ( server->sockfd < 0 ) {
		log(LOG_ERR, "couldn't create socket.\n");
                free(server);
                return NULL;
	}

        
        ret = prelude_resolve_addr(addr, &server->saddr.sin_addr);
        if ( ret < 0 ) {
                log(LOG_INFO, "couldn't resolve %s.\n", addr);
                udp_server_close(server);
                return NULL;
        }
        
        server->saddr.sin_family = AF_INET;
        server->saddr.sin_port = htons(port);
        memset(server->saddr.sin_zero, 0, sizeof(server->saddr.sin_zero));                

        ret = bind(server->sockfd, (struct sockaddr *) &server->saddr, sizeof(struct sockaddr));
        if ( ret < 0 ) {
		log(LOG_ERR, "couldn't bind to socket.\n");
                udp_server_close(server);
                return NULL;
	}
                
	return server;
}
