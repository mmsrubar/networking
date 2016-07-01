/*
 * TCP port scanner
 *
 * Simple implementation of a TCP port scanner. If the scanned port is filter on
 * the way to destination the the TCP will try to retransmit the lost packet and
 * that takes time. If the destination host has a lot of filtered ports by
 * firewall then the scanning can take really long.
 *
 * mmsrubar@gmail.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>

#define OPEN    1   // socket is opened and listening
#define CLOSED  2   // no one is listening
#define BLOCKED 3   // no response - probably blocked by firewall
#define stat_to_str(s) (s == OPEN) ? "open" : ((s == CLOSED) ? "closed" : "blocked")
static unsigned int socket_status;

void set_dest_port(struct sockaddr *sa, int port_num)
{
  if (sa->sa_family == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)sa;
    addr->sin_port = htons(port_num);
  }
  else {
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)sa;
    addr->sin6_port = htons(port_num);
  }
}

int main(int argc, char *argv[])
{
  struct addrinfo hints, *res, *p;
  struct servent *service;
  int status, port, s, i, rv;

  printf("Simple TCP port scanner\n\n");

  if (argc != 2) {
    fprintf(stderr, "usage: server\n");
    return 1;
  }

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;  // don't care about IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM;

  if ((status = getaddrinfo(argv[1], NULL, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    return 2;
  }

  printf("PORT\t\tSTATE\tSERVICE\n");

  for (port = 1; port < 65535; port++)
  {
    for (i = 0, p = res; p != NULL; i++, p = p->ai_next)
    {
      socket_status = OPEN;   // the port is considered as open by default 
      set_dest_port(p->ai_addr, port);

      // create a socket
      if ((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
        perror("socket");
        continue;
      }

      if ((rv = connect(s, p->ai_addr, p->ai_addrlen)) == -1) {
        if (errno == ECONNREFUSED) {
          socket_status = CLOSED;
          break;
        }
        if (errno == ETIMEDOUT) {
          socket_status = BLOCKED;
          break;
        }
        else {
          perror("connect");
          break;
        }

        continue;
      }

      break;
    }

    close(s); // close the connection

    if (socket_status != CLOSED) {
      if ((service = getservbyport(htons(port), "tcp")) != NULL)
        printf("%5d/tcp\t%s\t%s\n", port, stat_to_str(socket_status), service->s_name);
      else
        printf("%5d/tcp\t%s\n", port, stat_to_str(socket_status));
    }
  }

  freeaddrinfo(res);
  endservent();

  return 0;
}
