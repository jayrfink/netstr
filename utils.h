
#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in_systm.h>
#include <pcap.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#ifdef LINUX
#include <net/ethernet.h>
#endif
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <math.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <semaphore.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <netinet/udp.h>
#include <net/if.h>
#ifdef NETBSD
#include <net/if_ether.h>
#endif
#ifdef OPENBSD
#include <netinet/if_ether.h>
#endif
#include <sys/ioctl.h>
#include <time.h>

void isroot_uid(void);
void printime(char *);
char *return_time(void);
char *getlocaltime(void);
int u_int_check(char *);
char *copy_argv(char **);

#endif /* _UTILS_H */
