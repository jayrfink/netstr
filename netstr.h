
/*
 * prog.h
 *
 * Copyright (c) 2010 Jay Fink <jay.fink@gmail.com>
 * See COPYING file for details
 */

#ifndef NETSTR_H
#define NETSTR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
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
#include <getopt.h>
#include <net/if.h>
#ifdef NETBSD
#include <net/if_ether.h>
#endif
#ifdef OPENBSD
#include <netinet/if_ether.h>
#endif
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>


struct prog {
	char	*name;
	int	type;
	int	(*main)(int argc, char *argv[]);
};

/* 
 * Program types
 * DO NOT DEFINE A NEW TYPE unless absolutely required.
 */
#define PROG_TYPE_SCAN	0x16	/* scan and scan6 */
#define PROG_TYPE_PCAP	0x32	/* passive scan, tcpdump and arpsniff */

/*
 * Shared Program data, types and definitions
 * 
 * XXX Put specific header data, types and defines to share here
 */ 

/**** PCAP PROGRAM TYPE SHARED HEADER DATA ****/

/* TCP v4 header */
struct tcphdr4 {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    uint16_t th_win;
    uint16_t check;
    uint16_t urg_ptr;
};

#define ARP_REQUEST 1
#define ARP_RERPLY 2

typedef struct nr_arphdr {
    u_int16_t hwtype;
    u_int16_t proto;
    u_char hwlen;
    u_char proto_len;
    u_int16_t opcode;
    u_char sender_hwaddr[6];
    u_char sender_ipaddr[4];
    u_char target_hwaddr[6];
    u_char target_ipaddr[4];
} arphdr_t;

typedef struct ether_header eth_hdr; /* Ethernet header */
typedef struct ip ip4ip;             /* IP data         */
typedef struct tcphdr4 tcp_hdr;      /* TCP header      */

char * pcap_dev; /* For scan_passive and netdump */
short int pcap_proto_version;	/* protocol version */
short int pcap_decode_flag;	/* do we wish to decode packets? */

/* Prototype for the common packet decoder code */
void decoder (u_char *, const struct pcap_pkthdr *, const u_char *);

/**** SCAN PROGRAM HEADER DATA ****/
#define FAST_SCAN_TIMER 300000 /* When --fast drop to this after a good conn() */
#define PORTMAX 65535 /* shouldn't this be a POSIX thing? */
#define DEFAULT_START_PORT 1    /* default starting port to scan */
#define DEFAULT_END_PORT 1024   /* default ending port to scan */
#define DEFAULT_INET_TIMEOUT 0  /* default connect timeout */
#define DEFAULT_INET_U_TIMEOUT 500000 /* Default timeout in usecs */
/* A relatively common portlist. A 0 must be at the end! */
static int portlist [] = { 22, 80, 445, 25, 37, 53, 111, 113, 139, 21, 42, 67,
                           109, 110, 115, 137, 138, 161, 389, 443, 873, 0 };

/**** PROG_PASSIVE ****/
#define IPV4CW 16	/* IPv4 len */
#define PORT_THRESHOLD_DEFAULT 16 /* Set for small networks */
#define NPOLLS_DEFAULT 64 /* Very short passive scan */
#define PASSIVE_UTIMEO 500000 /* Counterscan timeout */


/**** USAGE Strings for all registered programs ****/
#define SCAN_USAGE "netstr scan     --isup <host> || --port [n]-N| | --strobe |\n                --time s.usec | --fast | -V <host>"

#define SCAN6_USAGE "netstr scan6    --dgram | --port N <ipv6addr>"
#define UDPSCAN_USAGE "netstr udpscan  --timeo sec | <host> || --show"
#ifndef SCAN
#define ARPSNIFF_USAGE "netstr arpsniff --if <dev> | --polls <count> | --decode {pcap-expr}"
#define PASSIVE_USAGE "netstr passive  --if <dev> | --polls <count> | --threshold <n> |  \n                --extra | --no-verify {pcap-expr}"
#define TCPDUMP_USAGE "netstr tcpdump  --if <dev> | --polls <count> | --decode {pcap-expr}"
#endif
#endif /* NETSTR_H */
