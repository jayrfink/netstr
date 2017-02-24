
/*
 * simple pcap packet decoder routine 
 * this is called from a few different places
 * and is NOT an independent set of code like the 
 * utils and ipv4_conn stuff. Not yet anyway.
 * See COPYING file for license 
 */

#include "netstr.h"
#include "utils.h"

void decoder(u_char * args, const struct pcap_pkthdr *header,
	     const u_char * packet)
{
	int i = 0, *counter = (int *)args;

	printf("Packet RECV Size: %d Payload:\n", header->len);
	for (i = 0; i < header->len; i++) {
		if (isprint(packet[i]))
			printf("%c ", packet[i]);
		else
			printf(". ");

		if ((i % 16 == 0 && i != 0) || i == header->len - 1)
			printf("\n");
	}
}
