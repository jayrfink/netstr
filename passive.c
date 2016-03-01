
/*
 * passive scan program file
 * See COPYING file for license details
 */

#define _BSD_SOURCE 1

#include "ipv4_conn.h"
#include "prog.h"
#include "utils.h"

static int xflag = 0;		/* Xtra ports flag. Goes past 1024 */
static int port_threshold;	/* the (connections/port)/protocol */
static int verify_port = 1;	/* By DEFAULT we verify ports */

static void add_list(char *ipaddr, uint16_t port);

/* Here is where passively collected data is kept in a simple list */
struct ipaddr_list {
	char host_ip_address[IPV4CW];	/* The ipaddress in string form */
	struct {
		uint16_t portlist[PORTMAX];	/* The port number that was detected     */
		int tcpconns[PORTMAX];	    /* # of tcp connects for position (port) */
		int udpconns[PORTMAX];	    /* # of udp connects for position (port) */
		int verified;	            /* Has this port been verified? */
	} portdata;
	struct ipaddr_list *next_ptr;	/* Next item in ze list */
};
struct ipaddr_list *first_ptr = NULL;	/* All things must have a start */

/* Add a port or a whole new ipaddr and port */
void addport(char *ipaddr, uint16_t port, char *proto_name)
{
	int x;
	struct ipaddr_list *current_ptr;

	if (strstr(ipaddr, "255") != NULL)
		return;		/* This has a broadcast addr in one of the octets */

	if (strstr(ipaddr, "0.0.0.0") != NULL)
		return;		/* Do not add non real addresses */

	current_ptr = first_ptr;

	/* If this is the first item add it to the list */
	if (current_ptr == NULL) {
		add_list(ipaddr, port);
		return;
	}

	/* 
	 * If we can find the current host by IP 
	 * If we are verifying and it has not been checked yet
	 * verify the port then add it
	 */
	/* XXX-jrf: the callout to ipv4_conn needs MACRO defined timeouts */
	while (current_ptr != NULL) {
		if (strcmp(current_ptr->host_ip_address, ipaddr) == 0) {
			if ((verify_port)
			    && (current_ptr->portdata.verified == 0))
				if (!ipv4_conn(port, 0, 300000, ipaddr)); /*call ipv4_connect*/
			current_ptr->portdata.verified = 1;

			for (x = 0; x < PORTMAX; x++) {
				if (current_ptr->portdata.portlist[x] == 0)
					current_ptr->portdata.portlist[x] =
					    port;

				if (current_ptr->portdata.portlist[x] == port) {
					if (strncmp(proto_name, "tcp", 3))
						current_ptr->
						    portdata.tcpconns[x] =
						    (current_ptr->
						     portdata.tcpconns[x] + 1);

					if (strncmp(proto_name, "udp", 3))
						current_ptr->
						    portdata.udpconns[x] =
						    (current_ptr->
						     portdata.udpconns[x] + 1);

					return;
				}
			}
		}

		current_ptr = current_ptr->next_ptr;
	}

	/* We never found the host. So add it to the end of the list */
	if (current_ptr == NULL)
		add_list(ipaddr, port);
}

/* Add a new entry to the end of the list */
static void add_list(char *ipaddr, uint16_t port)
{
	int x;
	struct ipaddr_list *new_item_ptr;

	new_item_ptr = malloc(sizeof(struct ipaddr_list));
	strcpy((*new_item_ptr).host_ip_address, ipaddr);
	for (x = 0; x < PORTMAX; x++) {
		new_item_ptr->portdata.portlist[x] = 0;
		new_item_ptr->portdata.tcpconns[x] = 0;
		new_item_ptr->portdata.udpconns[x] = 0;
	}

	(*new_item_ptr).portdata.portlist[0] = port;
	(*new_item_ptr).portdata.verified = 0;	/* set verified to no initially */
	(*new_item_ptr).next_ptr = first_ptr;
	first_ptr = new_item_ptr;
}

static void print_hosts(void)
{
	int x, printip;
	struct ipaddr_list *current_ptr;

	current_ptr = first_ptr;

	while (current_ptr != NULL) {
		printip = 0;
		x = 0;

		while (current_ptr->portdata.portlist[x] != 0) {
			if (verify_port) {
				if (current_ptr->portdata.verified == 0) {
					x++;
					continue;
				}
			}

			if ((current_ptr->portdata.tcpconns[x] >=
			     port_threshold)
			    || (current_ptr->portdata.udpconns[x] >=
				port_threshold)) {
				if (!printip)
					printf("%s:",
					       current_ptr->host_ip_address);
				++printip;

				printf(" %u ",
				       current_ptr->portdata.portlist[x]);
				if (current_ptr->portdata.tcpconns[x] >=
				    port_threshold)
					printf("tcp");
				if (current_ptr->portdata.udpconns[x] >=
				    port_threshold) {
					if (current_ptr->portdata.tcpconns[x] >=
					    port_threshold)
						printf("/");

					printf("udp ");
				}
			}
			x++;
		}

		printf("\n");
		current_ptr = current_ptr->next_ptr;
	}
}

/*
 * passive_pcap4: This is the ipv4 pcap looper. It is like most pcap callbacks
 * requires: all of the standard pcap_loop data
 */
static void passive_pcap4(u_char * args, const struct pcap_pkthdr *header,
			  const u_char * packet)
{
	u_int sport;
	u_int dport;
	eth_hdr *ethernet;         /* The ethernet header    */
	ip4ip *ip;                 /* The IP header          */
	struct protoent *proto;
	const struct tcphdr4 *tcp; /* TCP Header             */

	/* Extract ethernet, ip and tcp headers */
	ethernet = (eth_hdr *) (packet);	/* Pointer to ethernet header */
	ip = (ip4ip *) (packet + sizeof(eth_hdr));
	tcp = (struct tcphdr4 *)(packet +
				 sizeof(struct ether_header) +
				 sizeof(struct ip));

	if (ip->ip_v != 4)
		return;		/* don't try to do ipv6  yet */

	dport = ntohs(tcp->th_dport);	/* We only look at the dest port */
	proto = getprotobynumber(ip->ip_p);	/* Fetch the protocol string */

	if ((dport <= 1024) || (xflag))
		addport(inet_ntoa(ip->ip_dst), dport, proto->p_name);
}

int passive_main(int argc, char *argv[])
{
	register int c, i;             /* Temporary variable   */
	bpf_u_int32 mask;              /* our netmask          */
	bpf_u_int32  net;              /* our IP adx           */
	uint32_t     npolls;           /* Number of pcap polls */
	char errbuf[PCAP_ERRBUF_SIZE]; /* pcap error buffer    */
	char *filter = NULL;           /* pcap filter          */
	pcap_t *handle;	               /* pcap handle          */
	struct bpf_program program;    /* BPF filter program   */

	npolls = NPOLLS_DEFAULT;
	port_threshold = PORT_THRESHOLD_DEFAULT;

	/* This is a trick to have long options only as this is the standard
       for how netstr works. However, if one wanted to unglue this piece
       it wouldn't be too difficult                                      */
	while (1) {
		static struct option long_options[] = {
			{"if", required_argument, 0, 'i'},
			{"threshold", required_argument, 0, 'T'},
			{"polls", required_argument, 0, 'p'},
			{"no-verify", no_argument, 0, 'V'},
			{"extra", no_argument, 0, 'X'},
			{0, 0, 0, 0}
		};

		int option_index = 0;

		c = getopt_long(argc, argv, "", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'i':
			pcap_dev = optarg;
			break;
		case 'T':
			port_threshold = u_int_check(optarg);
			break;
		case 'p':
			npolls = u_int_check(optarg);
			break;
		case 'V':
			verify_port = 0;
			break;
		case 'X':
			xflag = 1;
			break;
		case 'u':
			printf("%s\n", PASSIVE_USAGE);
			return EXIT_SUCCESS;
			break;
		default:
			printf("%s\n", PASSIVE_USAGE);
			return EXIT_FAILURE;
			break;
		}
	}

	isroot_uid(); /* call utils  isroot_uid? */

	/* Strip off any none getopt arguments for pcap filter */
	if (!filter)
		filter = copy_argv(&argv[optind]);

	/* Initialize the interface to listen on */
	if ((!pcap_dev)
	    && ((pcap_dev = pcap_lookupdev(errbuf)) == NULL)) {
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}

	if ((handle = pcap_open_live(pcap_dev, 68, 0, 0, errbuf)) == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}

	pcap_lookupnet(pcap_dev, &net, &mask, errbuf);	/* Get netinfo */

	if (filter) {
		if (pcap_compile(handle, &program, filter, 0, net) == -1) {
			fprintf(stderr, "Error - `IP: pcap_compile() IP'\n");
			return EXIT_FAILURE;
		}

		if (pcap_setfilter(handle, &program) == -1) {
			fprintf(stderr, "Error - `IP: pcap_setfilter()'\n");
			return EXIT_FAILURE;
		}

		pcap_freecode(&program);
	}

	printf("Starting capturing engine on %s...\n", pcap_dev);
	pcap_loop(handle, npolls, passive_pcap4, NULL);
	printf("Closing capturing engine...\n");
	pcap_close(handle);
	print_hosts();

	return EXIT_SUCCESS;
}

struct prog passive = {
	"passive",
	PROG_TYPE_PCAP,
	passive_main
};
