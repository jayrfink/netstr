
/* 
 * tcpdump program file
 * see COPYING file for license details.
 */

#define _BSD_SOURCE 1

#include "prog.h"
#include "utils.h"

/*
 * pcap_handler4: This is the ipv4 pcap looper. It is like most pcap callbacks
 *         except it does a lot of printing.
 * requires: all of the standard pcap_loop data
 *
 * XXX-jrf: Would like to clean some of this up. Not sure if it is really
 *          needed since it works as described.
 */
static void pcap_handler4(u_char * args, const struct pcap_pkthdr *header,
			  const u_char * packet)
{
	u_int off, version;          /* offset, version        */
	u_int length = header->len;  /* True header len        */
	u_int id;                    /* Host id                */
	u_int i;                     /* Counter                */
	int len;                     /* real length            */
	eth_hdr *ethernet;           /* The ethernet header    */
	ip4ip *ip;                   /* The IP header          */
	char *protoname = "unknown"; /* string for protocol name */
	char *t;                     /* Timestamp intermediary */
	const struct tcphdr4 *tcp;   /* TCP Header             */
	struct udphdr *udp;          /* udp header info */
	struct icmphdr *icmp;        /* icmp hdr info */
	struct protoent *proto;      /* the proto string */

	/* Extract ethernet, ip and tcp headers */
	ethernet = (eth_hdr *) (packet);	       /* Pointer to ethernet header */
	ip = (ip4ip *) (packet + sizeof(eth_hdr)); /* and ip + eth header size   */
	tcp = (struct tcphdr4 *)(packet +          /* ... all of it together     */
				 sizeof(struct ether_header) +
				 sizeof(struct ip));

	if (ip->ip_v != 4) 
		return;		   /* bagout if it is not ipv4 */

	t = getlocaltime();      /* this is for timestamping */
	len = ntohs(ip->ip_len); /* length and the offset    */
	off = ntohs(ip->ip_off);
	proto = getprotobynumber(ip->ip_p);
	if (proto != NULL)
		protoname = proto->p_name;

	/* There is some formatting duplication here because the alternative would
       be to setup some sort of receiving structure, but, each protocol has
       different data so it all gets done _anyway_ this is similar to how the
       full tcpdump command works */
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		printf("%s: %s:", t, inet_ntoa(ip->ip_src));
		fprintf(stdout, "%u ", ntohs(tcp->th_sport));
		printf("> %s:", inet_ntoa(ip->ip_dst));
		fprintf(stdout, "%u ", ntohs(tcp->th_dport));
		fprintf(stdout,
			"%s len %u off %u ttl %u cksum %u seq %u ack %u win %u\n",
			protoname, len, off, ip->ip_ttl,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr *)(packet + sizeof(struct ip));
		printf("%s: %s:", t, inet_ntoa(ip->ip_src));
		printf("%u ", udp->uh_sport);
		printf("> %s:", inet_ntoa(ip->ip_dst));
		printf("%u ", udp->uh_dport);
		fprintf(stdout,
			"%s len %u sum %u off %u ttl %u cksum %u seq %u ack %u win %u\n",
			protoname, udp->uh_ulen, udp->uh_sum, off, ip->ip_ttl,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
		break;
	case IPPROTO_ICMP:
		icmp = (struct icmphdr *)(packet + sizeof(struct ip));
		printf("%s: %s:", t, inet_ntoa(ip->ip_src));
		printf("> %s", inet_ntoa(ip->ip_dst));
/* BSD Exception code */
#if DARWIN || NETBSD || OPENBSD
		fprintf(stdout,
			"%s len %u off %u ttl %u cksum %u seq %u ack %u win %u\n",
			protoname, len, off, ip->ip_ttl,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
#else
		fprintf(stdout,
			"icmp type %u code %u off %u ttl %u prot %u cksum %u seq %u ack %u win %u\n",
#if FREEBSD
			icmp->icmp_type, icmp->icmp_code,
#else
			icmp->type, icmp->code,
#endif				/* NET and FREEBSD */
			off, ip->ip_ttl, ip->ip_p,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
#endif				/* DARWIN */
		break;
	default:
		printf("%s: %s:", t, inet_ntoa(ip->ip_src));
		fprintf(stdout, "%u ", ntohs(tcp->th_sport));
		printf("> %s:", inet_ntoa(ip->ip_dst));
		fprintf(stdout, "%u ", ntohs(tcp->th_dport));
		fprintf(stdout,
			"??? len %u off %u ttl %u prot %u cksum %u seq %u ack %u win %u\n",
			len, off, ip->ip_ttl, ip->ip_p,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
		break;
	}

	if (pcap_decode_flag)
		decoder(args, header, packet);	/* Call decoder helper function */
}

int tcpdump_main(int argc, char *argv[])
{
	register int c, i;	/* Temporary variable   */
	bpf_u_int32 mask;	/* our netmask          */
	bpf_u_int32 net;	/* our IP adx           */
	uint32_t npolls;	/* Number of pcap polls */
	char *filter = NULL;	/* pcap filter          */
	pcap_t *handle;		/* pcap handle          */
	char errbuf[PCAP_ERRBUF_SIZE];	/* pcap error buffer    */
	struct bpf_program program;	/* BPF filter program   */

	npolls = -1;		/* Default to loop forever */
	pcap_proto_version = 4;	/* Default ipv4 */

	while (1) {
		static struct option long_options[] = {
			{"if", required_argument, 0, 'i'},
			{"polls", required_argument, 0, 'p'},
			{"decode", no_argument, 0, 'd'},
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
		case 'p':
			if (optarg != NULL && isdigit(*optarg)) {
				npolls = atol(optarg);
				if (npolls < 0) {
					fprintf(stderr,
						"Packets must be > than 0\n");
					return EXIT_FAILURE;
				}
			} else {
				fprintf(stderr, "Invalid packet number\n");
				return EXIT_FAILURE;
			}
			break;
		case 'd':
			pcap_decode_flag = 1;
			break;
		default:
			fprintf(stderr, "%s\n", TCPDUMP_USAGE);
			return EXIT_FAILURE;
			break;
		}
	}

	isroot_uid(); /* call utils isroot_uid? */

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

	/* IP: UDP, ICMP, TCP */
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

	/* Main loop */
	printf("Starting capturing engine on %s...\n", pcap_dev);
	if (pcap_proto_version == 4)
		pcap_loop(handle, npolls, pcap_handler4, NULL);
	else
		printf("IPV6 not yet supported\n");

	/* Exit program */
	printf("Closing capturing engine...\n");
	pcap_close(handle);

	return EXIT_SUCCESS;
}

struct prog tcpdump = {
	"tcpdump",
	PROG_TYPE_PCAP,
	tcpdump_main
};
