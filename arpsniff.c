
#define _BSD_SOURCE 1

#include "netstr.h"
#include "utils.h"

/* This is really just a vanilla libpcap reader using arp it is a pretty
   straightforward thing so there are not a lot of comments               */

static void pcap_arp_loop(uint32_t npolls, pcap_t * handle)
{
	int      i;                  /* Used for the print formatter */
	char     *t;                 /* intermediary timestamp       */
	u_char   *args;              /* pcap args (filters etc       */
	arphdr_t *arpheader;	     /* ARP specific header ptr addr */
	const unsigned char *packet; /* Packet Pointer address       */
	struct pcap_pkthdr   pkthdr; /* Packet Header structure      */

	/* Init safe defaults */
	packet    = NULL;
	arpheader = NULL;

	while (npolls != 0) {
		packet = pcap_next(handle, &pkthdr);
		arpheader = (struct nr_arphdr *)(packet + 14);
		t = getlocaltime();	/* call out localtime helper */
		printf("%s ", t);
		printf("recv-packet-len=%dbytes ", pkthdr.len);
		printf("hwtype=%s ", (ntohs(arpheader->hwtype) == 1) ?
		       "ethernet" : "Unknown");
		printf("proto=%s ", (ntohs(arpheader->proto) == 0x800) ?
		       "ipv4" : "Unknown");
		printf("oper=%s ", (ntohs(arpheader->opcode) == ARP_REQUEST) ?
		       "ARPrequest" : "ARPreply");
		if (ntohs(arpheader->hwtype) == 1 &&
		    ntohs(arpheader->proto) == 0x800) {
			for (i = 0; i < 6; i++)
				if (i < 5)
					printf("%02X:", arpheader->sender_hwaddr[i]);
				else
					printf("%02X ", arpheader->sender_hwaddr[i]);

			for (i = 0; i < 4; i++)
				if (i < 3)
					printf("%d.", arpheader->sender_ipaddr[i]);
				else
					printf("%d ", arpheader->sender_ipaddr[i]);
					      
			printf("-> ");
			for (i = 0; i < 6; i++)
				if (i < 5)
					printf("%02X:", arpheader->target_hwaddr[i]);
				else
					printf("%02X ", arpheader->target_hwaddr[i]);
			for (i = 0; i < 4; i++)
				if (i < 3)
					printf("%d.", arpheader->target_ipaddr[i]);
				else
					printf("%d ", arpheader->target_ipaddr[i]);

			printf("\n");
			npolls--;
		}

		/* If decoding was requested call it */
		if (pcap_decode_flag) decoder(args, &pkthdr, packet);
		
	}

}

int arpsniff_main(int argc, char *argv[])
{
	register int c, i;	 /* Temporary variable   */
	uint32_t npolls;	 /* Number of pcap polls */
	bpf_u_int32 mask;	 /* our netmask          */
	bpf_u_int32 net;	 /* our IP adx           */
	char *filter = NULL; /* pcap filter          */
	pcap_t *handle;		 /* pcap handle          */
	char errbuf[PCAP_ERRBUF_SIZE]; /* pcap error buffer    */
	struct bpf_program program;	   /* BPF filter program   */

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
			fprintf(stderr, "%s\n", ARPSNIFF_USAGE);
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

	if (pcap_compile(handle, &program, "arp", 1, mask) == -1) {
		fprintf(stderr, "Error - `ARP: pcap_compile()'\n");
		return EXIT_FAILURE;
	}

	if (pcap_setfilter(handle, &program) == -1) {
		fprintf(stderr, "Error - `ARP: pcap_setfilter()'\n");
		return EXIT_FAILURE;
	}

	pcap_arp_loop(npolls, handle);
	pcap_freecode(&program);
	return EXIT_SUCCESS;

}

struct prog arpsniff = {
	"arpsniff",
	PROG_TYPE_PCAP,
	arpsniff_main
};
