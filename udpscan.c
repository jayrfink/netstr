
/*
 * udpscan program file
 * See Copying files for details
 */

#include "netstr.h"
#include "utils.h"

#define UDPMAXBUF 1400
#define UDPMAXSCAN 100
#define UDPSCAN_DEFAULT_TIMEOUT 5 /* you can borrow the scan one */

/*
 * Information and flags used to determine timers , verosity etc.
 */
typedef struct udpscan_ops {
	int	timeout; /* The timeout for the _entrie_ host UDP scan not per port */
	int vflag;   /* Verbosity */
} udpscan_ops;
struct udpscan_ops scanops;

/*
 * UDP Port information with payloads, buffers, lengths and match flag 
 */
typedef struct port_t {
	u_short no;         /* portno (port number u_int16_t */
	char    *name;      /* portname */
	char    *sendstr;   /* send string */
	int     sendstrlen; /* sendstr length */
	char    *recvstr;   /* receive string */
	int     recvstrlen; /* receive string length */
	char    match;      /* this port record has a match */
} udp_payloads;

/* 
 * Protocol dependent probe definitions for UDP scanning
 */
struct port_t port[] = {

	7, "echo", 
	  "probe", 5, "probe", 5, 0,

	13, "daytime", 
	  "\x0a", 1, NULL, 0, 0,

	19, "chargen", 
	  "\x0a", 1, NULL, 0, 0,

	/* dig @ip localhost A */
	53, "dns", 
	  "\x68\x6c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x00\x00\x01\x00\x01", 27, NULL, 0, 0,

	/* echo "get a" | tftp ip */
	69, "tftp", 
	  "\x00\x01\x61\x00\x6e\x65\x74\x61\x73\x63\x69\x69\x00", 13, NULL, 0, 0,

	/* ntpq -p ip */
	123, "ntp", 
	  "\x16\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00", 13, NULL, 1, 0,

	/* nbtstat -A ip */
	137, "ns-netbios", 
	  "\x98\x38\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\00\01", 50, NULL, 1, 0,

	/* radtest a a localhost 1 a */
	1812, "RADIUS(1812)", 
	  "\x01\x86\x00\x35\x60\x05\x90\x90\x77\x74\x08\x14\xe8\xfa\xb9\x68\x96\x3d\xd1\xba\x01\x03\x61\x02\x12\xd1\x96\xe0\x60\x49\x22\xb5\x68\xca\xc0\xd3\xfc\xd5\x55\x43\x2f\x04\x06\xff\xff\xff\xff\x05\x06\x00\x00\x00\x01", 53, NULL, 1, 0,

	/* radius test (radtest) to a localhost 1 a */
	1645, "RADIUS(1645)", 
	  "\x01\x86\x00\x35\x60\x05\x90\x90\x77\x74\x08\x14\xe8\xfa\xb9\x68\x96\x3d\xd1\xba\x01\x03\x61\x02\x12\xd1\x96\xe0\x60\x49\x22\xb5\x68\xca\xc0\xd3\xfc\xd5\x55\x43\x2f\x04\x06\xff\xff\xff\xff\x05\x06\x00\x00\x00\x01", 53, NULL, 1, 0,

	/* snmpwal ip ILMI */
	161, "snmp(ILMI)", 
	  "\x30\x24\x02\x01\x00\x04\x04\x49\x4c\x4d\x49\xa1\x19\x02\x04\x18\x39\x99\xcd\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", 38, NULL, 0, 0,

	/* snmpwalk ip public */
	161, "snmp(public)", 
	  "\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa1\x19\x02\x04\x2c\x60\x2d\xb6\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", 40, NULL, 0, 0,

	0, NULL, NULL, 0, NULL, 0, 0
};


/* 
 * Print out the port information 
 */
void print_udp_portinfo(void)
{
	int i;

	printf("Supported UDP Protocols\n");
	for (i = 0; port[i].no; i++)
		printf("%s\n", port[i].name);
}


/*
 * Main called by the module register
 */
int udpscan_main(int argc, char *argv[]) 
{
	char               buf[UDPMAXBUF], opt, *host;
	int                fd[UDPMAXSCAN], nread, i, j, maxfd, repeat;
	time_t             seconds_start, seconds_now;
	socklen_t          socklen;
	struct timeval     tv;
	struct sockaddr_in dst_addr, src_addr;
	fd_set             fdset;
	struct  hostent    *he;

	scanops.timeout = UDPSCAN_DEFAULT_TIMEOUT;
	scanops.vflag   = 0; /* Start quiet */

	if (!argv[1]) { /* can't do somethin with nothin */
		fprintf(stderr, "Syntax error\n");
		fprintf(stderr, "%s\n", UDPSCAN_USAGE);
		return EXIT_FAILURE;
	}

	switch (argc) {
	case 2:     /* Trap help print request */
        if ((!strcmp(argv[1], "--show")) || (!strcmp(argv[1], "--usage"))) {
            printf("%s\n", UDPSCAN_USAGE);
			print_udp_portinfo();
            return EXIT_SUCCESS;
        } else {
            break;
        }

    default:
		for (i = 1; i < argc - 1; i++) {
			/* verbosity ? */
			if (!strcmp(argv[i], "-V")) {
				scanops.vflag = 1;
			/* Set host timeout in seconds */
			} else if (!strcmp(argv[i], "--timeo")) {
				scanops.timeout = atoi(argv[i + 1]);
			}
		}
	}

	host = argv[argc-1]; /* snarf the target */
	if( (he = gethostbyname(host)) == NULL) {
		fprintf(stderr, "Error: Cannot resolve %s!\n", host);
		exit(-1);
	}

	/* 
	 * Since we got this far if we are being verbose
	 */
	if (scanops.vflag)
		printf("Host timeout: %i\n", scanops.timeout);
	if (scanops.vflag) 
		printime("Scan start: ");

	/* Set socks */
	for( i = 0; port[i].no; i++ ) {
		if((fd[i] = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror("socket: ");
			exit(2);
		}

		src_addr.sin_family = AF_INET;
		src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		src_addr.sin_port = 0;

		dst_addr.sin_family = AF_INET;
		dst_addr.sin_addr = *((struct in_addr *)he->h_addr);
		dst_addr.sin_port =  htons(port[i].no);

		if( bind(fd[i], (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0 ) {
			perror("bind: ");
			close(fd[i]);
			exit(4);
		}

		memcpy( buf, port[i].sendstr, port[i].sendstrlen );
		if(sendto(fd[i], buf, port[i].sendstrlen, 0, 
		  (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
			perror("sendto: ");
			close(fd[i]);
			exit(5);
		}
	} /* end for portN */

	time( &seconds_start );

	/*
	 * The core algorithm is here. Running a base case of "we are out
	 * of time" loop through the UDP structure protocol by protocol
	 * if we find a match mark it and move on.
	 */
	while(1) {
		time(&seconds_now);
		if( seconds_start+scanops.timeout <= seconds_now ) break;
		tv.tv_sec  = scanops.timeout - (seconds_now - seconds_start);
		tv.tv_usec = 0;
		FD_ZERO( &fdset );
           
		for( maxfd = 0, i = 0; port[i].no; i++ )
			if( port[i].match == 0 ) {FD_SET( fd[i], &fdset ); maxfd = fd[i];}

		if( select( maxfd+1, &fdset, NULL, NULL, &tv ) < 0 ) {
			perror("select: ");
			exit(6);
		}

		for( i = 0; port[i].no; i++ ) {
			if( !FD_ISSET( fd[i], &fdset ) ) continue;
   
			if( (nread = recvfrom(fd[i], buf, UDPMAXBUF, 0, 
			  (struct sockaddr *)&dst_addr, &socklen)) <= 0 ) {
				port[i].match = 2;
				close( fd[i] );
				continue;
			}
   
		if( port[i].recvstr == NULL || 
		  !memcmp( buf, port[i].recvstr, port[i].recvstrlen ) ) {
			for( repeat = 0, j = 0; j < i; j++ ) 
				if(port[i].no == port[j].no && 
				  port[j].match > 0) repeat=1;
			if( !repeat ) printf( "%s\t%d/udp\n", host, port[i].no );
			port[i].match = 1;
			close( fd[i] );
		}
		} /* endfor portN */
	} /* end while 1 */
	for( i = 0; port[i].no; i++ )
		if( port[i].match == 0 ) close( fd[i] );

	if (scanops.vflag)
		printime("Scan end  : ");
   
	return EXIT_SUCCESS;
}

/* Registration bits */
struct prog udpscan = {
    "udpscan",
    PROG_TYPE_SCAN,
    udpscan_main
};

