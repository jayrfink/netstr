
/*
 * udpscan program file
 * See Copying files for details
 */

#include "prog.h"
#include "utils.h"

/* XXX mv these out to a header file ??? */
#define MAXBUF 1400
#define MAXSCAN 100
#define UDPSCAN_DEFAULT_TIMEOUT 5 /* you can borrow the scan one */

/* rename to scan_data and see what can be added */
typedef struct config {
	int timeout;
} config;

typedef struct port_t {
	u_int16_t number;	// Number of udp port to no
	char *name;			// Name of udp port 
	char *outstring;	// String to send (protocol dependent) sendstr
	int outstringlen;	// Len above to sendlen
	char *instring;		// String to wait (protocol dependent, NULL for *) recvstr
	int instringlen;	// Len above recvlen
	char match;			// Does port match? Allways initialized to 0 
} UDP_scan;

// Port scanning probes definitions (protocol dependent)
struct port_t port[] = {

	7, "echo", 
	  "probe", 5, "probe", 5, 0,

	13, "daytime", 
	  "\x0a", 1, NULL, 0, 0,

	19, "chargen", 
	  "\x0a", 1, NULL, 0, 0,

	// dig @ip localhost A
	53, "dns", 
	  "\x68\x6c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x00\x00\x01\x00\x01", 27, NULL, 0, 0,

	// echo "get a" | tftp ip
	69, "tftp", 
	  "\x00\x01\x61\x00\x6e\x65\x74\x61\x73\x63\x69\x69\x00", 13, NULL, 0, 0,

	// ntpq -p ip
	123, "ntp", 
	  "\x16\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00", 13, NULL, 1, 0,

	// nbtstat -A ip
	137, "ns-netbios", 
	  "\x98\x38\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\00\01", 50, NULL, 1, 0,

	// radtest a a localhost 1 a
	1812, "RADIUS(1812)", 
	  "\x01\x86\x00\x35\x60\x05\x90\x90\x77\x74\x08\x14\xe8\xfa\xb9\x68\x96\x3d\xd1\xba\x01\x03\x61\x02\x12\xd1\x96\xe0\x60\x49\x22\xb5\x68\xca\xc0\xd3\xfc\xd5\x55\x43\x2f\x04\x06\xff\xff\xff\xff\x05\x06\x00\x00\x00\x01", 53, NULL, 1, 0,

	// radtest a a localhost 1 a
	1645, "RADIUS(1645)", 
	  "\x01\x86\x00\x35\x60\x05\x90\x90\x77\x74\x08\x14\xe8\xfa\xb9\x68\x96\x3d\xd1\xba\x01\x03\x61\x02\x12\xd1\x96\xe0\x60\x49\x22\xb5\x68\xca\xc0\xd3\xfc\xd5\x55\x43\x2f\x04\x06\xff\xff\xff\xff\x05\x06\x00\x00\x00\x01", 53, NULL, 1, 0,

	// snmpwalk ip ILMI
	161, "snmp(ILMI)", 
	  "\x30\x24\x02\x01\x00\x04\x04\x49\x4c\x4d\x49\xa1\x19\x02\x04\x18\x39\x99\xcd\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", 38, NULL, 0, 0,

	// snmpwalk ip public
	161, "snmp(public)", 
	  "\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa1\x19\x02\x04\x2c\x60\x2d\xb6\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", 40, NULL, 0, 0,

	0, NULL, NULL, 0, NULL, 0, 0
};

/* XXX might use this to show the supported protos later */
/*
void usage(char *program) 
{
	int i;

	fprintf( stderr,
		"usage: %s [options] <host>\n\n"
		"options:\n"
		" -t <timeout>     Set port scanning timeout\n"
		"\nSupported protocol:\n"
	, program, program);
	for( i=0; port[i].number; i++)
		fprintf( stderr, "%s ", port[i].name );

	fprintf( stderr, "\n\n" );

	exit(-1);
}
*/

struct config conf;

int udpscan_main(int argc, char *argv[]) 
{
	char               buf[MAXBUF], opt, *host;
	int                fd[MAXSCAN], nread, i, j, maxfd, repeat;
	time_t             seconds_start, seconds_now;
	socklen_t          socklen;
	struct timeval     tv;
	struct sockaddr_in dst_addr, src_addr;
	fd_set             fdset;
	struct  hostent    *he;

	conf.timeout = UDPSCAN_DEFAULT_TIMEOUT;

	if (!argv[1]) { /* can't do somethin with nothin */
		fprintf(stderr, "Syntax error\n");
		fprintf(stderr, "%s\n", UDPSCAN_USAGE);
		return EXIT_FAILURE;
	}

	switch (argc) {
	case 2:     /* Trap help print request */
        if ((!strcmp(argv[1], "-?")) || (!strcmp(argv[1], "--usage"))) {
            printf("%s\n", UDPSCAN_USAGE);
            return EXIT_SUCCESS;
        } else {
            break;
        }

    default:
		for (i = 1; i < argc - 1; i++) {
			if (!strcmp(argv[i], "--timeout")) {
				conf.timeout = atoi(argv[i + 1]);
			}
		}
	}


	host = argv[argc-1];

	if( (he = gethostbyname(host)) == NULL) {
		fprintf(stderr, "Error: Cannot resolve %s!\n", host);
		exit(-1);
	}

	for( i = 0; port[i].number; i++ ) {
		if((fd[i] = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror("socket: ");
			exit(2);
		}

		src_addr.sin_family = AF_INET;
		src_addr.sin_addr.s_addr = htonl(INADDR_ANY );
		src_addr.sin_port = 0;

		dst_addr.sin_family = AF_INET;
		dst_addr.sin_addr = *((struct in_addr *)he->h_addr);
		dst_addr.sin_port =  htons(port[i].number);

		if( bind(fd[i], (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0 ) {
			perror("bind: ");
			close(fd[i]);
			exit(4);
		}

		memcpy( buf, port[i].outstring, port[i].outstringlen );
		if(sendto(fd[i], buf, port[i].outstringlen, 0, 
		  (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
			perror("sendto: ");
			close(fd[i]);
			exit(5);
		}
	} /* end for portN */

	time( &seconds_start );

	while( 1 ) {
		time( &seconds_now );
		if( seconds_start+conf.timeout <= seconds_now ) break;
		tv.tv_sec  = conf.timeout - (seconds_now - seconds_start);
		tv.tv_usec = 0;
		FD_ZERO( &fdset );
           
		for( maxfd = 0, i = 0; port[i].number; i++ )
			if( port[i].match == 0 ) {FD_SET( fd[i], &fdset ); maxfd = fd[i];}

		if( select( maxfd+1, &fdset, NULL, NULL, &tv ) < 0 ) {
			perror("select: ");
			exit(6);
		}

		for( i = 0; port[i].number; i++ ) {
			if( !FD_ISSET( fd[i], &fdset ) ) continue;
   
			if( (nread = recvfrom(fd[i], buf, MAXBUF, 0, 
			  (struct sockaddr *)&dst_addr, &socklen)) <= 0 ) {
				port[i].match = 2;
				close( fd[i] );
				continue;
			}
   
		if( port[i].instring == NULL || 
		  !memcmp( buf, port[i].instring, port[i].instringlen ) ) {
			for( repeat = 0, j = 0; j < i; j++ ) 
				if(port[i].number == port[j].number && 
				  port[j].match > 0) repeat=1;
			if( !repeat ) printf( "%s\t%d/udp\n", host, port[i].number );
			port[i].match = 1;
			close( fd[i] );
		}
		} /* endfor portN */
	} /* end while 1 */
	for( i = 0; port[i].number; i++ )
		if( port[i].match == 0 ) close( fd[i] );
   
	exit(0);
}

/* Registration bits */
struct prog udpscan = {
    "udpscan",
    PROG_TYPE_SCAN,
    udpscan_main
};

