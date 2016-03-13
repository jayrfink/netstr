
/*
 * scan program file
 * See Copying files for details
 */

#include "prog.h"
#include "utils.h"
#include "ipv4_conn.h"

/*
 * Information and flags used to determine the nature of the scan(s). 
 * This is really cool. By way of pointers we have everything we need
 * and use the real sized intergers we need. Super small, super fast
 * bugger.
 */
struct scan_data {
	u_short port_start;    /* Starting port */
	u_short port_end;      /* Last port */
	short int fflag;       /* fast flag */
	short int iflag;       /* Is alive check only flag */
	short int lflag;       /* short printout flag (line print ports */
	short int vflag;       /* Be verbose */
	int inet_timeo;        /* Connect timeout in seconds */
	int inet_utimeo;       /* Connect timeout useconds value */
	char addr[1024];       /* The raw start address from stdin */
} scandata;                /* Our base struct name */

struct scan_data *sd = &scandata; /* the quick way to get at it... */

/* helper to initialize pertinent scandata */
static void init_scandata(void)
{
	sd->port_start = 0; /* Normally a wicked bad idea, but it is used later */
	sd->port_end = DEFAULT_END_PORT;
	sd->iflag = 0;
	sd->vflag = 0;
	sd->inet_timeo = DEFAULT_INET_TIMEOUT;    /* Set connect timeout in secs */
	sd->inet_utimeo = DEFAULT_INET_U_TIMEOUT;  /* default usec for timer */
}

/* show the defaults for those who ask for the usage info */
static void print_scandata(void)
{
	int x = -1;

	printf("Default/connection timeouts %i secs and %i usecs\n",
		sd->inet_timeo, sd->inet_utimeo);
	printf("Default strobe port range is %i to %i\n",
		DEFAULT_START_PORT, DEFAULT_END_PORT);

	printf("Default portlist (can be changed in header):\n");
	while (portlist[++x] != 0) 
		printf("%i ", portlist[x]);

	printf("\n");
}

/*
 * This is a thin wrapper for ipv4_conn. It is provided to reduce
 * duplication of code by handling the results from ipv4_conn.
 */
static void portcheck(int port)
{
	int conn_status = 0;
	struct servent *portinfo;

	conn_status = ipv4_conn(port,sd->inet_timeo,sd->inet_utimeo,sd->addr);

	if (conn_status > 0) {
		if (sd->iflag) { /* if --isup then print it is up and bagout */
			printf("%s is up\n", sd->addr);
			if (sd->vflag) /* If verbosity is on print out end time */
				printime("Scan end  : ");

			exit(EXIT_SUCCESS);
		}

		/* If --fast is on but user spec'd a lower timeout go with userspec */
		if (sd->fflag) 
			if (sd->inet_utimeo > FAST_SCAN_TIMER)
				sd->inet_utimeo = FAST_SCAN_TIMER;

		portinfo = getservbyport(htons(port),"tcp");
		if (sd->lflag) /* if line print flag is set then do that */
			printf("%d ", port);
		else
			printf("%-5d %-30s\n",port,(portinfo == NULL) 
					? "unkinown" : portinfo->s_name);
	}
		
	if (conn_status < 0) 
		exit(EXIT_FAILURE);

}

/*
 * Scan a range of ports. They better be real or ... the socket will just fail
 */
static void scan_portrange(void)
{
	int port_offset;         /* the current port INDEX being scanned */
	register u_int finished; /* 1 when scanning is finished */

	port_offset= 0; /* addto sd->port_start to retain first port each host */
	finished = 0;   /* this is a performance variable we use (you'll see:) */

    /*  Iterate over a port range even if there is one port. */
	while (((sd->port_start + port_offset) <= sd->port_end) || !finished) {
		portcheck((sd->port_start + port_offset));
		port_offset++;
		if (sd->port_start + port_offset >= sd->port_end)
			finished = 1;
	} 
}


/* this is a helper for main() to parse out 
   n-N and fill in the scandata structure 
   via the sd-> pointer */
static void portparse(char *argv_port)
{
	char *token;

	token = strtok(argv_port, "-");
	if (!token) {
		fprintf(stderr, "Error! No port specified\n");
		fprintf(stderr, "%s\n", SCAN_USAGE);
		exit(EXIT_FAILURE);
	} else {
		sd->port_start = atoi(token);
		token = strtok(NULL, "-");
		if (token)
			sd->port_end = atoi(token);
		else { 
			sd->port_end = sd->port_start;
		}
	}

	if (sd->port_start <= 0) {
		fprintf(stderr, "Starting port is a negative number\n");
		exit(EXIT_FAILURE);
	} else if (sd->port_start > sd->port_end) {
		fprintf(stderr, "Starting port is greater than end port\n");
		exit(EXIT_FAILURE);
	} else if (sd->port_end >= 65535) {
		fprintf(stderr, "End port is past 65534\n");
		exit(EXIT_FAILURE);
	}

}

/* main parser helper function tokenize the NN.nn time string */
static void timerparse(char *argv_timer)
{
	char *token;

	token = strtok(argv_timer, ".");
	if (!token) {
		fprintf(stderr, "Error! No time specified\n");
		fprintf(stderr, "%s\n", SCAN_USAGE);
		exit(EXIT_FAILURE);
	} else {
		sd->inet_timeo = atoi(token);
		token = strtok(NULL, ".'");
		if (token)
			sd->inet_utimeo = atoi(token);
	}

}

/* set the ipaddr in sd->addr */
void set_scanaddr (char *arg)
{
    int o1; /* ipv4 octect 1 */
    int o2; /* ipv4 octect 2 */
    int o3; /* ipv4 octect 3 */
    int o4; /* ipv4 octect 4 */

    struct hostent *host_entry; /* A struct we use normalize an address */

    if (sscanf(arg,"%d.%d.%d.%d",&o1,&o2,&o3,&o4) != 4) {
        host_entry = gethostbyname(arg);
        if (host_entry == NULL) {
            fprintf(stderr,"error: cannot resolve host %s\n",arg);
            exit (0);
        }

        sprintf(sd->addr,"%d.%d.%d.%d",(unsigned char )
            host_entry->h_addr_list[0][0],
            (unsigned char ) host_entry->h_addr_list[0][1],
            (unsigned char ) host_entry->h_addr_list[0][2],
            (unsigned char ) host_entry->h_addr_list[0][3]);
    } else
        strncpy(sd->addr,arg,(1023));
}

/*
 *  Scan Main: Arguably, some stuff (like the subnet loop) could be pushed
 *             out of this but otherwise it is pretty simple.
 */
int scan_main(int argc, char *argv[])
{
	register int i;	  /* input parsing      */
	char *start_time; /* Grab the starting time */

	if (!argv[1]) { /* can't do somethin with nothin */
		fprintf(stderr, "Syntax error\n");
		fprintf(stderr, "%s\n", SCAN_USAGE);
		return EXIT_FAILURE;
	}

	/* Init */
	init_scandata(); /* Initialize the scan data structures */

	switch (argc) {
	case 2:		/* Trap help print request */
		if ((!strcmp(argv[1], "-?")) || (!strcmp(argv[1], "--usage"))) {
			printf("%s\n", SCAN_USAGE);
			print_scandata();
			return EXIT_SUCCESS;
		} else {
			break;
		}

	default:
		for (i = 1; i < argc - 1; i++) {
			/* verbose flag */
			if (!strcmp(argv[i], "-V")) {
				++sd->vflag;
			/* fast scan */
			} else if (!strcmp(argv[i], "--fast")) {
				++sd->fflag;
			/* isalive only check */
			} else if (!strcmp(argv[i], "--isup")) {
				++sd->iflag;
			/* line print ports */
			} else if (!strcmp(argv[i], "--line")) {
				++sd->lflag;
			/* port specification */
			} else if (!strcmp(argv[i], "--port")) {
				portparse(argv[i + 1]);
				i++;
			/* strobe 1-1024 */
			} else if (!strcmp(argv[i], "--strobe")) {
				sd->port_start = DEFAULT_START_PORT;
			/* timer specification */
			} else if (!strcmp(argv[i], "--time")) {
				timerparse(argv[i + 1]);
				i++;
			}
		}
	}

	set_scanaddr(argv[argc - 1]); /* setup the inet addr to be scanned */

	/* if verbose, be so */
	if (sd->vflag) 
		printf("Timeout: %i.%i\n", sd->inet_timeo, sd->inet_utimeo);
	if (sd->vflag) {
		printime("Scan start: ");
		start_time = return_time();
	}

	/* this looks wonky - it is - here is the skinny:
	       - If a single port was specified start will = end. So do the port
             check with one port
	       - if a scan range was specified, call the scan_portrange helper
		   - otherwise assume the default and spin through the portlist using
		     portlist[$i] == 0 as the base case.
	 */
	if (sd->port_start > 0) {
		if (sd->port_start == sd->port_end) 
			portcheck(sd->port_start);
		else
			scan_portrange();
	} else { 
		i = -1;
		while (portlist[++i] != 0) 
			portcheck(portlist[i]);
	}

	if (sd->lflag)
		printf("\n"); /* if doing single line print tack on a newline */
		
	if (sd->vflag) /* more verbosity */
		printime("Scan end  : ");

	return EXIT_SUCCESS;
}

/* Registration bits */
struct prog scan = {
	"scan",
	PROG_TYPE_SCAN,
	scan_main
};
