
/*
 * scan6 program file
 * See COPYING file for license details
 */

/* EXPERIMENTAL: Single host, single port which is about as good as it
                 gets for now. I dunno how many people have looked at
                 ipv6 code but the word "simple" is nowhere to be found
*/

#include "prog.h"
#include "utils.h"

static void quickport6(char *addr, char *portstring, char *socktype)
{
	register short int isalive6 = 0;
	struct addrinfo *res;
	struct addrinfo hints;

	memset(&hints, '\0', sizeof(hints));
	if (socktype == "STREAM")
		hints.ai_socktype = SOCK_STREAM;
	else
		hints.ai_socktype = SOCK_DGRAM;

#ifdef LINUX
	hints.ai_flags = AI_ADDRCONFIG;
#endif

	int e = getaddrinfo(addr, portstring, &hints, &res);
	if (e != 0) {
		printf("Error: %s\n", gai_strerror(e));
		exit(EXIT_FAILURE);
	}

	int sock = -1;
	struct addrinfo *r = res;
	for (; r != NULL; r = r->ai_next) {
		sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (sock != -1 && connect(sock, r->ai_addr, r->ai_addrlen) == 0) {
			printf("Port %s open on %s\n", portstring, addr);
			++isalive6;
			break;
		}
	}

	if (sock != -1)
		close(sock);

	freeaddrinfo(res);
	if (sock != -1)
		if (!isalive6) {
			printf
			    ("Was able to resolve %s but could not connect to port %s\n",
			     addr, portstring);
			close(sock);
			exit(EXIT_FAILURE);
		}

	close(sock);
}

int scan6_main(int argc, char *argv[])
{
	register int i;		/* input parsing      */
	char *portstring = NULL;
	char *socktype = "STREAM";
	char ip6addr[1024];

	if (!argv[1]) {
		fprintf(stderr, "Syntax error\n");
		fprintf(stderr, "%s\n", SCAN6_USAGE);
		return EXIT_FAILURE;
	}

	switch (argc) {
	case 2:		/* Trap help print request */
		if ((!strcmp(argv[1], "-?")) || (!strcmp(argv[1], "--usage"))) {
			printf("%s\n", SCAN6_USAGE);
			return EXIT_SUCCESS;
		} else {
			break;
		}

	default:
		for (i = 1; i < argc - 1; i++) {
			if (!strcmp(argv[i], "--port")) {
				portstring = argv[i + 1];
			} else if (!strcmp(argv[i], "--dgram")) {
				socktype = "DGRAM";
			}
		}
	}

	if (portstring == NULL) {
		fprintf(stderr, "No port specified\n");
		fprintf(stderr, "%s\n", SCAN6_USAGE);
		return EXIT_FAILURE;
	}

	strncpy(ip6addr, argv[argc - 1], 1023);
	printime("Scan start: ");
	return_time();
	quickport6(ip6addr, portstring, socktype);
	printime("Scan end: ");
	return_time();

	return EXIT_SUCCESS;

}

struct prog scan6 = {
	"scan6",
	PROG_TYPE_SCAN,
	scan6_main
};
