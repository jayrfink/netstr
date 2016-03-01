
/* 
 * main program file for netstr
 * See COPYING file for license details
 */

/* 
 * Here we setup the program modules. Basically all we do is send
 * the command and args off to the appropiate module. Why? It makes
 * managing things like optargs easier. Each module is its own program
 * so this gives us more options for each one and we only use what we
 * need. If they were all integrated as one then we would be allocating
 * more stuff at runtime start.
 */

#include "prog.h"

/*
 * New programs are registered here
 */
extern struct prog scan;
extern struct prog scan6;
#ifndef SCAN
extern struct prog passive;
extern struct prog tcpdump;
extern struct prog arpsniff;
#endif

#ifndef SCAN
static struct prog *programs[] = {
	&scan, &scan6, &passive, &tcpdump, &arpsniff, NULL
};
#else
static struct prog *programs[] = {
	&scan, &scan6, NULL
};
#endif

/* These are all defined in prog.h */
static void print_usage(void)
{
	fprintf(stderr, "Usage: netstr <command> <args> ...\n");
#ifndef SCAN
	fprintf(stderr, "%s\n%s\n%s\n%s\n%s\n",
		SCAN_USAGE, SCAN6_USAGE, PASSIVE_USAGE,
		TCPDUMP_USAGE, ARPSNIFF_USAGE);
#else
	fprintf(stderr, "%s\n%s\n", SCAN_USAGE, SCAN6_USAGE);
#endif
}

/* The hand off function. I got this idea from the dnet utility */
static int do_command(int argc, char *argv[])
{
	struct prog **p;

	for (p = programs; *p != NULL; p++) {
		if (strcmp(argv[0], p[0]->name) == 0)
			return (p[0]->main(argc, argv));
	}
	return (-1);
}

/* Ultra simple. Parse and hand off */
int main(int argc, char *argv[])
{
	if (argc < 2) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	if (do_command(argc - 1, argv + 1) < 0) {
		print_usage();
		exit(1);
	}
	return (EXIT_SUCCESS);
}
