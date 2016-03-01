
/* 
 * Some simple utilities
 * see COPYING file for license details
 */

#include "utils.h"

/* got root? */
void isroot_uid(void)
{
	if (getuid()) {
		fprintf(stderr, "Must be root user.\n");
		exit ( EXIT_FAILURE );
	}
}

/* print the current time along with a message */
void printime(char *msg)
{
	time_t curtime;
	char buffer[256];
	struct tm *loctime;

	curtime = time(NULL);
	loctime = localtime(&curtime);
	printf("%s", msg);
	fputs(asctime(loctime), stdout);
}

/* Return the current time */
char *return_time(void)
{
	time_t curtime;
	char buffer[256];
	struct tm *loctime;

	curtime = time(NULL);
	loctime = localtime(&curtime);

	return (asctime(loctime));
}

/*
 * getlocaltime: Retrieve localtime and send it back as a string
 */
char *getlocaltime(void)
{
	time_t result;
	char *t;

	t = "";
	result = time(NULL);
	t = asctime(localtime(&result));
	t[strlen(t) - 1] = ' ';
	t[strlen(t)] = 0;

	return (t);
}

/*
 * u_int_check: Make sure a value is a positive integer and greater than 0.
 */
int u_int_check(char *value)
{
	int retval;

	if (value != NULL && isdigit(*value)) {
		retval = atol(value);
		if (retval < 0) {
			fprintf(stderr, "Value must be greater than 0\n");
			exit(EXIT_FAILURE);
		}
	} else {
		fprintf(stderr, "Invalid input value.\n");
		exit(EXIT_FAILURE);
	}

	return (retval);
}

/* copy_argv: Copy off an argument vector */
char *copy_argv(char **argv)
{
	u_int len = 0;
	char **p;
	char *buf;
	char *src, *dst;

	p = argv;

	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	if (buf == NULL) {
		fprintf(stdout, "copy_argv: malloc");
		exit(EXIT_FAILURE);
	}

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0') ;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}
