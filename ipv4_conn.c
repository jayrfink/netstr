
/*
 * ipv4 port connection module
 */
#include "ipv4_conn.h"

/*
 * ipv4_conn-
 *  requires: portnumber, timeout in seconds, timoue in useconds, address
 *  returns : 1 on success, 0 on fail and -1 on socket failure.
 */
int ipv4_conn (int port, int timeo, int u_timeo, char *scanaddr) 
{
	int s;
	int retval = 0;
	fd_set wset;

    struct sockaddr_in addr;
    struct timeval timeout;

    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) 
		return (-1);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(scanaddr);

    fcntl(s, F_SETFL, O_NONBLOCK);

    connect(s,(struct sockaddr *) &addr, sizeof(addr));

    timeout.tv_sec = timeo;
    timeout.tv_usec = u_timeo;
    FD_ZERO(&wset);
    FD_SET(s, &wset);
	if (select(s+1,NULL,&wset,NULL,&timeout) == 1) {
        int so_error;
        socklen_t len = sizeof so_error;

        getsockopt(s, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0)
            retval++;
    }

    close(s);
    return retval;
}
