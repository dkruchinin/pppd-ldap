/* ppp_list.c
*
*  Lists records and it's values from UTMP
*
*
* TODO: Lot's of things... Sorting, displaying, etc.
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF		256

#include "ppp_utmp.h"

int main(argc,argv)
int argc; char *argv[];
{

	int rc; /* return values */
	int fd; /* UTMP file descriptor */
	struct ppp_utmp entry;
	char addr[BUF];
	char time[BUF];

	if ((fd = open(UTMP,O_RDONLY,0600)) == -1)
	{
		fprintf(stderr,"%s: %s\n",argv[0], strerror(errno));
		return -1;
	}

	fprintf(stdout,"%-8s %-20s %-8s %-15s %10s\n",
			"LINE","LOGIN","IFACE","ADDRESS","TIME");

	while(read_n(fd, &entry, sizeof(struct ppp_utmp)) &&
		  entry.state == ACTIVE)
	{
		strftime(time,BUF,"%b %d %T",localtime(&entry.time));
		fprintf(stdout,"%-8s \%-20s %-8s %-15s %-10s\n",
			entry.line,
			entry.login,
			entry.ifname,
			inet_ntop(AF_INET, &entry.ip_address, addr, BUF),
			time
		);

	}

return 1;
}


