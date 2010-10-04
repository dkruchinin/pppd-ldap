/* ppp_utmp.h
*
* Data definitions
*
*/

#include <pppd.h>

/* line state integers */

#define	IDLE		0
#define	ACTIVE		1
#define UTMP		"/var/run/pppd_utmp"

struct ppp_utmp {

 char		login[MAXNAMELEN]; /* login name */
 char		line[32];	/* terminal line name */
 char		ifname[8];	/* ppp interface name */
 char		cpn[24];	/* A-side number */
 u_int32_t	ip_address; /* peer's IP address */
 time_t		time;		/* last changed */
 int		state;		/* line state */

};

/* Function definitions */

int
write_n(int fd, void *buf, size_t size);

int
read_n(int fd, void *buf, size_t size);

off_t
utmp_seek(int fd, char *line);

int
utmp_count(int fd, char *login);
