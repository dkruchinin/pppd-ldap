#ifndef PPPD_LDAP_H
#define PPPD_LDAP_H

#include <ldap.h>

#include "pppd.h"
#include "chap-new.h"

#ifdef CHAPMS
#include "chap_ms.h"
#endif /* CHAPMS */

#include "fsm.h"
#include "ipcp.h"
#include "lcp.h"
#include "ppp_utmp.h"

/* main.h
*
*  LDAP plugin for pppd
*
*/

#define MAX_BUF	1024
#define SEARCH_TIMEOUT 20
/* main.h - contains defenitions for pppd_ldap plugin */

/* Radius-LDAPv3 schema definitions */

#define RADIUS_OBJECTCLASS		"radiusProfile"
#define RADIUS_DIALUPACCESS		"dialupAccess"
#define RADIUS_FRAMEDIPADDRESS	"radiusFramedIPAddress"
#define RADIUS_FRAMEDMRU		"radiusFramedMTU"
#define RADIUS_IDLETIMEOUT		"radiusIdleTimeout"
#define RADIUS_SESSIONTIMEOUT	"radiusSessionTimeout"
#define RADIUS_AUTHTYPE			"radiusAuthType"
#define LDAP_USERPASSWORD       "userPassword"
#define SAMBA_NTPASSWORDHASH    "sambaNTPassword"
#define SAMBA_LMPASSWORDHASH    "sambaLMPassword"


/* Keeps interpreted data recieved from LDAP */

struct ldap_data {
	int			maxconnect; /* maximum connect time in sec */
	int			maxoctets; /* maximum number of octets, reserved */
	int			maxoctets_dir; /* limit direction, reserved */
	int			idle_time_limit; /* connection idle timeout in sec */
	int			mru; /* Maximum recieve unit, reserved  */
	u_int32_t	addr; /* peer's IP address in network format */
	bool		access_ok; /* 1 if username/password pair correct */
	bool		address_set; /* 1 if addr contains value */
	bool		rebind; /* set to 1, reserved */
};

struct pppd_ldap_opts {
	char host[MAX_BUF];
	char dn[MAX_BUF];
	char password[MAX_BUF];
	char userbasedn[MAX_BUF];
	int	port;
	int	timeout;
	int	nettimeout;
	bool usetls;
	bool lutmp;
	bool debug;
};

typedef int (*chap_verify_fn)(LDAP *ldap, LDAPMessage *entry, char *user,
							  int id, struct chap_digest_type *digest,
							  u_char *challenge, u_char *response,
							  char *message, int message_space);

extern struct pppd_ldap_opts ldap_options;

#ifndef LDAP_FILT_MAXSIZ
#define LDAP_FILT_MAXSIZ 1024
#endif /* !LDAP_FILT_MAXSIZ */

#define pdld_ldap_error(ldap, fmt, args...)                         \
	__pppd_ldap_error(ldap, __FUNCTION__, __LINE__, fmt, ##args)
#define pdld_error(fmt, args...)                                    \
	__pppd_ldap_error(NULL, __FUNCTION__, __LINE__, fmt, ##args)

#define PDLD_DBG(msg, args...) \
	if (ldap_options.debug) { info("[LDAP DEBUG] " msg, ##args); }

#define PDLD_WARN(msg, args...) warn("[LDAP WARN] " msg, ##args)
#define PDLD_INFO(msg, args...) info("[LDAP] " msg, ##args)

/* plugin main functions */

int init_ldap_session(LDAP **out_ldap);
int ldap_login(LDAP *ldap);
void ldap_logount(LDAP *ldap);
int get_user_ldap_msg(LDAP *ldap, const char *uname, LDAPMessage **res_msg);

int ldap_chap_md5_verify(LDAP *ldap, LDAPMessage *entry, char *user,
						 int id, struct chap_digest_type *digest,
						 u_char *challenge, u_char *response,
						 char *message, int message_space);
#ifdef CHAPMS
int ldap_chap_ms_verify(LDAP *ldap, LDAPMessage *entry, char *user,
						int id, struct chap_digest_type *digest,
						u_char *challenge, u_char *response,
						char *message, int message_space);
int ldap_chap_ms2_verify(LDAP *ldap, LDAPMessage *entry, char *user,
						 int id, struct chap_digest_type *digest,
						 u_char *challenge, u_char *response,
						 char *message, int message_space);

#endif /* CHAPMS */
#endif /* PPPD_LDAP_H */
