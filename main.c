/*******************************************************************
 * main.c
 *
 * LDAP plugin for pppd. Performs PAP authentication and sets
 * pppd parameters using LDAP as a backend.
 *
 * Copyright (c) Nordcomp LTD, Syktyvkar, Russian Federation
 * Initial version written by Grigoriy Sitkarev <sitkarew@nordcomp.ru>
 *
 * This plugin may be distributed according to the terms of the GNU
 * General Public License, version 2 or any later version.
 *
 ********************************************************************/
/*
 * 2004/05/17: first release!!! :) v 0.10
 *
 * 2004/05/19: Small bugfix. If peer's address was specified by pppd options
 * at startup use it if can't get if from LDAP. Usefull feature for those
 * who needn't have per-user fixed IP for one part and define fixed IP for
 * another through LDAP.
 *
 * 2004/05/20: Cleanups. IP address handling improved.
 *
 * 2004/05/21: Plugin can talk TLS/SSL now. Added a hack to run with servers
 * which can use only LDAPS. Code seems beeing more clean. Created TODO file.
 * v 0.11 --> v 0.11b
 *
 * 2004/05/30: Plugin can log ppp session data (login, line, IP, time etc) to
 * ppp_utmp file. A simple tool "ppp_list" can list active entries. New option
 * "lutmp" introduced. This functionality NEEDS COMPEHENSIVE TESTING.
 * v 0.11b --> v 0.12
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>

#include <netinet/in.h>
#include "pppd_ldap.h"

#define PPPD_LD_DEFAULT_HOST       "localhost"
#define PPPD_LD_DEFAULT_TIMEOUT    15
#define PPPD_LD_DEFAULT_NETTIMEOUT 10

char pppd_version[] = VERSION;
static char rcsid[] = "$Id: main.c, v 0.12 2004/05/30 22:34:45 sitkarev Exp$";

struct pppd_ldap_opts ldap_options;
static struct ldap_data ldap_data;

static option_t options[] = {

		{ "ldaphost", o_string, ldap_options.host,
		  "LDAP server host name",
		  OPT_PRIV | OPT_STATIC, NULL, (MAX_BUF - 1)},

		{ "ldapdn", o_string, ldap_options.dn,
		  "DN to bind with to LDAP server",
		  OPT_PRIV | OPT_STATIC, NULL, (MAX_BUF - 1)},

		{ "ldappw", o_string, ldap_options.password,
		  "DN password",
		  OPT_PRIV | OPT_STATIC, NULL, (MAX_BUF - 1)},

		{ "ldapport", o_int, &ldap_options.port,
		  "LDAP server port",
		  OPT_PRIV | OPT_STATIC},

		{ "userbasedn", o_string, ldap_options.userbasedn,
		  "LDAP user base DN",
		  OPT_PRIV | OPT_STATIC, NULL, (MAX_BUF - 1)},

		{ "ldaptimeout", o_int, &ldap_options.timeout,
		  "LDAP search timeout",
		  OPT_PRIV | OPT_STATIC},

		{ "ldapnettimeout", o_int, &ldap_options.nettimeout,
		  "LDAP network activity timeout",
		  OPT_PRIV | OPT_STATIC },
#ifdef OPT_WITH_TLS
		{ "ldapusetls", o_bool, &ldap_options.usetls,
		  "Connect to LDAP server using TLS", 1},
#endif

		{ "lutmp", o_bool, &ldap_options.lutmp,
		  "Write session data to ppp_utmp", 1},

		{ NULL }
};

static int ldap_chap_check(void);
static int ldap_chap_verify(char *user, char *ourname, int id,
                            struct chap_digest_type *digest,
                            unsigned char *challenge,
                            unsigned char *response,
                            char *message, int message_space);

static void init_ldap_options(void)
{
		memset(&ldap_options, 0, sizeof(ldap_options));
		strncpy(ldap_options.host, PPPD_LD_DEFAULT_HOST, MAX_BUF);
		ldap_options.port = LDAP_PORT;
		ldap_options.timeout = PPPD_LD_DEFAULT_TIMEOUT;
		ldap_options.nettimeout = PPPD_LD_DEFAULT_NETTIMEOUT;
}

int plugin_init()
{
		init_ldap_options();
		add_options(options);

		pap_check_hook = ldap_pap_check;
		pap_auth_hook =	ldap_pap_auth;

		chap_check_hook = ldap_chap_check;
		chap_verify_hook = ldap_chap_verify;

		ip_choose_hook = ldap_ip_choose;
		allowed_address_hook = ldap_address_allowed;

		add_notifier(&ip_down_notifier, ldap_ip_down, NULL);
		add_notifier(&ip_up_notifier, ldap_ip_up, NULL);

		PDLD_INFO("Plugin initialized.");
}

static bool
can_auth_user(LDAP *ldap, LDAPMessage *entry)
{
		struct berval **vals;
		bool ret = 0;

		vals = ldap_get_values_len(ldap, entry, RADIUS_AUTHTYPE);
		if (!vals) {
				pdld_ldap_error(ldap, "Failed to get authtype %s", RADIUS_AUTHTYPE);
				goto out;
		}
		if (strncasecmp(vals[0]->bv_val, "LDAP", 4) != 0) {
				pdld_error("Sorry, only authtype=LDAP is supported");
				goto out;
		}

		ldap_value_free_len(vals);
		vals = ldap_get_values_len(ldap, entry, RADIUS_DIALUPACCESS);
		if (!vals) {
				pdld_ldap_error(ldap, "Failed to get value of attribute %s",
								RADIUS_DIALUPACCESS);
				goto out;
		}
		if (strncasecmp(vals[0]->bv_val, "YES", 3) != 0) {
				pdld_error("Dialup access disabled for given user");
				goto out;
		}

		ret = 1;
out:
		if (vals)
				ldap_value_free_len(vals);

		return ret;
}

static int
ldap_chap_verify(char *user, char *ourname, int id,
				 struct chap_digest_type *digest,
				 unsigned char *challenge,
				 unsigned char *response,
				 char *message, int message_space)
{
		int challenge_len, response_len, err;
		int loged_in = 0, ok;
		LDAP *ldap;
		LDAPMessage *result_msg, *ldap_entry;
		chap_verify_fn verifier = NULL;

		result_msg = NULL;
		challenge_len = *challenge;
		response_len = *response;

		PDLD_DBG(" => ldap_chap_verify called. User = %s\n", user);
		if ((digest->code != CHAP_MD5)
#ifdef CHAPMS
			&& (digest->code != CHAP_MICROSOFT)
			&& (digest->code != CHAP_MICROSOFT_V2)
#endif /* CHAPMS */
				) {
				PDLD_WARN("Unknown digest code: %d (user %s)\n",
						  digest->code, user);
				goto reject_auth;
		}

		err = init_ldap_session(&ldap);
		if (err != LDAP_SUCCESS) {
				pdld_error("Failed to initialize ldap session: %s",
						   ldap_err2string(err));
				goto reject_auth;
		}

		err = ldap_login(ldap);
		if (err) {
				pdld_ldap_error(ldap, "ldap_login() failed");
				goto reject_auth;
		}

		loged_in = 1;
		err = get_user_ldap_msg(ldap, user, &result_msg);
		if (err) {
				pdld_ldap_error(ldap, "Failed to find LDAP user %s", user);
				goto reject_auth;
		}
		if (!result_msg) {
				pdld_ldap_error(ldap, "No such user: %s", user);
				goto reject_auth;
		}

		ldap_entry = ldap_first_entry(ldap, result_msg);
		if (!can_auth_user(ldap, ldap_entry))
				goto reject_auth;

		switch (digest->code) {
		case CHAP_MD5:
				verifier = ldap_chap_md5_verify;
				break;
		case CHAP_MICROSOFT:
				verifier = ldap_chap_ms_verify;
				break;
		case CHAP_MICROSOFT_V2:
				verifier = ldap_chap_ms2_verify;
				break;
		}

		ok = verifier(ldap, ldap_entry, user, id,
					  digest, challenge, response,
					  message, message_space);
		if (!ok)
				goto reject_auth;

		PDLD_DBG("User %s was successfully authenticated. Access granted.\n",
				 user);
		ldap_msgfree(result_msg);
		ldap_logout(ldap);
		return ok;

reject_auth:
		if (result_msg)
				ldap_msgfree(result_msg);
		if (loged_in)
				ldap_logout(ldap);

		PDLD_DBG("Authentication rejected for user %s\n", user);
		return 0;
}

static int ldap_chap_check(void)
{
		PDLD_DBG("LDAP_CHAP_CHECK!\n");
		return 1;
}

/*
 *	FUNCTION: ldap_pap_auth()
 *	PURPOSE: Authenticates PAP user against LDAP server.
 *
 *	ARGUMENTS:
 *	user - user name
 *	password - user password
 *	msgp - PAP message to send
 *
 *	RETURN:  0 - Supplied username/password values incorrect
 *			 1 - Success
 *			-1 - Error, proceed to normal pap-options file
 */
#define LDAP_URL_LEN 512
static int ldap_pap_auth(char *user, char *password, char **msgp,
                         struct wordlist **paddrs, struct wordlist **popts)
{
		int rc,ldap_errno;
		int version = LDAP_VERSION3;
		char filter[LDAP_FILT_MAXSIZ];
		char userdn[MAX_BUF];
		char url[LDAP_URL_LEN];
		char **ldap_values;
		LDAP *ldap;
		LDAPMessage *ldap_mesg;
		LDAPMessage	*ldap_entry;

		PDLD_DBG("PAP_AUTH user %s\n", user);
		/* Initiate session and bind to LDAP server */
		sprintf(url, "ldap://%s:%d", ldap_options.host, ldap_options.port);
		if (ldap_initialize(&ldap, url) != LDAP_SUCCESS) {
				error("LDAP: Failed to initialize session: %s:%d\n",
					  strerror(errno), errno);
				return -1;
		}

		/* Set LDAP specific options such as timeout, version and tls */

		if ((rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION,
								  &version) != LDAP_OPT_SUCCESS)) {
				error("LDAP: failed to set protocol version\n");
				return -1;
		}

		if ((rc = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT,
								  &ldap_options.nettimeout) != LDAP_OPT_SUCCESS)) {
				error("LDAP: failed to set network timeout version\n");
				return -1;
		}

		if ((rc = ldap_set_option(ldap, LDAP_OPT_TIMELIMIT,
								  &ldap_options.timeout) != LDAP_OPT_SUCCESS)) {
				error("LDAP: failed to set timeout option\n");
				return -1;
		}

#ifdef OPT_WITH_TLS

		/* Some servers support only LDAPS but not TLS */
		if ((ldap_options.port == LDAPS_PORT) && ldap_options.usetls) {
				int tls_opt = LDAP_OPT_X_TLS_HARD;
				if ((rc = ldap_set_option(ldap, LDAP_OPT_X_TLS,
										  (void *)&tls_opt)) != LDAP_SUCCESS) {
						ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
						error("LDAP: failed to set TLS option: %s\n", ldap_err2string(rc));
						return -1;
				}
		}

		if (ldap_options.usetls) {
				PDLD_DBG("Setting TLS option -> ON\n");
				if((rc = ldap_start_tls_s(ldap, NULL, NULL) != LDAP_SUCCESS)) {
						ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
						error("LDAP: failed to initiate TLS: %s\n", ldap_err2string(ldap_errno));
						return -1;
				}
		};

#endif

		/* Perform binding at last */

		if ((rc = ldap_bind_s(ldap, ldap_options.dn, ldap_options.password, LDAP_AUTH_SIMPLE)) != LDAP_SUCCESS) {
				ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
				error("LDAP: failed to bind: %s\n",ldap_err2string(rc));
				ldap_unbind(ldap);
				return -1;
		}

		/* Form a search filter from supplied peer's credentials */

		if ((rc = snprintf(filter, LDAP_FILT_MAXSIZ,"(&(uid=%s)(objectClass=%s))",
						   user, RADIUS_OBJECTCLASS)) == -1) {
				error("LDAP: LDAP filter too big\n");
				ldap_unbind(ldap);
				return -1;
		};

		PDLD_DBG("search filter: %s\n",filter);
		/* Perform search*/

		if ((rc = ldap_search_s(ldap, ldap_options.userbasedn, LDAP_SCOPE_SUBTREE, filter,
								NULL, 0, &ldap_mesg)) != LDAP_SUCCESS) {
				ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
				error("LDAP: Can't perform search: %s\n",
					  ldap_err2string(rc));
				ldap_unbind(ldap);
				return -1;
		};

		/* If search returned more than 2 results or 0 - something is wrong! */

		if ( ldap_mesg == NULL ){
				info("LDAP: No such user \"%s\"\n",user);
				ldap_unbind(ldap);
				return -1;
		}

		if ((ldap_count_entries(ldap, ldap_mesg)) > 1){
				warn("LDAP: more than one user \"%s\" exists!\n",user);
				ldap_unbind(ldap);
				return -1;
		}

		/* Check existance of dialupAccess attribute and it's value */
		PDLD_DBG("LDAP: found %u entries\n",ldap_count_entries(ldap, ldap_mesg));

		/* radiusAuthType = LDAP ->  check it! */

		ldap_entry = ldap_first_entry(ldap, ldap_mesg);

		ldap_values = ldap_get_values(ldap, ldap_entry, RADIUS_AUTHTYPE);

		if (ldap_count_values(ldap_values) != 0) {

				if ((strncasecmp(ldap_values[0],"LDAP",4) != 0)) {
						PDLD_DBG("Sorry, only authtype=LDAP is supported\n");
						ldap_unbind(ldap);
						ldap_msgfree(ldap_mesg);
						return -1;
				}
		} else {
				PDLD_DBG("Can not get authentication type\n");
				ldap_unbind(ldap);
				ldap_msgfree(ldap_mesg);
				return -1;
		}

		ldap_values = ldap_get_values(ldap, ldap_entry, RADIUS_DIALUPACCESS);
		if (((strncasecmp(ldap_values[0],"YES",3) == 0)) ||
			((strncasecmp(ldap_values[0],"FALSE",5)) != 0)) {

				/* Rebind with peers supplied credentials */

				if ((rc = snprintf(userdn,MAX_BUF,"%s",ldap_get_dn(ldap,ldap_entry))) == -1)
						warn("LDAP: user DN stripped\n");

				PDLD_DBG("LDAP: rebind DN: %s\n",userdn);
				if ((rc = ldap_simple_bind_s(ldap,userdn,password)) != LDAP_SUCCESS) {
						error("LDAP: username or password incorrect\n");
						*msgp = "Username or password incorrect!";
						ldap_unbind(ldap);
						ldap_msgfree(ldap_mesg);
						return 0;
				}
		} else {

				error("LDAP: dialup access disabled for user %s\n",user);
				*msgp = "Dial-in access not allowed!";
				ldap_unbind(ldap);
				ldap_msgfree(ldap_mesg);
				return 0;
		}

		/* Set pppd options */

		ldap_setoptions(ldap, ldap_mesg, &ldap_data);

		PDLD_DBG("Auth success\n");
		*msgp = "Access OK!";
		ldap_data.access_ok = 1;

		/* Write ppp_utmp data in place */

		return 1;
}

static void ldap_ip_choose(u_int32_t *addrp)
{
		if (ldap_data.address_set)
				*addrp = ldap_data.addr;
}

static void ldap_ip_down(void *opaque, int arg)
{
		if(ldap_options.lutmp)
				ldap_deactivate_utmp(devnam);
}

static void ldap_ip_up(void *opaque, int arg)
{
		PDLD_DBG("ldap_ip_up notifier: lutmp %d\n", ldap_options.lutmp);
		if(ldap_options.lutmp)
				ldap_activate_utmp(&ldap_data, devnam, ifname, peer_authname);
}

static int ldap_address_allowed(u_int32_t addr)
{
		/* if (ldap_data.address_set) return 1;*/
		if (ntohl(addr) == ldap_data.addr) return 1;

		/* if peer's address was specified in options
		   allow it */
		if ((ipcp_wantoptions[0].hisaddr != 0) &&
			(ipcp_wantoptions[0].hisaddr == addr)) return 1;

		return 0;
}

static int ldap_pap_check(void)
{
		return 1;
}


/*
 *	FUNCTION: ldap_activate_utmp(struct ldap_data *ldap_data,
 char *devnam, char *ppp_devname, char *user);
 *	PURPOSE: Writes ppp session data to ppp_utmp file
 *	ARGUMENTS:
 *	ldap_data - pointer to ldap_data structure
 *	devnam - 	tty device name ("/dev/" will be stripped)
 *	ppp_devname - interface name (ppp1, ppp0, etc) associated with
 *				ppp session
 *	user -		user login name
 *
 *	RETURNS: -1 in case of error
 1 if success
*/

static int ldap_activate_utmp(struct ldap_data *ldap_data,
                              char *devnam, char *ppp_devname, char* user)
{
		int rc;
		int fd;
		off_t offset;
		struct ppp_utmp entry;

		memset(&entry, 0, sizeof(struct ppp_utmp));

		if ((fd = open(UTMP , O_RDWR | O_CREAT, 0644)) == -1)
		{
				error("LDAP: can't open utmp file\n");
				return -1;
		}

		if(strncmp(devnam,"/dev/",5) == 0)
				devnam += 5;

		if ((rc = lockf(fd, F_LOCK, 0)) == -1)
		{
				error("LDAP: can't lock utmp file: %s\n",
					  strerror(errno));
				return -1;
		}

		switch ((offset = utmp_seek(fd, devnam))) {

        case -1:

				strncpy(entry.line, devnam, strlen(devnam));
				strncpy(entry.login, user, strlen(user));
				strncpy(entry.ifname, ppp_devname, strlen(ppp_devname));

				if (!ldap_data->address_set)
						entry.ip_address = ipcp_wantoptions[0].hisaddr;
				else entry.ip_address = ldap_data->addr;

				entry.time = time(NULL);
				entry.state = ACTIVE;

				lseek(fd, 0, SEEK_END);
				if ((write_n(fd, &entry, sizeof(struct ppp_utmp))) == -1){
						error("LDAP: failed to write utmp entry\n");
						return -1;
				}

				break;

        default:

				lseek(fd, offset, SEEK_SET);
				read_n(fd,&entry,sizeof(struct ppp_utmp));

				strncpy(entry.line, devnam, strlen(devnam));
				strncpy(entry.login, user, strlen(user));
				strncpy(entry.ifname, ppp_devname, strlen(ppp_devname));

				if (!ldap_data->address_set)
						entry.ip_address = ipcp_wantoptions[0].hisaddr;
				else entry.ip_address = ldap_data->addr;

				entry.time = time(NULL);
				entry.state = ACTIVE;

				lseek(fd, offset, SEEK_SET);
				if ((write_n(fd, &entry, sizeof(struct ppp_utmp))) == -1){
						error("LDAP: failed to write utmp entry\n");
						return -1;
				}

				break;
		}

		lseek(fd, 0, SEEK_SET);
		if ((rc = lockf(fd, F_ULOCK, 0)) == -1)
		{
				error("LDAP: can't unlock utmp file: %s\n",
					  strerror(errno));
				return -1;
		}

		if ((rc = close(fd)) == -1)
		{
				error("LDAP: can't close utmp file: %s\n",
					  strerror(errno));
				return -1;
		}

		return 1;

}

/*
 *	FUNCTION: ldap_deactivate_utmp(char *devnam);
 *	PURPOSE: sets ppp session data to IDLE in ppp_utmp associated with tty
 *	ARGUMENTS:
 *	devnam - 	tty device name ("/dev/" will be stripped)
 *
 *	RETURNS: -1 in case of error
 1 if success
*/


static int ldap_deactivate_utmp(char *devnam)
{

		int rc;
		int fd;
		off_t offset;
		struct ppp_utmp entry;

		memset(&entry, 0, sizeof(struct ppp_utmp));
		if(strncmp(devnam,"/dev/",5) == 0)
				devnam += 5;

#ifdef DEBUG
		error("LDAP: deactivating %s\n",devnam);
#endif

		if ((fd = open(UTMP, O_RDWR, 0600)) == -1){
				error("LDAP: can't open utmp file: %s\n",
					  strerror(errno));
				return -1;
		}

		if ((rc = lockf(fd, F_LOCK, 0)) == -1){
				error("LDAP: can't lock utmp file: %s\n",
					  strerror(errno));
				return -1;
		}

		while(read_n(fd, &entry, sizeof(struct ppp_utmp))) {
				if (strncmp(entry.line, devnam, strlen(entry.line)) == 0) {
						entry.state = IDLE;
						lseek(fd, -sizeof(struct ppp_utmp), SEEK_CUR);
						if ((rc = write_n(fd, &entry, sizeof(struct ppp_utmp))) == -1) {
								error("LDAP: can't change utmp record status: %s\n",
									  strerror(errno));
								return -1;
						}
				}
		}

		lseek(fd, 0, SEEK_SET);
		if ((rc = lockf(fd, F_ULOCK, 0)) == -1){
				error("LDAP: can't unlock utmp file: %s\n",
					  strerror(errno));
				return -1;
		}

		close(fd);
		return 1;
}

/*
 *	FUNCTION: ldapset_options()
 *	PURPOSE: sets different pppd options retrieved from user's LDAP entry
 *	Currently ldap_set_options() processes radiusFramedIPAddress, radiusSessionTimeout,
 *	radiusIdleTimeout. Additional options should be easy.
 *
 *	ARGUMENTS:
 *	ld - pointer to current LDAP structure
 *	ldap_entry - points to current LDAP entry we want to process
 *	ldap_data - points to ldap_data structure which holds necessary values
 *
 *	RETURNS: Nothing
 *
 */

static int ldap_setoptions(LDAP *ld, LDAPMessage *ldap_entry, struct ldap_data *ldap_data)
{
		int rc;
		char **ldap_values;

		if (((ldap_values = ldap_get_values(ld, ldap_entry,
											RADIUS_FRAMEDIPADDRESS)) != NULL) &&
			((ldap_count_values(ldap_values)) != 0)) {
				if ((rc = inet_pton(AF_INET, ldap_values[0],&ldap_data->addr)) > 0){
						ldap_data->address_set = 1;
						PDLD_DBG("peer address is %p\n",ldap_data->addr);
				} else
				{
						switch(rc) {
						case 0:
								error("LDAP: LDAP server supplied incorrect IP address\n");
								break;

						default:
								error("LDAP: Can not convert supplied IP address: %s\n",
									  strerror(rc));
								break;
						}
				}
		}

		if (((ldap_values = ldap_get_values(ld, ldap_entry,
											RADIUS_IDLETIMEOUT)) != NULL ) &&
			((ldap_count_values(ldap_values)) != 0)) {
				ldap_data->idle_time_limit = atoi(ldap_values[0]);
				PDLD_DBG("peer idle timeout is %u seconds\n",
						 ldap_data->idle_time_limit);
				idle_time_limit = ldap_data->idle_time_limit;
		}

		if (((ldap_values = ldap_get_values(ld, ldap_entry,
											RADIUS_SESSIONTIMEOUT)) != NULL ) &&
			((ldap_count_values(ldap_values)) != 0)) {
				ldap_data->maxconnect = atoi(ldap_values[0]);
				PDLD_DBG("peer session timeout is %u seconds\n",
						 ldap_data->maxconnect);
				maxconnect = ldap_data->maxconnect;
		}

}
