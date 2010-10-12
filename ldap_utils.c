#include <ldap.h>
#include "pppd.h"
#include "pppd_ldap.h"

#define LDAP_URI_LEN 512
#define LDAP_SETOPT_ERR(rc) ((rc) != LDAP_OPT_SUCCESS)

static int
configure_ldap_timeouts(LDAP *ldap)
{
	int rc;

	rc = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT,
						 &ldap_options.nettimeout);
	if (LDAP_SETOPT_ERR(rc)) {
		PDLD_DBG("Failed to set LDAP_OPT_NETWORK_TIMEOUT to %d\n",
				 ldap_options.nettimeout);
		return -1;
	}

	rc = ldap_set_option(ldap, LDAP_OPT_TIMELIMIT, &ldap_options.timeout);
	if (LDAP_SETOPT_ERR(rc)) {
		PDLD_DBG("Failed to set LDAP_OPT_TIMELIMIT to %d\n",
				 ldap_options.timeout);
		return -1;
	}

	return 0;
}

static int
start_tls_session(LDAP *ldap)
{
#ifdef LDAP_OPT_X_TLS
	int tls_opt = LDAP_OPT_X_TLS_HARD;
	int rc;

	rc = ldap_set_option(ldap, LDAP_OPT_X_TLS_HARD, &tls_opt);
	if (LDAP_SETOPT_ERR(rc)) {
		PDLD_DBG("Failed to set LDAP_OPT_TLS_HARD to %d\n", tls_opt);
		return -1;
	}

	rc = ldap_start_tls_s(ldap, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		PDLD_DBG("Failed to start TLS session: [rc = %d]\n", rc);
		return -1;
	}

	return 0;
#else /* LDAP_OPT_X_TLS */
	LDAP_INFO("Your version of libldap doesn't provide TLS support\n");
#endif /* !LDAP_OPT_X_TLS */
}


int
init_ldap_session(LDAP **out_ldap)
{
	char uri[LDAP_URI_LEN];
	int rc;

	sprintf(uri, "ldap%s://%s:%d", ldap_options.usessl ? "s" : "",
			ldap_options.host, ldap_options.port);
	PDLD_DBG("Connecting to ldap server. URI: %s\n", uri);

	if ((rc = ldap_initialize(out_ldap, uri)) != LDAP_SUCCESS) {
		*out_ldap = NULL;
	}

	return rc;
}


int
ldap_login(LDAP *ldap)
{
	int rc;
	int version = LDAP_VERSION3;

	rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (LDAP_SETOPT_ERR(rc)) {
		PDLD_DBG("Failed to set LDAP protocol version to %d\n", version);
		rc = -1;
		goto out;
	}

	rc = configure_ldap_timeouts(ldap);
	if (rc)
		goto out;

	if (ldap_options.usetls) {
		PDLD_DBG("Starting TLS session...\n");
		rc = start_tls_session(ldap);
		if (rc)
			goto out;
	}

	rc = ldap_bind_s(ldap, ldap_options.dn, ldap_options.password,
					 LDAP_AUTH_SIMPLE);
	if (rc != LDAP_SUCCESS) {
		PDLD_DBG("Failed to login to LDAP server using DN \"%s\"\n",
				 ldap_options.dn);
		rc = -1;
		goto out;
	}

	rc = 0;
out:
	return rc;
}

void
ldap_logout(LDAP *ldap)
{
	ldap_unbind(ldap);
}

int
get_user_ldap_msg(LDAP *ldap, const char *uname, LDAPMessage **res_msg)
{
	char filter[LDAP_FILT_MAXSIZ];
	int rc;

	rc = snprintf(filter, LDAP_FILT_MAXSIZ, "(&(uid=%s)(objectClass=%s))",
				  uname, RADIUS_OBJECTCLASS);
	if (rc < 0) {
		PDLD_DBG("Filter is too big. [limit = %d bytes]", LDAP_FILT_MAXSIZ);
		return rc;
	}

	rc = ldap_search_ext_s(ldap, ldap_options.userbasedn, LDAP_SCOPE_SUBTREE,
						   filter, NULL, 0, NULL, NULL, NULL,
						   LDAP_NO_LIMIT, res_msg);
	if (rc != LDAP_SUCCESS) {
		PDLD_DBG("ldap_search_ext_s() failed\n");
		return -1;
	}

	return 0;
}

void
__pppd_ldap_error(LDAP *ldap, const char *fn,
				  int line, const char *fmt, ...)
{
	va_list ap;
	char buf[MAX_BUF];
	int ld_errno, len;

	va_start(ap, fmt);
	len = snprintf(buf, MAX_BUF, "[PPPD-LDAP ERROR]: ");
	len += vsnprintf(buf + len, MAX_BUF - len, fmt, ap);
	if (ldap != NULL) {
		ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &ld_errno);
		if (ld_errno != LDAP_SUCCESS) {
			snprintf(buf + len, MAX_BUF - len,
					 "\n	 LD_ERRNO: [%d:%s]",
					 ld_errno, ldap_err2string(ld_errno));
		}
	}

	error("%s\n	   AT: %s:%d\n", buf, fn, line);
}
