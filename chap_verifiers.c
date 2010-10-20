/*
 * chap_verifiers.c
 * Here are three types of CHAP verifiers authenticating user
 * using its LDAP userinfo.
 *
 * 1) ldap_chap_md5_verify [CHAP-MD5]
 * Verifies simple CHAP-MD5. Unfortunatelly the only way to
 * support CHAP-MD5 authentication using LDAP userinfo is to
 * hold userPassword value in plain-text on your LDAP server.
 * It's not very good stuff but there is an only way CHAP-MD5 will work.
 *
 * 2) ldap_chap_ms_verify [MSCHAP]
 * Verifies MSCHAP. The autentification will work if one of the following
 * conditions is hold:
 *   a) userPassword value is presented as plain-text on LDAP server
 *   b) each LDAP user that would be authenticated using pppd-ldap plugin
 *      has SambdaNTPassword attribute on LDAP server where its password holds
 *      as NT-HASH(MD4 hash). NOTE: if MSLANMAN password is used istead of NT
 *      LDAP user should have SambeLMPassword attribute with password that will
 *      be used for MSCHAP authentication.
 * Obviously variant (b) is more secure than (a) because it doesn't need to
 * transfer passwords in plain-text from LDAP server to the machine where
 * pppd-ldap is run. Only password hashes(NT and LM if enbaled) will be
 * transferred. The only drawback of (b) is that it requires SambaNTPassword
 * and SambaLMPassword(if LM is enabled) attributes for every LDAP user who
 * would be authenticated via LDAP.
 *
 * 3) ldap_chap_ms2_verify [MSCHAP-V2]
 * Verifies MSCHAP-V2. The authentication will work when at least
 * one condition listed above in (2) holds. In other words MSCHAP-V2 and
 * MSCHAP authentications require near the same configuration. The only
 * difference is that MSCHAP-V2 hasn't LM passowrd hash support.
 *
 * NOTE: MSCHAP and MSCHAP-V2 verifiers work as follow
 * At first they try to figure out if LDAP user has SambaNTPassword
 * (and SambaLMPassword if ms_lanman is enabled for MSCHAP). If so,
 * they try to authenticate the user using password hash taken from
 * corresponding field. If authentication by hashed password fails or
 * if user doesn't have mentioned above fields, userPassword value is
 * fetched. If userPassword value is in plain-text, MSCHAP and MSCHAP-V2
 * verifiers try to authenticate user by that value. Otherwise access
 * denied.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "pppd_ldap.h"
#include "md4.h"

#ifdef MSLANMAN
bool ms_lanman = 0;/* Use LanMan password instead of NT */
/* Has meaning only with MS-CHAP challenges */
#endif /* MSLANMAN */

/*
 * Unfortunatelly ChallengeResponse, NTPasswordHash and Set_Start_Key,
 * are declared as static functions in pppd. So I had to copy-paste them
 * to make authentication work.
 * Note: these three function were taken from pppd/chap_ms.c
 */

static void
ChallengeResponse(u_char *challenge,
				  u_char PasswordHash[MD4_SIGNATURE_SIZE],
				  u_char response[24])
{
	u_char	  ZPasswordHash[21];

	BZERO(ZPasswordHash, sizeof(ZPasswordHash));
	BCOPY(PasswordHash, ZPasswordHash, MD4_SIGNATURE_SIZE);

	(void) DesSetkey(ZPasswordHash + 0);
	DesEncrypt(challenge, response + 0);
	(void) DesSetkey(ZPasswordHash + 7);
	DesEncrypt(challenge, response + 8);
	(void) DesSetkey(ZPasswordHash + 14);
	DesEncrypt(challenge, response + 16);
}

static void
NTPasswordHash(u_char *secret, int secret_len, u_char hash[MD4_SIGNATURE_SIZE])
{
#ifdef __NetBSD__
	/* NetBSD uses the libc md4 routines which take bytes instead of bits */
	int			mdlen = secret_len;
#else
	int			mdlen = secret_len * 8;
#endif
	MD4_CTX		md4Context;

	MD4Init(&md4Context);
	/* MD4Update can take at most 64 bytes at a time */
	while (mdlen > 512) {
		MD4Update(&md4Context, secret, 512);
		secret += 64;
		mdlen -= 512;
	}
	MD4Update(&md4Context, secret, mdlen);
	MD4Final(hash, &md4Context);

}


#ifdef MPPE

/*
 * Set mppe_xxxx_key from MS-CHAP credentials. (see RFC 3079)
 */
static void
Set_Start_Key(u_char *rchallenge, u_char PasswordHash[MD4_SIGNATURE_SIZE])
{
	u_char	PasswordHashHash[MD4_SIGNATURE_SIZE];

	/* Hash (x2) the Unicode version of the secret (== password). */
	NTPasswordHash(PasswordHash, MD4_SIGNATURE_SIZE, PasswordHashHash);
	mppe_set_keys(rchallenge, PasswordHashHash);
}

#endif /* MPPE */

static char *ldap_ptypes[] = {
	"crypt",
	"md5",
	"sha",
	"ssha",
	NULL
};

static int
get_ldap_userpassword(LDAP *ldap, LDAPMessage *entry,
					  char *secret, int maxsecret_len)
{
	struct berval **bvals;
	char *p, *passwd;
	int passwd_len = -1;

	bvals = ldap_get_values_len(ldap, entry, LDAP_USERPASSWORD);
	if (!bvals) {
		pdld_ldap_error(ldap, "Failed to get userPassword field value");
		goto out;
	}

	passwd = bvals[0]->bv_val;

	/*
	 * userPassword LDAP field can be either plain text or
	 * hashed/encrypted. If password is encrypted or hashed
	 * it has the following format:
	 * {HASH_NAME/CRYPTO}hashed/encrypted_password
	 * Otherwise password is plain text.
	 */
	if ((passwd[0] == '{') &&
		((p = strchr(passwd + 1, '}')) != NULL)) {
		char **type;
		int len = p - (passwd + 1);

		/*
		 * Even if userPassword has value like "{sometext}password",
		 * it actually could be in plain-text format. Nothing forbids
		 * user from making it password looking like {texthere}textthere
		 * To make it clear we compare text in figure brakets with
		 * list of names of known LDAP password holding mehtods. If
		 * the text doesn't correspond to any, then we assume that it's
		 * a plain-text password.
		 */
		if (len > 0) {
			for (type = ldap_ptypes; *type; type++) {
				if (!strncasecmp(*type, passwd + 1, len)) {
					PDLD_DBG("userPassword is not plain-text: "
							 "password type is %s\n", *type);
					goto out;
				}
			}
		}
	}

	passwd_len = bvals[0]->bv_len;
	if (passwd_len > maxsecret_len) {
		PDLD_DBG("userPassword is too long: %d"
				 "(%d bytes was expected)\n",
				 passwd_len, maxsecret_len);
		passwd_len = -1;
		goto out;
	}

	bzero(secret, maxsecret_len);
	strncpy(secret, passwd, passwd_len);
out:
	if (bvals)
		ldap_value_free_len(bvals);

	return passwd_len;
}

/*
 * Convert hexadecimal character
 * to corresponding 1 byte integer
 */
static u_char
xdigit(u_char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	/* not a hex */
	return 0;
}

static int
get_ldap_passwordhash(LDAP *ldap, LDAPMessage *entry,
					  char *attr, u_char pwhash[MD4_SIGNATURE_SIZE])
{
	struct berval **bvals;
	u_char *hex;
	int i, ret = -1;

	bvals = ldap_get_values_len(ldap, entry, attr);
	if (!bvals) {
		pdld_ldap_error(ldap, "Failed to get %s password hsah", attr);
		goto out;
	}

	/*
	 * LDAP returns SambaNTPassword and SambaLMPassword as hex strings.
	 * Hash hex string should be 32 bytes long and correspond to 16-bytes
	 * MD4 hash.
	 */
	if (bvals[0]->bv_len != MD4_SIGNATURE_SIZE * 2) {
		PDLD_WARN("%s password hash has insufficient "
				  "length %d (%d expected)",
				  attr, bvals[0]->bv_len, MD4_SIGNATURE_SIZE * 2);
		goto out;
	}

	/*
	 * We have to convert 32 bytes hex string describind MD4 hash
	 * to 16 bytes hash itself. Each 2 bytes of hex string describe
	 * 1 byte of MD4 hash (from left to right).
	 */
	hex = bvals[0]->bv_val;
	for (i = 0; i < MD4_SIGNATURE_SIZE; i++, hex += 2)
		pwhash[i] = xdigit(hex[1]) + xdigit(hex[0]) * 0x10;

	ret = 0;

out:
	if (bvals)
		ldap_value_free_len(bvals);

	return ret;
}

/*
 * Try authenticate user using SambaNTPassword and SambaLMPassword
 * (if LM is enabled) by CHAPMS. The function returns 1 on success and 0
 * if user can not be authenticated.
 * NOTE: the following code is based on chapms_verify_response function
 * from pppd/chap_ms.c
 */
static int
try_auth_chapms(LDAP *ldap, LDAPMessage *entry,
				u_char *rchallenge, u_char *response,
				char *message, int message_space)
{
	int rc, diff;
	u_char md[MS_CHAP_RESPONSE_LEN];
	u_char nt_pwhash[MD4_SIGNATURE_SIZE];
#ifdef MSLANMAN
	u_char lm_pwhash[MD4_SIGNATURE_SIZE];
#endif /* MSLANMAN */

	BZERO(md, MS_CHAP_RESPONSE_LEN);
#ifdef MSLANMAN
	if (!response[MS_CHAP_USENT]) {
		PDLD_WARN("Peer request for LANMAN auth "
				  "that is not supported\n");
		return 0;
	}
#endif /* !MSLANMAN */

	rc = get_ldap_passwordhash(ldap, entry, SAMBA_NTPASSWORDHASH,
							   nt_pwhash);
	if (rc)
		return 0;

	ChallengeResponse(rchallenge, nt_pwhash, &md[MS_CHAP_NTRESP]);
	md[MS_CHAP_USENT] = 1;

#ifdef MSLANMAN
	rc = get_ldap_passwordhash(ldap, entry, SAMBA_LMPASSWORDHASH,
							   lm_pwhash);
	if (!rc) {
		ChallengeResponse(rchallenge, lm_pwhash,
						  &md[MS_CHAP_LANMANRESP]);
		md[MS_CHAP_USENT] = !ms_lanman;
	}
#endif /* MSLANMAN */

#ifdef MPPE
	Set_Start_Key(rchallenge, nt_pwhash);
#endif /* !MPPE */

	diff = memcmp(&response[MS_CHAP_NTRESP], &md[MS_CHAP_NTRESP],
				  MS_CHAP_NTRESP_LEN);

#ifdef MSLANMAN
	/* Determine which part of response to verify against */
	if (!response[MS_CHAP_USENT]) {
		diff = memcmp(&response[MS_CHAP_LANMANRESP],
					  &md[MS_CHAP_LANMANRESP], MS_CHAP_LANMANRESP_LEN);
	}
#endif /* !MSLANMAN */

	if (diff == 0) {
		slprintf(message, message_space, "Access granted");
		return 1;
	}

	return 0;
}


/*
 * Try authenticate user by CHAPMS-V2 using SambaNTPassword attribute value.
 * The function returns 1 if authentication successed and 0 otherwise.
 * NOTE: the following code is based on chapms2_verify_response function
 * from pppd/chap_ms.c
 */
static int
try_auth_chapms2(LDAP *ldap, LDAPMessage *entry, char *user,
				 u_char *rchallenge, u_char *response,
				 char *message, int message_space)
{
	u_char md[MS_CHAP2_RESPONSE_LEN];
	u_char Challenge[8];
	u_char nt_pwhash[MD4_SIGNATURE_SIZE];
	u_char PasswordHashHash[MD4_SIGNATURE_SIZE];
	u_char saresponse[MS_AUTH_RESPONSE_LENGTH + 1];
	u_char *PeerChallenge = &response[MS_CHAP2_PEER_CHALLENGE];
	u_char *p = &md[MS_CHAP2_PEER_CHALLENGE];

	BZERO(md, sizeof(*md));

	/* Generate the Peer-Challenge if requested, or copy it if supplied. */
	if (!PeerChallenge) {
		int i;

		for (i = 0; i < MS_CHAP2_PEER_CHAL_LEN; i++)
			*p++ = (u_char) (drand48() * 0xff);
	}
	else {
		BCOPY(PeerChallenge, &md[MS_CHAP2_PEER_CHALLENGE],
			  MS_CHAP2_PEER_CHAL_LEN);
	}

	ChallengeHash(&md[MS_CHAP2_PEER_CHALLENGE], rchallenge,
				  user, Challenge);
	if (get_ldap_passwordhash(ldap, entry, SAMBA_NTPASSWORDHASH,
							  nt_pwhash) < 0) {
		return 0;
	}

	ChallengeResponse(Challenge, nt_pwhash, &md[MS_CHAP2_NTRESP]);
	NTPasswordHash(nt_pwhash, sizeof(nt_pwhash), PasswordHashHash);
	GenerateAuthenticatorResponse(PasswordHashHash,
								  &md[MS_CHAP2_NTRESP],
								  &md[MS_CHAP2_PEER_CHALLENGE],
								  rchallenge, user, saresponse);

#ifdef MPPE
	mppe_set_keys2(PasswordHashHash, &md[MS_CHAP2_NTRESP],
				   MS_CHAP2_AUTHENTICATOR);
#endif
	if (memcmp(&md[MS_CHAP2_NTRESP], &response[MS_CHAP2_NTRESP],
			   MS_CHAP2_NTRESP_LEN) == 0) {
		if (response[MS_CHAP2_FLAGS])
			slprintf(message, message_space, "S=%s", saresponse);
		else
			slprintf(message, message_space, "S=%s M=%s",
					 saresponse, "Access granted");
		return 1;
	}

	return 0;
}

/*
 * Try authenticate user using the value of userPassword attribute.
 * If userPassword value is in plain-text, the function tries to
 * call builtin verify_response function of given digest.
 *
 * If userPassword value can not be fetched for some reason or
 * if it's not in plain-text, the function returns -1.
 * 1 is returned if authentication succeeded and 0 is returned otherwise.
 */
static int
try_standard_auth(LDAP *ldap, LDAPMessage *entry, char *user,
				  int id, struct chap_digest_type *digest,
				  u_char *challenge, u_char *response,
				  char *message, int message_space)
{
	u_char secret[MAXSECRETLEN];
	int secret_len, ok;

	secret_len = get_ldap_userpassword(ldap, entry, secret, MAXSECRETLEN);
	if (secret_len < 0) {
		return -1;
	}

	ok = digest->verify_response(id, user, secret, secret_len,
								 challenge, response, message,
								 message_space);
	memset(secret, 0, sizeof(secret));
	return ok;
}

/*
 * Verify peer using simple CHAP-MD5.
 * chap_md5_verify expects that userPassword attribute of given
 * user is an MD5 hash or plaintext password.
 * Otherwise user won't be authenticated.
 */
int
ldap_chap_md5_verify(LDAP *ldap, LDAPMessage *entry, char *user,
					 int id, struct chap_digest_type *digest,
					 u_char *challenge, u_char *response,
					 char *message, int message_space)
{
	int ok, challenge_len;

	challenge_len = *challenge;
	PDLD_DBG("Authenticate user %s using CHAP\n", user);
	ok = try_standard_auth(ldap, entry, user, id, digest,
						   challenge, response,
						   message, message_space);
	if (ok < 0) {
		PDLD_WARN("CHAP verification method supports "
				  "only plain-text LDAP password\n");
		goto bad;
	}

	return ok;

bad:
	slprintf(message, message_space, "E=691 R=1 C=%0.*B V=0",
			 challenge_len, challenge + 1);
	return 0;
}

int
ldap_chap_ms_verify(LDAP *ldap, LDAPMessage *entry, char *user,
					int id, struct chap_digest_type *digest,
					u_char *challenge, u_char *response,
					char *message, int message_space)
{
	int ok;
	int challenge_len, response_len;

	challenge_len = *challenge;
	response_len = *response;

	PDLD_DBG("Authenticate %s using CHAPMS\n", user);
	if (response_len != MS_CHAP_RESPONSE_LEN) {
		PDLD_DBG("Bad response length: %d (%d was expected)\n",
				 response_len, MS_CHAP_RESPONSE_LEN);
		goto bad;
	}

	PDLD_DBG("Trying MSCHAP using SambaNTPassword...\n");
	ok = try_auth_chapms(ldap, entry, challenge + 1, response + 1,
						 message, message_space);
	if (ok) {
		PDLD_DBG("Succeed\n");
		return 1;
	}

	PDLD_DBG("Failed\nTrying MSCHAP using userPassword...\n");
	ok = try_standard_auth(ldap, entry, user, id, digest,
						   challenge, response,
						   message, message_space);
	if (ok < 0) {
		PDLD_DBG("Failed\n");
		goto bad;
	}
	if (!ok) {
		PDLD_WARN("MSCHAP authentication works only if either "
				  "userPasswrod is in plain-text or if SambaNTPassword "
				  "field is present!\n");
	}

	return ok;

bad:
	slprintf(message, message_space, "E=691 R=1 C=%0.*B V=0",
			 challenge_len, challenge);
	return 0;

}

int
ldap_chap_ms2_verify(LDAP *ldap, LDAPMessage *entry, char *user,
					 int id, struct chap_digest_type *digest,
					 u_char *challenge, u_char *response,
					 char *message, int message_space)
{
	int challenge_len, response_len, ok;

	challenge_len = *challenge;
	response_len = *response;

	PDLD_DBG("Authenticate %s using MSCHAP-V2\n", user);
	if (response_len != MS_CHAP2_RESPONSE_LEN) {
		PDLD_DBG("Bad response length: %d (%d was expected)\n",
				 response_len, MS_CHAP2_RESPONSE_LEN);
		goto bad;
	}

	PDLD_DBG("Trying CHAPMS-V2 using SamabNTPassword...\n");
	ok = try_auth_chapms2(ldap, entry, user, challenge + 1, response + 1,
						  message, message_space);
	if (ok) {
		PDLD_DBG("Succeed\n");
		return 1;
	}

	PDLD_DBG("Failed\nTrying CHAPMS-V2 using userPassword...\n");
	ok = try_standard_auth(ldap, entry, user, id, digest,
						   challenge, response,
						   message, message_space);
	if (ok < 0) {
		PDLD_DBG("Faield\n");
		goto bad;
	}
	if (!ok) {
		PDLD_WARN("MSCHAP-v2 authentication works only if either "
				  "userPasswrod is in plain-text or if SambaNTPassword "
				  "field is present!\n");
	}

	return ok;

bad:
	slprintf(message, message_space, "E=691 R=1 C=%0.*B V=0 M=%s",
			 challenge_len, challenge + 1, "Access denied");
	return 0;

}
