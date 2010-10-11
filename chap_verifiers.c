#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "pppd_ldap.h"
#include "md4.h"

#ifdef MSLANMAN
bool ms_lanman = 0;/* Use LanMan password instead of NT */
/* Has meaning only with MS-CHAP challenges */
#endif /* MSLANMAN */

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
		NTPasswordHash(PasswordHash, sizeof(PasswordHash), PasswordHashHash);
		mppe_set_keys(rchallenge, PasswordHashHash);
}

#endif /* MPPE */

int
get_ldap_userpassword(LDAP *ldap, LDAPMessage *entry,
					  char *secret, int maxsecret_len)
{
		struct berval **bvals;
		char *p, *passwd;
		int passwd_len;

		bvals = ldap_get_values_len(ldap, entry, LDAP_USERPASSWORD);
		if (!bvals) {
				pdld_ldap_error(ldap, "Failed to get userPassword field value");
				return -1;
		}

		passwd_len = bvals[0]->bv_len;
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
				char type_str[32];
				int len = (p - 1) - (passwd + 1);

				PDLD_DBG("LEN = %d\n", len);
				bzero(type_str, sizeof(type_str));
				strncpy(type_str, passwd + 1, len);
				PDLD_DBG("PASSWORD TYPE = %s\n", type_str);
				ldap_value_free_len(bvals);
				return -1;
		}
		if (passwd_len > maxsecret_len) {
				PDLD_DBG("userPassword is too long: %d"
						 "(%d bytes was expected)\n",
						 passwd_len, maxsecret_len);
				ldap_value_free_len(bvals);
				return -1;
		}

		bzero(secret, maxsecret_len);
		strncpy(secret, passwd, passwd_len);
		ldap_value_free_len(bvals);
		return passwd_len;
}

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
		rc = get_password_hash(ldap, entry, SAMBA_NTPASSWORDHASH, nt_pwhash);
		if (rc)
				return 0;

		ChallengeResponse(rchallenge, nt_pwhash, &md[MS_CHAP_NTRESP]);
		md[MS_CHAP_USENT] = 1;

#ifdef MSLANMAN
		rc = get_passwordhash(ldap, entry, SAMBA_LMPASSWORDHASH, lm_pwhash);
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

static int
try_auth_chapms2(LDAP *ldap, LDAPMessage *entry, char *user,
				 u_char *rchallenge, u_char *response,
				 char *message, int message_space)
{
		u_char md[MS_CHAP2_RESPONSE_LEN];
		u_char Challenge[8];
		u_char nt_pwhash[MD4_SIGNATURE_SIZE];
		u_char PasswordHashHash[MD4_SIGNATURE_SIZE];
		char saresponse[MS_AUTH_RESPONSE_LENGTH + 1];
		u_char *PeerChallenge = &response[MS_CHAP2_PEER_CHALLENGE];
		u_char *p = &md[MS_CHAP2_PEER_CHALLENGE];

		BZERO(response, sizeof(*response));

		/* Generate the Peer-Challenge if requested, or copy it if supplied. */
		if (!PeerChallenge) {
				int i;

				for (i = 0; i < MS_CHAP2_PEER_CHAL_LEN; i++)
						*p++ = (u_char) (drand48() * 0xff);
		}
		else {
				BCOPY(PeerChallenge, &response[MS_CHAP2_PEER_CHALLENGE],
					  MS_CHAP2_PEER_CHAL_LEN);
		}

		ChallangeHash(PeerChallenge, rchallenge, user, Challenge);
		if (get_passwordhash(ldap, entry, SAMBA_NTPASSWORDHASH, nt_pwhash) < 0) {
				return 0;
		}

		ChallengeResponse(Challenge, nt_pwhash, &response[MS_CHAP2_NTRESP]);
		NTPasswordHash(nt_pwhash, sizeof(nt_pwhash), PasswordHashHash);
		GenerateAuthenticatorResponse(PasswordHashHash,
									  &md[MS_CHAP2_NTRESP], PeerChallenge,
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

		if (response_len != MS_CHAP_RESPONSE_LEN)
				goto bad;
		ok = try_auth_chapms(ldap, entry, challenge + 1, response + 1,
							 message, message_space);
		if (ok)
				return 1;

		ok = try_standard_auth(ldap, entry, user, id, digest,
							   challenge, response,
							   message, message_space);
		if (ok < 0) {
				goto bad;
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

		if (response_len != MS_CHAP2_RESPONSE_LEN)
				goto bad;

		ok = try_auth_chapms2(ldap, entry, user, challenge + 1, response + 1,
							  message, message_space);
		if (ok)
				return 1;

		ok = try_standard_auth(ldap, entry, user, id, digest,
							   challenge, response,
							   message, message_space);
		if (ok < 0) {
				goto bad;
		}

		return ok;

bad:
		slprintf(message, message_space, "E=691 R=1 C=%0.*B V=0 M=%s",
				 challenge_len, challenge + 1, "Access denied");
		return 0;

}
