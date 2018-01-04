#ifndef __AUTH_LIBSECRET_H__
#define	__AUTH_LIBSECRET_H__

#define AUTH_FALLBACK			0
#define AUTH_MATCH_DEFAULT		1
#define AUTH_MATCH_DOMAIN_COMPAT	2
#define AUTH_MATCH_DOMAIN		3
#define AUTH_MATCH_SERVER		4
#define AUTH_MATCH_RESOURCE		5

#ifdef HAVE_LIBSECRET
struct libsecret_authinfo{
    char	*domain;
    char	*user;
    char	*password;
    int		suitability;
};

void libsecret_init(void);
void libsecret_done(void);
int  libsecret_enable(int state);
int  libsecret_set_request_timeout(int timeout);

struct libsecret_authinfo* libsecret_get_authinfo(
					const char *domain,
					const char *server,
					const char *share);

void libsecret_free_authinfo(struct libsecret_authinfo*);
#endif /* HAVE_LIBSECRET */

#endif /* __AUTH_LIBSECRET_H__ */