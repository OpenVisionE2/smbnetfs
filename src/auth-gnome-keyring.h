#ifndef __AUTH_GNOME_KEYRING_H__
#define	__AUTH_GNOME_KEYRING_H__

#define AUTH_FALLBACK			0
#define AUTH_MATCH_DEFAULT		1
#define AUTH_MATCH_DOMAIN_COMPAT	2
#define AUTH_MATCH_DOMAIN		3
#define AUTH_MATCH_SERVER		4
#define AUTH_MATCH_RESOURCE		5

#ifdef HAVE_GNOME_KEYRING
struct gnome_keyring_authinfo{
    char	*domain;
    char	*user;
    char	*password;
    int		suitability;
};

void gnome_keyring_init(void);
void gnome_keyring_done(void);
int  gnome_keyring_enable(int state);
int  gnome_keyring_set_request_timeout(int timeout);

struct gnome_keyring_authinfo* gnome_keyring_get_authinfo(
						const char *domain,
						const char *server,
						const char *share);

void gnome_keyring_free_authinfo(struct gnome_keyring_authinfo*);
#endif /* HAVE_GNOME_KEYRING */


#endif /* __AUTH_GNOME_KEYRING_H__ */