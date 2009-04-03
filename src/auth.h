#ifndef __AUTH_H__
#define __AUTH_H__

#include "list.h"

struct authinfo{
    LIST			entries;
    int				ref_count;
    char			*domain;
    char			*user;
    char			*password;
};


void              auth_set_default_login_name(const char *name);
struct authinfo * auth_get_authinfo(
				const char *domain,
				const char *server,
				const char *share);
void              auth_release_authinfo(struct authinfo *info);
int               auth_store_auth_data(
				const char *server_or_domain,
				const char *share_or_empty,
				const char *domain,
				const char *user,
				const char *password);
void              auth_delete_obsolete(time_t threshold);

#endif	/* __AUTH_H__ */
