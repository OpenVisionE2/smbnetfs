#include "config.h"
#include <pwd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "list.h"
#include "common.h"
#include "auth.h"

struct authitem{
    char			*name;		// item name
    time_t			touch_time;	// item touch time
    struct authinfo		*info;
    struct{
	int			child_cnt;	// number of subitem
	int			max_child_cnt;	// maximum number of subitem
	struct authitem		**childs;	// sorted list of subitems
    };
};

char		auth_login[64]		= "guest";
char		*auth_fake_password	= "********";
struct authinfo	authinfo_default	= {{NULL, NULL}, 1, "", auth_login, ""};
LIST		authinfo_list		= STATIC_LIST_INITIALIZER(authinfo_list);
struct authitem	authroot		= {NULL, (time_t) 0, NULL, {0, 0, NULL}};
pthread_mutex_t	m_auth			= PTHREAD_MUTEX_INITIALIZER;


void auth_set_default_login_name(const char *name){
    strncpy(auth_login, name, sizeof(auth_login));
    auth_login[sizeof(auth_login) - 1] = '\0';
    DPRINTF(5, "login=%s\n", auth_login);
}

struct authinfo * authinfo_create_new(
				const char *domain,
				const char *user,
				const char *password){

    size_t		len;
    struct authinfo	*info;

    len = sizeof(struct authinfo) +
		strlen(domain) + strlen(user) + strlen(password) + 3;
    if ((info = malloc(len)) == NULL) return NULL;
    memset(info, 0, len);

    info->domain   = (char *) (info + 1);
    info->user     = info->domain + strlen(domain) + 1;
    info->password = info->user + strlen(user) + 1;

    strcpy(info->domain,   domain);
    strcpy(info->user,     user);
    strcpy(info->password, password);

    return info;
}

static inline void authinfo_delete(struct authinfo *info){
    free(info);
}

inline int authinfo_compare(struct authinfo *info,
				const char *domain,
				const char *user,
				const char *password){
    return ((strcmp(info->domain,   domain)   == 0) &&
	    (strcmp(info->user,     user)     == 0) &&
	    (strcmp(info->password, password) == 0));
}

struct authinfo * authinfo_find_in_list(
				const char *domain,
				const char *user,
				const char *password){

    struct authinfo	*info;
    LIST		*elem;

    elem = first_list_elem(&authinfo_list);
    while(is_valid_list_elem(&authinfo_list, elem)){
	info = list_entry(elem, struct authinfo, entries);
	if (authinfo_compare(info, domain, user, password)) return info;
	elem = elem->next;
    }
    return NULL;
}

struct authinfo * authinfo_store_list(
				const char *domain,
				const char *user,
				const char *password){

    struct authinfo	*info;

    DPRINTF(10, "domain=%s, user=%s, password=%s\n",
			domain, user, auth_fake_password);

    info = authinfo_find_in_list(domain, user, password);
    if (info != NULL){
	remove_from_list(&authinfo_list, &info->entries);
    }else{
	info = authinfo_create_new(domain, user, password);
	if (info == NULL) return NULL;
    }

    info->ref_count++;
    add_to_list_back(&authinfo_list, &info->entries);
    return info;
}

void authinfo_release(struct authinfo *info){
    info->ref_count--;
    if (info->ref_count == 0){
	remove_from_list(&authinfo_list, &info->entries);
	authinfo_delete(info);
    }
}

struct authitem* authitem_create_item(const char *name){
    struct authitem	*item;

    item = malloc(sizeof(struct authitem) + strlen(name) + 1);
    if (item == NULL) return NULL;

    memset(item, 0 , sizeof(struct authitem));
    item->name = (char *) (item + 1);
    strcpy(item->name, name);
    item->touch_time = time(NULL);
    return item;
}

static inline void authitem_delete_item(struct authitem *item){
    if (item->info != NULL) authinfo_release(item->info);
    if (item->childs != NULL) free(item->childs);
    free(item);
}

void authitem_delete_obsolete_items(struct authitem *item, time_t threshold){
    int		i;

    for(i = item->child_cnt - 1; i >= 0; i--){
	authitem_delete_obsolete_items(item->childs[i], threshold);
	if ((item->childs[i]->info == NULL) && 
	    (item->childs[i]->childs == NULL)){

	    authitem_delete_item(item->childs[i]);
	    if (i != item->child_cnt - 1){
		memmove(&item->childs[i],
			&item->childs[i + 1],
			(item->child_cnt - i - 1) * sizeof(struct authitem *));
	    }
	    item->child_cnt--;
	}
    }
    if ((item->touch_time < threshold) && (item->info != NULL)){
	authinfo_release(item->info);
	item->info = NULL;
    }
    if ((item->child_cnt == 0) && (item->childs != NULL)){
	free(item->childs);
	item->childs = NULL;
	item->max_child_cnt = 0;
    }
}

/*
 * This function search for an item in specified authitem subitems,
 * subitems MUST be sorted alphabetically, so we can bisect.
 *
 * return:
 *   a) item position, if item with specified name was found
 *   b) negative value -(pos+1), if item was not found,
 *      where 'pos' is the position to insert the new element
 */
int authitem_find_subitem(struct authitem *item, const char *name){
    int		first = 0, last = item->child_cnt - 1;

    while(first <= last){
	int i		= (first + last) >> 1;
	int result	= strcasecmp(item->childs[i]->name, name);

	if (result == 0) return i;
	if (result < 0) first = i + 1;
	else last = i - 1;
    }
    return -(first + 1);
}

/*
 * This function insert an element to specified authitem,
 * insert position MUST be obtained with authitem_find_subitem().
 *
 * return:
 *   a) zero, if no errors
 *   b) (-1), if insertion failed
 */
int authitem_insert_subitem(struct authitem *item,
				struct authitem *subitem, int pos){
    if ((pos > item->child_cnt) || (pos < 0)) return -1;

    if (item->max_child_cnt == item->child_cnt){
	struct authitem	**new_childs;
	int		new_max_cnt;

	new_max_cnt = (item->max_child_cnt == 0) ?
			64 : 2 * item->max_child_cnt;
	new_childs = realloc(item->childs,
			new_max_cnt * sizeof(struct authitem *));
	if (new_childs == NULL) return -1;

	item->max_child_cnt = new_max_cnt;
	item->childs = new_childs;
    }

    if (pos < item->child_cnt){
	memmove(&item->childs[pos + 1],
		&item->childs[pos],
		(item->child_cnt - pos) * sizeof(struct authitem *));
    }
    item->childs[pos] = subitem;
    item->child_cnt++;
    return 0;
}

struct authitem * authitem_get_subitem(
				struct authitem *item,
				const char *name){
    int			pos;
    struct authitem	*subitem;

    pos = authitem_find_subitem(item, name);
    if (pos < 0){
	/* create new subitem and add it to item */
	subitem = authitem_create_item(name);
	if (subitem == NULL) return NULL;
	pos = -(pos + 1);
	if (authitem_insert_subitem(item, subitem, pos) != 0){
	    authitem_delete_item(subitem);
	    return NULL;
	}
    }
    return item->childs[pos];
}

struct authinfo * auth_get_authinfo(
				const char *domain,
				const char *server,
				const char *share){

    int			pos;
    struct authitem	*item;
    struct authinfo	*info;

    DPRINTF(10, "domain=%s, server=%s, share=%s\n", domain, server, share);

    if ((server == NULL) || (*server == '\0')) return NULL;
    if (domain == NULL) domain = "";
    if (share  == NULL) share  = "";

    item = &authroot;
    info = &authinfo_default;
    pthread_mutex_lock(&m_auth);
	if (item->info != NULL) info = item->info;
	if (*domain != '\0'){
	    pos = authitem_find_subitem(item, domain);
	    if ((pos >= 0) && (item->childs[pos]->info != NULL))
		info = item->childs[pos]->info;
	}

	if ((pos = authitem_find_subitem(item, server)) < 0) goto end;
	item = item->childs[pos];
	if (item->info != NULL) info = item->info;

	if (*share == '\0') goto end;
	if ((pos = authitem_find_subitem(item, share)) < 0) goto end;
	item = item->childs[pos];
	if (item->info != NULL) info = item->info;

      end:
        info->ref_count++;
    pthread_mutex_unlock(&m_auth);
    DPRINTF(10, "domain=%s, user=%s, password=%s\n",
			info->domain, info->user, auth_fake_password);
    return info;
}

void auth_release_authinfo(struct authinfo *info){
    pthread_mutex_lock(&m_auth);
    authinfo_release(info);
    pthread_mutex_unlock(&m_auth);
}

int auth_store_auth_data(const char *server,
				const char *share,
				const char *domain,
				const char *user,
				const char *password){

    int			result;
    struct authinfo	*info;
    struct authitem	*item;

    DPRINTF(10, "smb://%s/%s, domain=%s, user=%s, password=%s\n",
			server, share, domain, user, auth_fake_password);

    if ((user == NULL) || (*user == '\0')) return -1;
    if (server   == NULL) server   = "";
    if (share    == NULL) share    = "";
    if (domain   == NULL) domain   = "";
    if (password == NULL) password = "";
    if ((*server == '\0') && (*share != '\0')) return -1;

    result = -1;
    item = &authroot;
    pthread_mutex_lock(&m_auth);
	if (*server == '\0') goto update_info;
	if ((item = authitem_get_subitem(item, server)) == NULL) goto error;

	if (*share == '\0') goto update_info;
	if ((item = authitem_get_subitem(item, share)) == NULL) goto error;

      update_info:
	if ((item->info == NULL) ||
	    ! authinfo_compare(item->info, domain, user, password)){

	    info = authinfo_store_list(domain, user, password);
	    if (info == NULL) goto error;
	    if (item->info != NULL) authinfo_release(item->info);
	    item->info = info;
	}
	item->touch_time = time(NULL);
	result = 0;

      error:
    pthread_mutex_unlock(&m_auth);
    return result;
}

void auth_delete_obsolete(time_t threshold){
    pthread_mutex_lock(&m_auth);
    authitem_delete_obsolete_items(&authroot, threshold);
    pthread_mutex_unlock(&m_auth);
}
