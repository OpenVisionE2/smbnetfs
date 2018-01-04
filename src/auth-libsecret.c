#include "config.h"
#ifdef HAVE_LIBSECRET

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <glib.h>
#include <libsecret/secret.h>

#include "common.h"
#include "auth-libsecret.h"


static gboolean req_timeout_prepare (GSource *source, gint *timeout);
static gboolean req_timeout_check   (GSource *source);
static gboolean req_timeout_dispatch(GSource *source, GSourceFunc callback,
				     gpointer user_data);
static void     req_timeout_finalize(GSource *source);


enum libsecret_status{
    LIBSECRET_NOT_AVAILABLE = -1,
    LIBSECRET_DISABLED = 0,
    LIBSECRET_ENABLED
};

struct req_timeout{
    struct timeval	start_time;
    gint		timeout_len;
    gboolean		expired;
    GCancellable	*cancellable;
};

struct req_data{
    const char			*domain;
    const char			*server;
    const char			*share;
    SecretItem			*secret_item;
    struct libsecret_authinfo	*auth_info;
    int				suitability;
};

#define REQ_TIMEOUT(source)	(&G_STRUCT_MEMBER(struct req_timeout, source, sizeof(GSource)))

static pthread_mutex_t			m_auth_libsecret = PTHREAD_MUTEX_INITIALIZER;
static enum libsecret_status		libsecret	 = LIBSECRET_NOT_AVAILABLE;
static const SecretSchema		libsecret_schema = {
					    "org.gnome.keyring.NetworkPassword", SECRET_SCHEMA_DONT_MATCH_NAME,
					    {
						{ "protocol", SECRET_SCHEMA_ATTRIBUTE_STRING },
						{ "server",   SECRET_SCHEMA_ATTRIBUTE_STRING },
						{ "object",   SECRET_SCHEMA_ATTRIBUTE_STRING },
						{ "domain",   SECRET_SCHEMA_ATTRIBUTE_STRING },
						{ "user",     SECRET_SCHEMA_ATTRIBUTE_STRING },
						{ NULL, 0 },
					    }
					};
static GMainLoop			*loop		 = NULL;
static GHashTable			*search_hash	 = NULL;
static GSourceFuncs			req_timeout_func = {
					    .prepare  = req_timeout_prepare,
					    .check    = req_timeout_check,
					    .dispatch = req_timeout_dispatch,
					    .finalize = req_timeout_finalize
					};
static struct req_timeout		*req_timeout	 = NULL;
static int				max_req_timeout	 = 500;	/* in milliseconds */
static SecretService			*secret_service	 = NULL;
static SecretCollection			*secret_collection = NULL;


static struct libsecret_authinfo * libsecret_create_authinfo(const char *domain,
                                                             const char *user,
                                                             const char *password,
                                                             int suitability)
{
    struct libsecret_authinfo	*info;

    if (password == NULL) return NULL;
    if ((user == NULL) || (*user == '\0')) return NULL;
    if (domain == NULL) domain = "";

    info = malloc(sizeof(struct libsecret_authinfo) +
                   strlen(domain) + strlen(user) + strlen(password) + 3);
    if (info == NULL) return NULL;

    info->domain   = (char *) (info + 1);
    info->user     = info->domain + strlen(domain) + 1;
    info->password = info->user + strlen(user) + 1;

    strcpy(info->domain,   domain);
    strcpy(info->user,     user);
    strcpy(info->password, password);
    info->suitability = suitability;
    return info;
}

void libsecret_free_authinfo(struct libsecret_authinfo* info){
    free(info);
}

int libsecret_set_request_timeout(int timeout){
    if (timeout <= 0) return 0;
    DPRINTF(7, "max_req_timeout=%d\n", timeout);
    pthread_mutex_lock(&m_auth_libsecret);
    max_req_timeout = timeout;
    pthread_mutex_unlock(&m_auth_libsecret);
    return 1;
}

int libsecret_enable(int state){
    int		ret;

    pthread_mutex_lock(&m_auth_libsecret);
    switch(libsecret){
	case LIBSECRET_DISABLED:
	case LIBSECRET_ENABLED:
	    libsecret = (state) ?
		LIBSECRET_ENABLED : LIBSECRET_DISABLED;
	    ret = 0;
	    break;
	default:
	    ret = -1;
	    break;
    }
    pthread_mutex_unlock(&m_auth_libsecret);
    return ret;
}

static gboolean req_timeout_prepare(GSource *source, gint *timeout){
    struct req_timeout	*req;
    struct timeval	tv;
    gint		diff;

    req = REQ_TIMEOUT(source);

    /* req->timeout_len have a milliseconds resolution */
    gettimeofday(&tv, NULL);
    diff = (tv.tv_sec - req->start_time.tv_sec) * 1000 +
	   (tv.tv_usec - req->start_time.tv_usec) / 1000;

    if (diff < 0){
	/* time in the past, redefine req->start_time to avoid long delay */
	req->start_time = tv;
	*timeout = req->timeout_len;
	return FALSE;
    }else if (diff < req->timeout_len){
	*timeout = req->timeout_len - diff;
	return FALSE;
    }
    if (!g_cancellable_is_cancelled(req->cancellable)) g_cancellable_cancel(req->cancellable);
    *timeout = 10;
    return FALSE;
}

static gboolean req_timeout_check(GSource *source){
    gint		timeout;

    return req_timeout_prepare(source, &timeout);
}

static gboolean req_timeout_dispatch(GSource *source,
				     GSourceFunc callback,
				     gpointer user_data){
    (void) source;
    (void) callback;
    (void) user_data;
    /* all termination done via req->cancellable, so do nothing */
    return FALSE;
}

static void req_timeout_finalize(GSource *source){
    struct req_timeout	*req;

    req = REQ_TIMEOUT(source);
    req->timeout_len = 0;
    req->expired = FALSE;
    g_object_unref(req->cancellable);
    req->cancellable = NULL;
}

static void request_timeout_init(struct req_timeout *req, int timeout){
    req->expired = FALSE;
    req->timeout_len = timeout;
    gettimeofday(&req->start_time, NULL);
    g_cancellable_reset(req->cancellable);
}

static void secret_service_get_callback(GObject *source_object,
                                        GAsyncResult *res,
                                        gpointer user_data)
{
    (void)source_object;
    (void)user_data;

    GError *error = NULL;
    secret_service = secret_service_get_finish(res, &error);
    if (error != NULL){
	secret_service = NULL;
	g_error_free(error);
    }
    if (secret_service == NULL) DPRINTF(10, "can't get secret service\n");
    g_main_loop_quit(loop);
}

static void secret_collection_for_alias_callback(GObject *source_object,
                                                 GAsyncResult *res,
                                                 gpointer user_data)
{
    (void)source_object;
    (void)user_data;

    GError *error = NULL;
    secret_collection = secret_collection_for_alias_finish(res, &error);
    if (error != NULL){
	secret_collection = NULL;
	g_error_free(error);
    }
    if (secret_collection == NULL) DPRINTF(10, "can't get secret collection\n");
    g_main_loop_quit(loop);
}

void libsecret_init(void){
    GSource		*source;
    GCancellable	*cancellable;

    g_set_application_name(PACKAGE_NAME);

    search_hash = g_hash_table_new(g_str_hash, g_str_equal);
    if (search_hash == NULL){
	DPRINTF(10, "can't create glib hash\n");
	goto g_hash_fail;
    }
    g_hash_table_insert(search_hash, "protocol", "smb");

    loop = g_main_loop_new(NULL, FALSE);
    if (loop == NULL){
	DPRINTF(10, "can't create glib main loop\n");
	goto g_main_loop_fail;
    }

    cancellable = g_cancellable_new();
    if (cancellable == NULL){
	DPRINTF(10, "can't create glib cancellable\n");
	goto g_source_fail;
    }

    source = g_source_new(&req_timeout_func,
			  sizeof(GSource) + sizeof(struct req_timeout));
    if (source == NULL){
	DPRINTF(10, "can't create glib event source\n");
	g_object_unref(cancellable);
	goto g_source_fail;
    }
    req_timeout = REQ_TIMEOUT(source);
    req_timeout->cancellable = cancellable;
    g_source_attach(source, g_main_loop_get_context(loop));

    request_timeout_init(req_timeout, max_req_timeout);
    secret_service_get(SECRET_SERVICE_OPEN_SESSION | SECRET_SERVICE_LOAD_COLLECTIONS,
                       req_timeout->cancellable,
                       secret_service_get_callback,
                       NULL);
    g_main_loop_run(loop);
    if (secret_service == NULL) goto g_source_fail;

    request_timeout_init(req_timeout, max_req_timeout);
    secret_collection_for_alias(secret_service, "default",
                                SECRET_COLLECTION_LOAD_ITEMS,
                                req_timeout->cancellable,
                                secret_collection_for_alias_callback,
                                NULL);
    g_main_loop_run(loop);
    if (secret_collection == NULL) goto secret_collection_fail;

    libsecret = LIBSECRET_ENABLED;
    return;

  secret_collection_fail:
    g_object_unref(secret_service);
    secret_service = NULL;
  g_source_fail:
    g_main_loop_unref(loop);
    loop = NULL;
  g_main_loop_fail:
    g_hash_table_unref(search_hash);
    search_hash = NULL;
  g_hash_fail:
    libsecret = LIBSECRET_NOT_AVAILABLE;
    DPRINTF(1, "libsecret is not available.\n");
    return;
}

void libsecret_done(void){
    if (libsecret == LIBSECRET_NOT_AVAILABLE) return;

    if (secret_collection != NULL){
	g_object_unref(secret_collection);
	secret_collection = NULL;
    }
    if (secret_service != NULL){
	g_object_unref(secret_service);
	secret_service = NULL;
    }
    if (loop != NULL){
	g_main_loop_unref(loop);
	loop = NULL;
    }
    if (search_hash != NULL){
	g_hash_table_unref(search_hash);
	search_hash = NULL;
    }
    libsecret = LIBSECRET_NOT_AVAILABLE;
}

/*
 * On success req->secret_item field will be filled and corresponding
 * reference will be taken.
 */
static void secret_collection_search_callback(GObject *source_object,
                                              GAsyncResult *res,
                                              gpointer user_data)
{
    SecretCollection	*secret_collection = (SecretCollection*) source_object;
    struct req_data	*req = (struct req_data*) user_data;
    GError		*error = NULL;
    GList		*list = NULL, *elem;
    const char		*domain, *user, *server, *share;
    SecretItem		*secret_item;
    GHashTable		*hash;

    list = secret_collection_search_finish(secret_collection, res, &error);
    if (error != NULL){
	list = NULL;
	g_error_free(error);
    }
    if (list == NULL) goto search_fail;

    for(elem = list; elem != NULL; elem = elem->next){
	secret_item = (SecretItem*)elem->data;

	hash = secret_item_get_attributes(secret_item);
	if (hash == NULL){
	    req->secret_item = NULL;
	    req->suitability = -1;
	    g_hash_table_unref(hash);
	    break;
	}

	user = g_hash_table_lookup(hash, "user");
	if ((user == NULL) || (*user == '\0')){
	    /* skip bad record */
	    goto loop_end;
	}

	domain = g_hash_table_lookup(hash, "domain");
	server = g_hash_table_lookup(hash, "server");
	share  = g_hash_table_lookup(hash, "object");
	if (domain == NULL) domain = "";
	if (server == NULL) server = "";
	if (share  == NULL) share  = "";

	if (*share != '\0'){
	    if (*server == '\0'){
		/* skip bad record */
		goto loop_end;
	    }
	    if ((req->suitability < AUTH_MATCH_RESOURCE) &&
	        (strcasecmp(req->server, server) == 0) &&
	        (strcasecmp(req->share,  share)  == 0))
	    {
		req->secret_item = secret_item;
		req->suitability = AUTH_MATCH_RESOURCE;
	    }
	    goto loop_end;
	}

	if (*server != '\0'){
	    /* record without share name */
	    if ((req->suitability < AUTH_MATCH_SERVER) &&
	        (strcasecmp(req->server, server) == 0))
	    {
		req->secret_item = secret_item;
		req->suitability = AUTH_MATCH_SERVER;
	    }
	    else
	    if ((req->suitability < AUTH_MATCH_DOMAIN_COMPAT) &&
	        (strcasecmp(req->domain, server) == 0))
	    {
		req->secret_item = secret_item;
		req->suitability = AUTH_MATCH_DOMAIN_COMPAT;
	    }
	    goto loop_end;
	}

	if ((*domain != '\0') &&
	    (req->suitability < AUTH_MATCH_DOMAIN) &&
	    (strcasecmp(req->domain, domain) == 0))
	{
	    req->secret_item = secret_item;
	    req->suitability = AUTH_MATCH_DOMAIN;
	    goto loop_end;
	}

	if (req->suitability < AUTH_MATCH_DEFAULT)
	{
	    req->secret_item = secret_item;
	    req->suitability = AUTH_MATCH_DEFAULT;
	}

      loop_end:
	g_hash_table_unref(hash);
    }

    if (req->secret_item != NULL) g_object_ref(req->secret_item);
    g_list_free_full(list, g_object_unref);
  search_fail:
    g_main_loop_quit(loop);
}

/*
 * On success libsecret_authinfo structure will be allocated and
 * req->auth_info field will point to allocated structure.
 * The req->secret_item field will be unrefered and cleared in any case.
 */
static void secret_item_load_secret_callback(GObject *source_object,
                                             GAsyncResult *res,
                                             gpointer user_data)
{
    SecretItem		*secret_item = (SecretItem*) source_object;
    struct req_data	*req = (struct req_data*) user_data;
    GError		*error = NULL;
    GHashTable		*hash;
    SecretValue		*secret;
    gboolean		result;
    const char		*domain, *user, *password;

    result = secret_item_load_secret_finish(secret_item, res, &error);
    if (error != NULL){
	result = FALSE;
	g_error_free(error);
    }
    if (result == FALSE) goto end;

    secret = secret_item_get_secret(secret_item);
    if (secret == NULL) goto end;

    hash = secret_item_get_attributes(secret_item);
    if (hash == NULL) goto password_fail;

    domain   = g_hash_table_lookup(hash, "domain");
    user     = g_hash_table_lookup(hash, "user");
    password = secret_value_get_text(secret);

    req->auth_info = libsecret_create_authinfo(domain, user, password, req->suitability);

    g_hash_table_unref(hash);
  password_fail:
    secret_value_unref(secret);
  end:
    g_main_loop_quit(loop);
    /* secret_item is not needed anymore, so unref it and clear req->secret_item as well */
    g_object_unref(secret_item);
    req->secret_item = NULL;
}

struct libsecret_authinfo * libsecret_get_authinfo(
						const char *domain,
						const char *server,
						const char *share){
    struct req_data	req;

    DPRINTF(10, "domain=%s, server=%s, share=%s\n", domain, server, share);

    if ((server == NULL) || (*server == '\0')) return NULL;
    if (domain == NULL) domain = "";
    if (share  == NULL) share  = "";

    req.domain = domain;
    req.server = server;
    req.share  = share;
    req.secret_item = NULL;
    req.auth_info   = NULL;
    req.suitability = -1;

    pthread_mutex_lock(&m_auth_libsecret);
    if (libsecret != LIBSECRET_ENABLED) goto end;

    if (g_main_context_acquire(g_main_loop_get_context(loop)) == FALSE){
	DPRINTF(10, "can't acquire GMainContext\n");
	goto end;
    }

    request_timeout_init(req_timeout, max_req_timeout);
    secret_collection_search(secret_collection, &libsecret_schema, search_hash,
                             SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK,
                             req_timeout->cancellable,
                             secret_collection_search_callback,
                             &req);
    g_main_loop_run(loop);

    if (req.secret_item != NULL){
	secret_item_load_secret(req.secret_item,
	                        req_timeout->cancellable,
	                        secret_item_load_secret_callback,
	                        &req);
	g_main_loop_run(loop);
    }

    g_main_context_release(g_main_loop_get_context(loop));
  end:
    pthread_mutex_unlock(&m_auth_libsecret);
    return req.auth_info;
}

#endif /* HAVE_LIBSECRET */
