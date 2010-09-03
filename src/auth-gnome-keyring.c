#include "config.h"
#ifdef HAVE_GNOME_KEYRING

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <glib.h>
#include <gnome-keyring.h>

#include "common.h"
#include "auth-gnome-keyring.h"


static gboolean req_timeout_prepare (GSource *source, gint *timeout);
static gboolean req_timeout_check   (GSource *source);
static gboolean req_timeout_dispatch(GSource *source, GSourceFunc callback,
				     gpointer user_data);
static void     req_timeout_finalize(GSource *source);


enum gnome_keyring_status{
    GNOME_KEYRING_NOT_AVAILABLE = -1,
    GNOME_KEYRING_DISABLED = 0,
    GNOME_KEYRING_ENABLED
};

struct req_timeout{
    struct timeval	start_time;
    gint		timeout_len;
    gboolean		expired;
};

struct req_data{
	const char			*domain;
	const char			*server;
	const char			*share;
	struct gnome_keyring_authinfo	*info;
};


#define REQ_TIMEOUT(source)	(&G_STRUCT_MEMBER(struct req_timeout, source, sizeof(GSource)))


int				max_req_timeout	 = 500;	/* in milliseconds */
enum gnome_keyring_status	gnome_keyring	 = GNOME_KEYRING_NOT_AVAILABLE;
pthread_mutex_t			m_auth_gnome	 = PTHREAD_MUTEX_INITIALIZER;
static GMainLoop		*loop		 = NULL;
static struct req_timeout	*req_timeout	 = NULL;
static GSourceFuncs		req_timeout_func = {
				    .prepare  = req_timeout_prepare,
				    .check    = req_timeout_check,
				    .dispatch = req_timeout_dispatch,
				    .finalize = req_timeout_finalize
				};


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
    return TRUE;
}

static gboolean req_timeout_check(GSource *source){
    gint		timeout;

    return req_timeout_prepare(source, &timeout);
}

static gboolean req_timeout_dispatch(GSource *source,
				     GSourceFunc callback,
				     gpointer user_data){
    struct req_timeout	*req;

    (void) callback;
    (void) user_data;

    req = REQ_TIMEOUT(source);
    req->expired = TRUE;
    g_main_loop_quit(loop);
    return TRUE;
}

static void req_timeout_finalize(GSource *source){
    struct req_timeout	*req;

    req = REQ_TIMEOUT(source);
    req->timeout_len = 0;
    req->expired = FALSE;
}

static void request_timeout_init(struct req_timeout *req, int timeout){
    req->expired = FALSE;
    req->timeout_len = timeout;
    gettimeofday(&req->start_time, NULL);
}

void gnome_keyring_init(void){
    GSource		*source;

    g_set_application_name(PACKAGE_NAME);
    if (gnome_keyring_is_available() != TRUE) goto error;

    loop = g_main_loop_new(NULL, FALSE);
    if (loop == NULL) goto error;

    source = g_source_new(&req_timeout_func,
			  sizeof(GSource) + sizeof(struct req_timeout));
    if (source == NULL) goto error;

    req_timeout = REQ_TIMEOUT(source);
    g_source_attach(source, g_main_loop_get_context(loop));
    gnome_keyring = GNOME_KEYRING_ENABLED;
    return;

  error:
    if (loop != NULL){
	g_main_loop_unref(loop);
	loop = NULL;
    }
    gnome_keyring = GNOME_KEYRING_NOT_AVAILABLE;
    DPRINTF(1, "gnome-keyring is not available.\n");
    return;
}

void gnome_keyring_done(void){
    if (gnome_keyring == GNOME_KEYRING_NOT_AVAILABLE) return;
    if (loop != NULL){
	g_main_loop_unref(loop);
	loop = NULL;
    }
    gnome_keyring = GNOME_KEYRING_NOT_AVAILABLE;
}

int gnome_keyring_set_request_timeout(int timeout){
    pthread_mutex_lock(&m_auth_gnome);
    if (timeout > 0) max_req_timeout = timeout;
    pthread_mutex_unlock(&m_auth_gnome);
    return (timeout > 0) ? 1 : 0;
}

int gnome_keyring_enable(int state){
    int		ret;

    pthread_mutex_lock(&m_auth_gnome);
    switch(gnome_keyring){
	case GNOME_KEYRING_DISABLED:
	case GNOME_KEYRING_ENABLED:
	    gnome_keyring = (state) ?
		GNOME_KEYRING_ENABLED : GNOME_KEYRING_DISABLED;
	    ret = 0;
	    break;
	default:
	    ret = -1;
	    break;
    }
    pthread_mutex_unlock(&m_auth_gnome);
    return ret;
}

struct gnome_keyring_authinfo * gnome_keyring_update_authinfo(
					struct gnome_keyring_authinfo *info,
					const char *domain,
					const char *user,
					const char *password,
					int suitability){
    if (domain == NULL) domain = "";
    if ((user == NULL) || (*user == '\0')) return info;
    if (password == NULL) password = "";

    if (info != NULL){
	if (info->suitability >= suitability) return info;
	gnome_keyring_free_authinfo(info);
	info = NULL;
    }

    info = malloc(sizeof(struct gnome_keyring_authinfo) +
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

void gnome_keyring_free_authinfo(struct gnome_keyring_authinfo* info){
    free(info);
}

void gnome_keyring_get_list_callback(GnomeKeyringResult result, GList *list, gpointer data){
    GList		*elem;
    struct req_data	*req = (struct req_data*) data;

    if (result != GNOME_KEYRING_RESULT_OK){
	g_main_quit(loop);
	return;
    }

    elem = g_list_first(list);
    while(elem != NULL){
	GnomeKeyringNetworkPasswordData		*p = elem->data;

	if (((req->server != NULL) && (req->server != '\0')) &&
	    ((req->share  != NULL) && (req->share  != '\0')) &&
            ((p->server != NULL)   && (*p->server != '\0')) &&
	    ((p->object != NULL)   && (*p->object != '\0')) &&
	    (strcasecmp(p->server, req->server) == 0) &&
	    (strcasecmp(p->object, req->share) == 0)){

	    req->info = gnome_keyring_update_authinfo(req->info,
				p->domain, p->user, p->password,
				AUTH_MATCH_RESOURCE);
	    /* fond the best password, so break loop */
	    break;
	}
	if (((req->server != NULL) && (req->server != '\0')) &&
	    ((p->server != NULL)   && (*p->server != '\0')) &&
	    ((p->object == NULL)   || (*p->object == '\0')) &&
	    (strcasecmp(p->server, req->server) == 0)){

	    req->info = gnome_keyring_update_authinfo(req->info,
				p->domain, p->user, p->password,
				AUTH_MATCH_SERVER);
	    goto next;
	}
	if (((req->domain != NULL) && (req->domain != '\0')) &&
	    ((p->domain != NULL)   && (*p->domain != '\0')) &&
	    ((p->server == NULL)   || (*p->server == '\0')) &&
	    ((p->object == NULL)   || (*p->object == '\0')) &&
	    (strcasecmp(p->domain, req->domain) == 0)){

	    req->info = gnome_keyring_update_authinfo(req->info,
				p->domain, p->user, p->password,
				AUTH_MATCH_DOMAIN);
	    goto next;
	}
	if (((req->domain != NULL) && (req->domain != '\0')) &&
	    ((p->server != NULL)   && (*p->server != '\0')) &&
	    ((p->object == NULL)   || (*p->object == '\0')) &&
	    (strcasecmp(p->server, req->domain) == 0)){

	    req->info = gnome_keyring_update_authinfo(req->info,
				p->domain, p->user, p->password,
				AUTH_MATCH_DOMAIN_COMPAT);
	    goto next;
	}
	if (((p->server == NULL) || (*p->server == '\0')) &&
	    ((p->object == NULL) || (*p->object == '\0'))){

	    req->info = gnome_keyring_update_authinfo(req->info,
				p->domain, p->user, p->password,
				AUTH_MATCH_DEFAULT);
	}

      next:
	elem = g_list_next(elem);
    }
    g_main_quit(loop);
}

struct gnome_keyring_authinfo * gnome_keyring_get_authinfo(
						const char *domain,
						const char *server,
						const char *share){
    gpointer		request;
    struct req_data	req_data;

    DPRINTF(10, "domain=%s, server=%s, share=%s\n", domain, server, share);

    if ((server == NULL) || (*server == '\0')) return NULL;
    if (domain == NULL) domain = "";
    if (share  == NULL) share  = "";

    req_data.domain      = domain;
    req_data.server      = server;
    req_data.share       = share;
    req_data.info        = NULL;

    pthread_mutex_lock(&m_auth_gnome);
    if (gnome_keyring != GNOME_KEYRING_ENABLED) goto end;
    if (req_timeout == NULL) goto end;

    if (g_main_context_acquire(g_main_loop_get_context(loop)) == FALSE){
	DPRINTF(10, "can't acquire GMainContext\n");
	goto end;
    }

    request_timeout_init(req_timeout, max_req_timeout);
    request = gnome_keyring_find_network_password(
		NULL,     /* user          */
		NULL,     /* domain        */
		NULL,     /* server        */
		NULL,     /* object        */
		"smb",    /* protocol      */
		NULL,     /* authtype      */
		0,        /* port          */
		gnome_keyring_get_list_callback, /* callback      */
		&req_data,/* callback data */
		NULL      /* destroy data  */
    );
    g_main_loop_run(loop);

    if (req_timeout->expired == TRUE){
	gnome_keyring_cancel_request(request);
	if (req_data.info != NULL){
	    gnome_keyring_free_authinfo(req_data.info);
	    req_data.info = NULL;
	}
    }

    g_main_context_release(g_main_loop_get_context(loop));
  end:
    pthread_mutex_unlock(&m_auth_gnome);
    return req_data.info;
}


#endif /* HAVE_GNOME_KEYRING */
