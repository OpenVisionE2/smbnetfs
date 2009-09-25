#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <libsmbclient.h>
#include <fuse/fuse.h>

#include "common.h"
#include "smbitem.h"
#include "auth.h"
#include "process.h"
#include "samba.h"
#include "reconfigure.h"

int		event_query_browser_flag	= 1;
int		event_time_step			= 10;
int		event_smb_tree_scan_period	= 300;
int		event_smb_tree_elements_ttl	= 900;
int		event_config_update_period	= 300;

time_t		event_last_smb_tree_scan	= (time_t) 0;
time_t		event_last_config_update	= (time_t) 0;

pthread_mutex_t	m_evthread			= PTHREAD_MUTEX_INITIALIZER;

pthread_t	event_ev_thread_id;
pthread_t	event_smb_thread_id;

int event_set_query_browser_flag(int flag){
    DPRINTF(7, "flag=%d\n", flag);
    pthread_mutex_lock(&m_evthread);
    event_query_browser_flag = flag;
    pthread_mutex_unlock(&m_evthread);
    return 1;
}

int event_get_query_browser_flag(void){
    int flag;

    pthread_mutex_lock(&m_evthread);
    flag = event_query_browser_flag;
    pthread_mutex_unlock(&m_evthread);
    DPRINTF(7, "flag=%d\n", flag);
    return flag;
}

int event_set_time_step(int step){
    if (step < 1) return 0;
    DPRINTF(7, "step=%d\n", step);
    pthread_mutex_lock(&m_evthread);
    event_time_step = step;
    pthread_mutex_unlock(&m_evthread);
    return 1;
}

int event_get_time_step(void){
    int step;

    pthread_mutex_lock(&m_evthread);
    step = event_time_step;
    pthread_mutex_unlock(&m_evthread);
    DPRINTF(7, "step=%d\n", step);
    return step;
}

int event_set_smb_tree_elements_ttl(int ttl){
    DPRINTF(7, "ttl=%d\n", ttl);
    pthread_mutex_lock(&m_evthread);
    if (ttl < event_smb_tree_scan_period) ttl = -1;
    else event_smb_tree_elements_ttl = ttl;
    pthread_mutex_unlock(&m_evthread);
    return (ttl > 0) ? 1 : 0;
}

int event_get_smb_tree_elements_ttl(void){
    int ttl;

    pthread_mutex_lock(&m_evthread);
    ttl = event_smb_tree_elements_ttl;
    pthread_mutex_unlock(&m_evthread);
    DPRINTF(7, "ttl=%d\n", ttl);
    return ttl;
}

int event_set_smb_tree_scan_period(int period){
    DPRINTF(7, "period=%d\n", period);
    pthread_mutex_lock(&m_evthread);
    if (period < event_time_step) period = -1;
    else event_smb_tree_scan_period = period;
    pthread_mutex_unlock(&m_evthread);
    return (period > 0) ? 1 : 0;
}

void event_set_last_smb_tree_scan(time_t scan_time){
    pthread_mutex_lock(&m_evthread);
    event_last_smb_tree_scan = scan_time;
    pthread_mutex_unlock(&m_evthread);
}

int event_is_time_for_smb_tree_scan(void){
    int flag;

    pthread_mutex_lock(&m_evthread);
    flag = (time(NULL) >= event_last_smb_tree_scan +
			  event_smb_tree_scan_period) ? 1 : 0;
    pthread_mutex_unlock(&m_evthread);
    return flag;
}

int event_set_config_update_period(int period){
    DPRINTF(7, "period=%d\n", period);
    pthread_mutex_lock(&m_evthread);
    if (period < event_time_step) period = -1;
    else event_config_update_period = period;
    pthread_mutex_unlock(&m_evthread);
    return (period > 0) ? 1 : 0;
}

void event_set_last_config_update(time_t update_time){
    pthread_mutex_lock(&m_evthread);
    event_last_config_update = update_time;
    pthread_mutex_unlock(&m_evthread);
}

int event_is_time_for_config_update(void){
    int flag;

    pthread_mutex_lock(&m_evthread);
    flag = (time(NULL) >= event_last_config_update +
			  event_config_update_period) ? 1 : 0;
    pthread_mutex_unlock(&m_evthread);
    return flag;
}

void event_scan_samba_group(const char *group){
    char		buf[4096], name[256], link[256];
    int			count;
    samba_fd		fd;

    DPRINTF(5, "group=%s\n", group);
    snprintf(name, sizeof(name), "/%s", group);
    fd = samba_opendir(name);
    while(1){
	struct smb_conn_dirent_rec	*rec;

	count = samba_readdir(fd, buf, sizeof(buf));
	if (count <= 0) break;

	rec = (struct smb_conn_dirent_rec *) buf;
	for( ; count >= (int) sizeof(struct smb_conn_dirent_rec);
			count -= sizeof(struct smb_conn_dirent_rec)){
	    switch(rec->smbc_type){
		case SMBC_SERVER:
		    smbitem_mkhost(rec->d_name, group, 1, SMBITEM_SAMBA_TREE);
		    snprintf(name, sizeof(name), "%s/%s", group, rec->d_name);
		    snprintf(link, sizeof(link), "../%s", rec->d_name);
		    smbitem_mklink(name, link, SMBITEM_SAMBA_TREE);
		    break;
		default:
		    DPRINTF(6, "ups..., smbc_type=%d, d_name=%s\n",
				rec->smbc_type, rec->d_name);
	    }
	    rec++;
	}
    }
    samba_closedir(fd);
}

void event_scan_smb_root(void){
    char		buf[4096];
    int			count;
    samba_fd		fd;

    DPRINTF(5, "reading group list\n");
    fd = samba_opendir("/");
    while(1){
	struct smb_conn_dirent_rec	*rec;

	count = samba_readdir(fd, buf, sizeof(buf));
	if (count <= 0) break;

	rec = (struct smb_conn_dirent_rec *) buf;
	for( ; count >= (int) sizeof(struct smb_conn_dirent_rec);
			count -= sizeof(struct smb_conn_dirent_rec)){
	    switch(rec->smbc_type){
		case SMBC_WORKGROUP:
		    smbitem_mkgroup(rec->d_name, SMBITEM_SAMBA_TREE);
		    break;
		default:
		    DPRINTF(6, "ups..., smbc_type=%d, d_name=%s\n",
				rec->smbc_type, rec->d_name);
	    }
	    rec++;
	}
    }
    samba_closedir(fd);
}

void event_scan_smb_tree(void){
    int			i;
    struct smbitem	*dir;

    if (event_get_query_browser_flag()) event_scan_smb_root();
    dir = smbitem_get_samba_groups();
    for(i = 0; i < dir->child_cnt; i++){
	if (dir->childs[i]->type != SMBITEM_GROUP) continue;
	event_scan_samba_group(dir->childs[i]->name);
    }
    smbitem_release_dir(dir);
}

void* event_update_smb_tree_thread(void *data){
    time_t		scan_time;
    time_t		die_threshold;
    int			time_step;

    (void)data;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    scan_time = time(NULL);
    event_scan_smb_tree();
    event_set_last_smb_tree_scan(scan_time);

    while(1){
	time_step = event_get_time_step();
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	sleep(time_step);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	if (event_is_time_for_smb_tree_scan()){
	    scan_time = time(NULL);
	    die_threshold = scan_time - event_get_smb_tree_elements_ttl();
	    DPRINTF(5, "start at timestamp=%u, die_threshold=%u\n",
			(unsigned) scan_time, (unsigned) die_threshold);

	    event_scan_smb_tree();
	    smbitem_delete_obsolete(die_threshold, SMBITEM_SAMBA_TREE);
	    event_set_last_smb_tree_scan(scan_time);
	}
    }
    return NULL;
}

void event_reread_config(void){
    time_t		reread_time;

    reread_time = time(NULL);
    DPRINTF(5, "start at timestamp=%u\n", (unsigned) reread_time);

    reconfigure_read_config(0);
    smbitem_delete_obsolete(reread_time, SMBITEM_USER_TREE);
    auth_delete_obsolete(reread_time);
    event_set_last_config_update(reread_time);
}

void* event_thread(void *data){
    siginfo_t		siginfo;
    sigset_t		signal_set;
    time_t		start_time;
    struct timespec	timeout;

    (void)data;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    start_time = time(NULL);
    event_set_last_config_update(start_time);

    /* set signals to watch */
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGHUP);
    sigaddset(&signal_set, SIGCHLD);

    while(1){
	timeout.tv_sec  = event_get_time_step();
	timeout.tv_nsec = 0;
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	sigtimedwait(&signal_set, &siginfo, &timeout);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	if (siginfo.si_signo == SIGCHLD) process_cleanup_from_zombies();
	if ((siginfo.si_signo == SIGHUP) ||
	    event_is_time_for_config_update()) event_reread_config();
    }
    return NULL;
}

static void* event_init(struct fuse_conn_info *conn){
    (void) conn;

    if (pthread_create(&event_smb_thread_id, NULL,
			event_update_smb_tree_thread, NULL) != 0){
	fprintf(stderr, "Could not create smb_tree thread\n");
	exit(1);
    }
    if (pthread_create(&event_ev_thread_id, NULL,
			event_thread, NULL) != 0){
	fprintf(stderr, "Could not create event thread\n");
	exit(1);
    }
    return NULL;
}

static void event_destroy(void *private_data){
    (void)private_data;

    DPRINTF(1, "Destroy cfg and smb_tree threads\n");
    process_disable_new_smb_conn_starting();
    process_kill_all();
    pthread_cancel(event_ev_thread_id);
    pthread_cancel(event_smb_thread_id);
    pthread_join(event_ev_thread_id, NULL);
    pthread_join(event_smb_thread_id, NULL);
}

void event_set_event_handler(struct fuse_operations *file_oper){
    file_oper->init	= event_init;
    file_oper->destroy	= event_destroy;
}
