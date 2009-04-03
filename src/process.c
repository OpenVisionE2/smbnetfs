#include "config.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <signal.h>
#include <pthread.h>
#include <langinfo.h>

#include "common.h"
#include "list.h"
#include "smb_conn_proto.h"
#include "process.h"

#define	CHARSET_LEN	64

struct process_rec{
    LIST	entries;
    int		child_fd;
    pid_t	child_pid;
};

char	process_system_charset[CHARSET_LEN]		= "UTF-8";
char	process_server_local_charset[CHARSET_LEN]	= "UTF-8";
char	process_server_samba_charset[CHARSET_LEN]	= "UTF-8";
int	process_server_listen_timeout			= 300;
int	process_server_smb_debug_level			= 0;
int	process_start_enabled				= 1;

LIST		process_list		= STATIC_LIST_INITIALIZER(process_list);
pthread_mutex_t	m_process		= PTHREAD_MUTEX_INITIALIZER;


int process_init(void){
    static int		initialized = 0;

    char		*charset;

    if (! initialized){
	if ((charset = nl_langinfo(CODESET)) == NULL){
	    DPRINTF(0, "Can't find system charset, use utf-8 instead. Check your locale.\n");
	    charset = "UTF-8";
	}else{
	    initialized = 1;
	}
	strncpy(process_system_charset, charset, CHARSET_LEN);
	process_system_charset[CHARSET_LEN - 1] = '\0';
	DPRINTF(5, "system_charset=%s\n", process_system_charset);
    }
    pthread_mutex_lock(&m_process);
    strncpy(process_server_local_charset, process_system_charset, CHARSET_LEN);
    process_server_local_charset[CHARSET_LEN - 1] = '\0';
    strncpy(process_server_samba_charset, "UTF-8", CHARSET_LEN);
    process_server_samba_charset[CHARSET_LEN - 1] = '\0';
    pthread_mutex_unlock(&m_process);
    return initialized;
}

void process_disable_new_smb_conn_starting(void){
    pthread_mutex_lock(&m_process);
    process_start_enabled = 0;
    DPRINTF(7, "disable new process starting at %u\n",
				(unsigned int) time(NULL));
    pthread_mutex_unlock(&m_process);
}

int process_set_server_listen_timeout(int timeout){
    if (timeout < 30) return 0;
    DPRINTF(7, "timeout=%d\n", timeout);
    pthread_mutex_lock(&m_process);
    process_server_listen_timeout = timeout;
    pthread_mutex_unlock(&m_process);
    return 1;
}

int process_set_server_smb_debug_level(int level){
    if ((level < 0) || (level > 10)) return 0;
    DPRINTF(7, "level=%d\n", level);
    pthread_mutex_lock(&m_process);
    process_server_smb_debug_level = level;
    pthread_mutex_unlock(&m_process);
    return 1;
}

int process_set_server_local_charset(const char *charset){
    if ((charset == NULL) || (*charset == '\0'))
	charset = process_system_charset;

    DPRINTF(7, "local_charset=%s\n", charset);
    pthread_mutex_lock(&m_process);
    strncpy(process_server_local_charset, charset, CHARSET_LEN);
    process_server_local_charset[CHARSET_LEN - 1] = '\0';
    pthread_mutex_unlock(&m_process);
    return 1;
}

int process_set_server_samba_charset(const char *charset){
    if ((charset == NULL) || (*charset == '\0')) charset = "UTF-8";

    DPRINTF(7, "samba_charset=%s\n", charset);
    pthread_mutex_lock(&m_process);
    strncpy(process_server_samba_charset, charset, CHARSET_LEN);
    process_server_samba_charset[CHARSET_LEN - 1] = '\0';
    pthread_mutex_unlock(&m_process);
    return 1;
}

int process_start_new_smb_conn(char *shmem_ptr, size_t shmem_size){
    int			error;
    int			pair[2];
    pid_t		pid;
    struct process_rec	*rec;

    if ((shmem_ptr == NULL) || ((int) shmem_size < getpagesize())){
	errno = EINVAL;
	return -1;
    }

    pid = (pid_t) (-1);
    pthread_mutex_lock(&m_process);
    if (process_start_enabled != 1){
	error = EPERM;
	pair[0] = -1;
	goto error;
    }
    if ((rec = malloc(sizeof(struct process_rec))) == NULL){
	error = errno;
	pair[0] = -1;
	goto error;
    }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) < 0){
	error = errno;
	free(rec);
	pair[0] = -1;
	goto error;
    }

    memset(rec, 0, sizeof(struct process_rec));

    if ((pid = fork()) == -1){
	error = errno;
	close(pair[0]);
	close(pair[1]);
	free(rec);
	pair[0] = -1;
	goto error;
    }

    if (pid == 0){
	struct smb_conn_srv_ctx	srv_ctx;

	pthread_mutex_unlock(&m_process);
	close(pair[0]);

	srv_ctx.conn_fd         = pair[1];
	srv_ctx.shmem_ptr       = shmem_ptr;
	srv_ctx.shmem_size      = shmem_size;
	srv_ctx.timeout         = process_server_listen_timeout;
	srv_ctx.smb_debug_level = process_server_smb_debug_level;
	srv_ctx.samba_charset   = process_server_samba_charset;
	srv_ctx.local_charset   = process_server_local_charset;
	smb_conn_srv_listen(&srv_ctx);
	exit(EXIT_SUCCESS);
    }

    close(pair[1]);
    rec->child_pid = pid;
    rec->child_fd  = pair[0];
    add_to_list(&process_list, &rec->entries);
    DPRINTF(6, "starting new child with pid=%d, fd=%d\n", (int) pid, pair[0]);

  error:
    pthread_mutex_unlock(&m_process);
    return pair[0];
}

int process_is_smb_conn_alive(int fd){
    int			result;
    LIST		*elem;
    struct process_rec	*rec;

    result = 0;
    pthread_mutex_lock(&m_process);
    elem = first_list_elem(&process_list);
    while(is_valid_list_elem(&process_list, elem)){
	rec = list_entry(elem, struct process_rec, entries);
	elem = elem->next;

	if ((rec->child_fd  == fd) &&
	    (rec->child_pid != (pid_t) (-1))){
	    result = 1;
	    break;
	}
    }
    pthread_mutex_unlock(&m_process);
    return result;
}

void process_kill_all(void){
    LIST		*elem;
    struct process_rec	*rec;

    pthread_mutex_lock(&m_process);
    elem = first_list_elem(&process_list);
    while(is_valid_list_elem(&process_list, elem)){
	rec = list_entry(elem, struct process_rec, entries);
	elem = elem->next;

	if (rec->child_pid != (pid_t) (-1)){
	    DPRINTF(6, "kill child with pid=%d, fd=%d\n",
			(int) rec->child_pid, rec->child_fd);
	    kill(rec->child_pid, SIGKILL);
	}
    }
    pthread_mutex_unlock(&m_process);
}

void process_kill_by_smb_conn_fd(int fd){
    LIST		*elem;
    struct process_rec	*rec;

    pthread_mutex_lock(&m_process);
    elem = first_list_elem(&process_list);
    while(is_valid_list_elem(&process_list, elem)){
	rec = list_entry(elem, struct process_rec, entries);
	elem = elem->next;

	if (rec->child_fd == fd){
	    DPRINTF(6, "closing child connection with pid=%d, fd=%d\n",
				(int) rec->child_pid, rec->child_fd);
	    close(rec->child_fd);
	    rec->child_fd = -1;
	    if (rec->child_pid == (pid_t) (-1)){
		DPRINTF(6, "cleanup child record with fd=%d\n", fd);
		remove_from_list(&process_list, &rec->entries);
		free(rec);
	    }else
		kill(rec->child_pid, SIGKILL);
	    break;
	}
    }
    pthread_mutex_unlock(&m_process);
}

void process_cleanup_from_zombies(void){
    pid_t		pid;
    LIST		*elem;
    struct process_rec	*rec;

    pthread_mutex_lock(&m_process);
    while(1){
	pid = waitpid((pid_t) (-1), NULL, WNOHANG);
	if (pid <= 0) break;

	elem = first_list_elem(&process_list);
	while(is_valid_list_elem(&process_list, elem)){
	    rec = list_entry(elem, struct process_rec, entries);
	    elem = elem->next;

	    if (rec->child_pid == pid){
		DPRINTF(6, "R.I.P. child with pid=%d, fd=%d\n",
				(int) rec->child_pid, rec->child_fd);
		rec->child_pid = (pid_t) (-1);
		if (rec->child_fd == -1){
		    DPRINTF(6, "cleanup child record with pid=%d\n", (int) pid);
		    remove_from_list(&process_list, &rec->entries);
		    free(rec);
		}
		break;
	    }
	}
    }
    pthread_mutex_unlock(&m_process);
}
