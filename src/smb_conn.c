#include "config.h"
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>

#include "list.h"
#include "common.h"
#include "smbitem.h"
#include "auth-gnome-keyring.h"
#include "auth.h"
#include "smb_conn_proto.h"
#include "process.h"
#include "smb_conn.h"

#ifndef MAP_ANONYMOUS
    #define	MAP_ANONYMOUS	MAP_ANON
#endif


int		smb_conn_max_retry_count	= 3;
int		smb_conn_max_passwd_query_count	= 10;
int		smb_conn_server_reply_timeout	= 60;
pthread_mutex_t	m_smb_conn			= PTHREAD_MUTEX_INITIALIZER;

int smb_conn_set_max_retry_count(int count){
    if (count < 1) return 0;
    DPRINTF(7, "count=%d\n", count);
    pthread_mutex_lock(&m_smb_conn);
    smb_conn_max_retry_count = count;
    pthread_mutex_unlock(&m_smb_conn);
    return 1;
}

int smb_conn_get_max_retry_count(void){
    int count;

    pthread_mutex_lock(&m_smb_conn);
    count = smb_conn_max_retry_count;
    pthread_mutex_unlock(&m_smb_conn);
    DPRINTF(7, "count=%d\n", count);
    return count;
}

int smb_conn_set_max_passwd_query_count(int count){
    if (count < 3) return 0;
    DPRINTF(7, "count=%d\n", count);
    pthread_mutex_lock(&m_smb_conn);
    smb_conn_max_passwd_query_count = count;
    pthread_mutex_unlock(&m_smb_conn);
    return 1;
}

int smb_conn_get_max_passwd_query_count(void){
    int count;

    pthread_mutex_lock(&m_smb_conn);
    count = smb_conn_max_passwd_query_count;
    pthread_mutex_unlock(&m_smb_conn);
    DPRINTF(7, "count=%d\n", count);
    return count;
}

int smb_conn_set_server_reply_timeout(int timeout){
    if (timeout < 10) return 0;
    DPRINTF(7, "timeout=%d\n", timeout);
    pthread_mutex_lock(&m_smb_conn);
    smb_conn_server_reply_timeout = timeout;
    pthread_mutex_unlock(&m_smb_conn);
    return 1;
}

int smb_conn_get_server_reply_timeout(void){
    int timeout;

    pthread_mutex_lock(&m_smb_conn);
    timeout = smb_conn_server_reply_timeout;
    pthread_mutex_unlock(&m_smb_conn);
    DPRINTF(7, "timeout=%d\n", timeout);
    return timeout;
}

void smb_conn_connection_close(struct smb_conn_ctx *ctx){
    LIST			*elem;
    struct smb_conn_file	*conn_file;

    if (ctx->shmem_ptr == NULL) return;

    process_kill_by_smb_conn_fd(ctx->conn_fd);
    ctx->conn_fd = -1;

    elem = first_list_elem(&ctx->smb_conn_file_list);
    while(is_valid_list_elem(&ctx->smb_conn_file_list, elem)){
	conn_file = list_entry(elem, struct smb_conn_file, entries);
	conn_file->access_time = 0;
	conn_file->srv_fd = NULL;
	elem = elem->next;
    }
}

int smb_conn_up_if_broken(struct smb_conn_ctx *ctx){
    if (ctx->conn_fd != -1){
	if (process_is_smb_conn_alive(ctx->conn_fd)) return 0;
	smb_conn_connection_close(ctx);
    }
    ctx->conn_fd = process_start_new_smb_conn(ctx->shmem_ptr, ctx->shmem_size);
    return (ctx->conn_fd != -1) ? 0 : -1;
}

int smb_conn_ctx_init(struct smb_conn_ctx *ctx, size_t shmem_size){
    if ((ssize_t) shmem_size < getpagesize()) return -1;

    init_list(&ctx->smb_conn_file_list);
    pthread_mutex_init(&ctx->mutex, NULL);
    ctx->access_time = time(NULL);
    ctx->shmem_size = shmem_size;
    ctx->conn_fd = -1;

    if ((ctx->shmem_ptr = (char*) mmap(NULL, ctx->shmem_size,
	    PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED){
	pthread_mutex_destroy(&ctx->mutex);
	return -1;
    }
    return 0;
}

int smb_conn_ctx_destroy(struct smb_conn_ctx *ctx){
    int result = -1;

    if (ctx->shmem_ptr == NULL) return -1;

    pthread_mutex_lock(&ctx->mutex);
    if (is_list_empty(&ctx->smb_conn_file_list)){
	if (ctx->conn_fd != -1) smb_conn_connection_close(ctx);
	munmap(ctx->shmem_ptr, ctx->shmem_size);
	ctx->shmem_ptr = NULL;
	result = 0;
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (result == 0) pthread_mutex_destroy(&ctx->mutex);
    return result;
}

int smb_conn_send_password_base(struct smb_conn_ctx *ctx, const char *domain,
				const char *user, const char *password){
    ssize_t			bytes;
    struct iovec		iov[5];
    struct smb_conn_query_hdr	header;
    struct smb_conn_passwd	data;

    if ((ctx == NULL) || (ctx->conn_fd == -1)) return -1;

    iov[0].iov_base = &header;
    iov[0].iov_len  = sizeof(header);
    iov[1].iov_base = &data;
    iov[1].iov_len  = sizeof(data);
    iov[2].iov_base = (char*) domain;
    iov[2].iov_len  = strlen(domain) + 1;
    iov[3].iov_base = (char*) user;
    iov[3].iov_len  = strlen(user) + 1;
    iov[4].iov_base = (char*) password;
    iov[4].iov_len  = strlen(password) + 1;

    header.query_len   = iov[0].iov_len + iov[1].iov_len +
			 iov[2].iov_len + iov[3].iov_len + iov[4].iov_len;
    header.query_cmd   = PASSWORD;
    header.debug_level = common_get_smbnetfs_debug_level();
    data.domain_offs   = sizeof(data);
    data.username_offs = sizeof(data) + iov[2].iov_len;
    data.password_offs = sizeof(data) + iov[2].iov_len + iov[3].iov_len;

    if (header.query_len <= COMM_BUF_SIZE){
	/* send password data */
	bytes = writev(ctx->conn_fd, iov, 5);
    }else{
	bytes = -1;
    }
    return (bytes == (ssize_t) header.query_len) ? 0 : -1;
}

int smb_conn_send_password(struct smb_conn_ctx *ctx,
			const char *server, const char *share){

#ifdef HAVE_GNOME_KEYRING
    struct gnome_keyring_authinfo	*gnome_keyring_info;
#endif /* HAVE_GNOME_KEYRING */
    struct authinfo			*config_file_info;
    int					config_file_info_suitability;
    char				workgroup[256];
    int					ret;

    if ((ctx == NULL) || (ctx->conn_fd == -1)) return -1;

    memset(workgroup, 0, sizeof(workgroup));
    smbitem_get_group(server, workgroup, sizeof(workgroup));

    config_file_info_suitability = -1;
    config_file_info = auth_get_authinfo(
				workgroup, server, share,
				&config_file_info_suitability);
    if ((config_file_info != NULL) &&
	((config_file_info->domain   == NULL) ||
	 (config_file_info->user     == NULL) ||
	 (config_file_info->password == NULL))){

	DPRINTF(0, "WARNING!!! Damaged authinfo record\n");
	auth_release_authinfo(config_file_info);
	config_file_info = NULL;
	config_file_info_suitability = -1;
    }

#ifdef HAVE_GNOME_KEYRING
    gnome_keyring_info = gnome_keyring_get_authinfo(
				workgroup, server, share);
    if ((gnome_keyring_info != NULL) &&
	((gnome_keyring_info->domain   == NULL) ||
	 (gnome_keyring_info->user     == NULL) ||
	 (gnome_keyring_info->password == NULL))){

	DPRINTF(0, "WARNING!!! Damaged gnome_keyring_info record\n");
	gnome_keyring_free_authinfo(gnome_keyring_info);
	gnome_keyring_info = NULL;
    }

    if (gnome_keyring_info != NULL){
	if (gnome_keyring_info->suitability >= config_file_info_suitability){
	    if (config_file_info != NULL)
		auth_release_authinfo(config_file_info);
	    config_file_info = NULL;
	    config_file_info_suitability = -1;
	    goto use_gnome_keyring_info;
	}
	gnome_keyring_free_authinfo(gnome_keyring_info);
	gnome_keyring_info = NULL;
    }
#endif /* HAVE_GNOME_KEYRING */

    if (config_file_info == NULL) return -1;
    ret = smb_conn_send_password_base(ctx,
			config_file_info->domain,
			config_file_info->user,
			config_file_info->password);
    auth_release_authinfo(config_file_info);
    return ret;

#ifdef HAVE_GNOME_KEYRING
  use_gnome_keyring_info:
    ret = smb_conn_send_password_base(ctx,
			gnome_keyring_info->domain,
			gnome_keyring_info->user,
			gnome_keyring_info->password);
    gnome_keyring_free_authinfo(gnome_keyring_info);
    return ret;
#endif /* HAVE_GNOME_KEYRING */
}

int smb_conn_process_query_lowlevel_va(
			struct smb_conn_ctx *ctx,
			enum smb_conn_cmd query_cmd,
			void *query, size_t query_len,
			int *errno_value,
			void *reply, size_t reply_len,
			va_list ap){

    int				iov_cnt, retval, count;
    ssize_t			bytes;
    struct iovec		iov[4];
    struct smb_conn_query_hdr	query_header;

    if ((ctx == NULL) || (ctx->conn_fd == -1) ||
	((query == NULL) || (query_len == 0)) ||
	(errno_value == NULL) ||
	((reply == NULL) && (reply_len != 0))) return EINVAL;

    iov_cnt = 2;
    query_header.query_cmd = query_cmd;
    query_header.debug_level = common_get_smbnetfs_debug_level();
    query_header.query_len = sizeof(query_header) + query_len;

    iov[0].iov_base = &query_header;
    iov[0].iov_len  = sizeof(query_header);
    iov[1].iov_base = query;
    iov[1].iov_len  = query_len;

    while(1){
	const char	*str;

	str = va_arg(ap, const char *);
	if (str == NULL) break;
	if (iov_cnt >= (ssize_t) (sizeof(iov) / sizeof(struct iovec))){
	    va_end(ap);
	    return EINVAL;
	}

	iov[iov_cnt].iov_base = (void *) str;
	iov[iov_cnt].iov_len  = strlen(str) + 1;
	query_header.query_len += iov[iov_cnt].iov_len;
	iov_cnt++;
    }

    if (query_header.query_len > COMM_BUF_SIZE) return EIO;

    /* send query */
    bytes = writev(ctx->conn_fd, iov, iov_cnt);
    if (bytes != (ssize_t) query_header.query_len) goto error;

    count = 0;
    while(1){
	fd_set				readfds, exceptfds;
	struct timeval			tv;
	struct smb_conn_reply_hdr	*reply_hdr;
	char				buf[COMM_BUF_SIZE];

	tv.tv_sec = smb_conn_get_server_reply_timeout();
	tv.tv_usec = 0;

	FD_ZERO(&readfds);
	FD_SET(ctx->conn_fd, &readfds);

	FD_ZERO(&exceptfds);
	FD_SET(ctx->conn_fd, &exceptfds);

	/* wait for reply */
	retval = select(ctx->conn_fd + 1, &readfds, NULL, &exceptfds, &tv);
	if ((retval <= 0) || FD_ISSET(ctx->conn_fd, &exceptfds)) goto error;

	/* read reply */
	bytes = read(ctx->conn_fd, buf, COMM_BUF_SIZE);
	if (bytes < (ssize_t) sizeof(struct smb_conn_reply_hdr)) goto error;

	/* check reply */
	reply_hdr = (struct smb_conn_reply_hdr *) buf;
	if ((ssize_t) reply_hdr->reply_len != bytes) goto error;

	/* is it message? */
	if ((reply_hdr->reply_cmd == MESSAGE) ||
	    (reply_hdr->reply_cmd == DIE_MSG)){

	    const char			*msg;
	    struct smb_conn_message_req	*msg_req;

	    if ((reply_hdr->reply_cmd == MESSAGE) &&
		(reply_hdr->errno_value != 0)) goto error;

	    if (buf[bytes - 1] != '\0' ) goto error;
	    bytes -= sizeof(struct smb_conn_reply_hdr);
	    if (bytes < (ssize_t) sizeof(struct smb_conn_message_req))
		goto error;

	    msg_req = (struct smb_conn_message_req *) (reply_hdr + 1);
	    if (msg_req->msg_offs != sizeof(struct smb_conn_message_req))
		goto error;
	    bytes -= sizeof(struct smb_conn_message_req);

	    msg = ((char *) msg_req) + msg_req->msg_offs;
	    if (bytes != (ssize_t) (strlen(msg) + 1)) goto error;

	    common_debug_print(msg_req->debug_level, msg);

	    if (reply_hdr->reply_cmd == DIE_MSG){
		errno = reply_hdr->errno_value;
		goto error;
	    }
	    continue;
	}

	/* is it password request? */
	if (reply_hdr->reply_cmd == PASSWORD){
	    const char			*server, *share;
	    struct smb_conn_passwd_req	*passwd_req;

	    /* infinite loop? */
	    if (count > smb_conn_get_max_passwd_query_count()) goto error;

	    if (reply_hdr->errno_value != 0) goto error;
	    if (buf[bytes - 1] != '\0' ) goto error;
	    bytes -= sizeof(struct smb_conn_reply_hdr);
	    if (bytes < (ssize_t) sizeof(struct smb_conn_passwd_req)) goto error;

	    passwd_req = (struct smb_conn_passwd_req *) (reply_hdr + 1);
	    if ((passwd_req->server_offs != sizeof(struct smb_conn_passwd_req)) ||
		(passwd_req->share_offs  <= passwd_req->server_offs) ||
		((ssize_t) passwd_req->share_offs  >  bytes - 1)) goto error;
	    bytes -= sizeof(struct smb_conn_passwd_req);

	    server = ((char *) passwd_req) + passwd_req->server_offs;
	    share  = ((char *) passwd_req) + passwd_req->share_offs;
	    if (bytes != (ssize_t) (strlen(server) + strlen(share) + 2))
		goto error;

	    /* process password request */
	    count++;
	    if (smb_conn_send_password(ctx, server, share) != 0) goto error;
	    continue;
	}

	/* it should be our reply */
	if (reply_hdr->reply_cmd != query_cmd) goto error;
	if (reply_hdr->errno_value != 0) reply_len = 0;
	if (bytes != (ssize_t) (sizeof(struct smb_conn_reply_hdr) + reply_len))
	    goto error;

	/* ok, we got a reply, store error/reply and exit */
	if (reply_len != 0) memcpy(reply, reply_hdr + 1, reply_len);
	*errno_value = reply_hdr->errno_value;
	return 0;
    }

  error:
    smb_conn_connection_close(ctx);
    return EIO;
}

int smb_conn_process_query_lowlevel(
			struct smb_conn_ctx *ctx,
			enum smb_conn_cmd query_cmd,
			void *query, size_t query_len,
			int *errno_value,
			void *reply, size_t reply_len,
			...){
    va_list	ap;
    int		retval;

    va_start(ap, reply_len);
    retval = smb_conn_process_query_lowlevel_va(
			ctx,
			query_cmd,
			query, query_len,
			errno_value,
			reply, reply_len,
			ap);
    va_end(ap);
    return retval;
}

int smb_conn_process_query(
			struct smb_conn_ctx *ctx,
			enum smb_conn_cmd query_cmd,
			void *query, size_t query_len,
			void *reply, size_t reply_len,
			...){

    va_list		ap;
    int			count, retval, errno_value;

    for(count = 0; count < smb_conn_get_max_retry_count(); count++){
	if (smb_conn_up_if_broken(ctx) != 0) break;

	va_start(ap, reply_len);
	retval = smb_conn_process_query_lowlevel_va(
			ctx,
			query_cmd,
			query, query_len,
			&errno_value,
			reply, reply_len,
			ap);
	va_end(ap);

	if (retval == 0) return errno_value;
	sleep(2);
    }
    return EIO;
}

int smb_conn_process_fd_query(
			struct smb_conn_ctx *ctx,
			enum smb_conn_cmd query_cmd,
			struct smb_conn_file *file,
			smb_conn_srv_fd *query_fd_ptr,
			void *query, size_t query_len,
			void *reply, size_t reply_len){

    int			count, retval, errno_value;

    if ((file == NULL) || (file->url == NULL)) return EINVAL;

    for(count = 0; count < smb_conn_get_max_retry_count(); count++){
	if (smb_conn_up_if_broken(ctx) != 0) break;

	if (file->srv_fd == NULL){
	    union{
		struct smb_conn_open_query	open;
		struct smb_conn_url_query	opendir;
	    } fd_query;
	    size_t			fd_len;
	    struct smb_conn_fd_reply	fd_reply;

	    switch(file->reopen_cmd){
		case OPEN:
		    fd_len = sizeof(fd_query.open);

		    fd_query.open.url_offs = sizeof(fd_query.open);
		    fd_query.open.mode     = 0664;
		    fd_query.open.flags    = file->reopen_flags & (~(O_CREAT | O_TRUNC));
		    break;

		case OPENDIR:
		    /* we cant reopen directory with non-zero offset, so return EIO */
		    if (file->reopen_flags != 0) return EIO;

		    fd_len = sizeof(fd_query.opendir);

		    fd_query.opendir.url_offs = sizeof(fd_query.opendir);
		    break;

		default:
		    return EIO;
	    }

	    retval = smb_conn_process_query_lowlevel(
			ctx,
			file->reopen_cmd,
			&fd_query, fd_len,
			&errno_value,
			&fd_reply, sizeof(fd_reply),
			file->url, NULL);
	    if (retval != 0) goto loop_end;
	    if (errno_value != 0) return errno_value;
	
	    file->srv_fd = fd_reply.srv_fd;
	}

	*query_fd_ptr = file->srv_fd;
	retval = smb_conn_process_query_lowlevel(
			ctx,
			query_cmd,
			query, query_len,
			&errno_value,
			reply, reply_len,
			NULL);
	if (retval == 0) return errno_value;

      loop_end:
	sleep(2);
    }
    return EIO;
}

smb_conn_fd smb_conn_open(struct smb_conn_ctx *ctx,
				const char *url, int flags, mode_t mode){

    int					error;
    struct smb_conn_file		*file;
    struct smb_conn_open_query		query;
    struct smb_conn_fd_reply		reply;

    file = malloc(sizeof(struct smb_conn_file) + strlen(url) + 1);
    if (file == NULL){
	errno = ENOMEM;
	return NULL;
    }

    memset(&file->entries, 0, sizeof(LIST));
    file->access_time  = (time_t) 0;
    file->ctx          = ctx;
    file->url          = ((char *) file) + sizeof(struct smb_conn_file);
    file->reopen_cmd   = OPEN;
    file->reopen_flags = flags & ~(O_CREAT | O_EXCL | O_TRUNC);
    file->srv_fd       = NULL;
    strcpy(file->url, url);

    query.url_offs = sizeof(struct smb_conn_open_query);
    query.mode     = mode;
    query.flags    = flags;

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    file->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, OPEN,
			&query, sizeof(query),
			&reply, sizeof(reply),
			url, NULL);
    if (error == 0){
	file->srv_fd = reply.srv_fd;
	add_to_list(&ctx->smb_conn_file_list, &file->entries);
    }else{
	free(file);
	file = NULL;
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0) errno = error;
    return file;
}

smb_conn_fd smb_conn_creat(struct smb_conn_ctx *ctx,
				const char *url, mode_t mode){

    int					error;
    struct smb_conn_file		*file;
    struct smb_conn_url_mode_query	query;
    struct smb_conn_fd_reply		reply;

    file = malloc(sizeof(struct smb_conn_file) + strlen(url) + 1);
    if (file == NULL){
	errno = ENOMEM;
	return NULL;
    }

    memset(&file->entries, 0, sizeof(LIST));
    file->access_time  = (time_t) 0;
    file->ctx          = ctx;
    file->url          = ((char *) file) + sizeof(struct smb_conn_file);
    file->reopen_cmd   = OPEN;
    file->reopen_flags = O_WRONLY;
    file->srv_fd       = NULL;
    strcpy(file->url, url);

    query.url_offs = sizeof(struct smb_conn_url_mode_query);
    query.mode     = mode;

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    file->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, CREAT,
			&query, sizeof(query),
			&reply, sizeof(reply),
			url, NULL);
    if (error == 0){
	file->srv_fd = reply.srv_fd;
	add_to_list(&ctx->smb_conn_file_list, &file->entries);
    }else{
	free(file);
	file = NULL;
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0) errno = error;
    return file;
}

ssize_t smb_conn_read(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, off_t offset,
			void *buf, size_t bufsize){

    int					error;
    struct smb_conn_file		*file;
    struct smb_conn_rw_query		query;
    struct smb_conn_buf_reply		reply;

    if ((fd == NULL) || (bufsize > ctx->shmem_size)){
	errno = EINVAL;
	return -1;
    }

    /* query.fd will be substituted in smb_conn_process_fd_query() */
    query.offset  = offset;
    query.bufsize = bufsize;

    error = EINVAL;
    reply.bufsize = -1;
    file = (struct smb_conn_file *) fd;

    pthread_mutex_lock(&ctx->mutex);
    if ((file->reopen_cmd == OPEN) && (file->ctx == ctx)){
	ctx->access_time = time(NULL);
	file->access_time = time(NULL);
	error = smb_conn_process_fd_query(
			ctx, READ, file,
			&query.srv_fd,
			&query, sizeof(query),
			&reply, sizeof(reply));
	if ((error == 0) && (reply.bufsize <= (ssize_t) bufsize)){
	    memcpy(buf, ctx->shmem_ptr, reply.bufsize);
	}else{
	    reply.bufsize = -1;
	    if (error == 0) error = EIO;
	}
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0) errno = error;
    return reply.bufsize;
}

ssize_t smb_conn_write(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, off_t offset,
			void *buf, size_t bufsize){

    int					error;
    struct smb_conn_file		*file;
    struct smb_conn_rw_query		query;
    struct smb_conn_buf_reply		reply;

    if ((fd == NULL) || (bufsize > ctx->shmem_size)){
	errno = EINVAL;
	return -1;
    }

    /* query.fd will be substituted in smb_conn_process_fd_query() */
    query.offset  = offset;
    query.bufsize = bufsize;

    error = EINVAL;
    reply.bufsize = -1;
    file = (struct smb_conn_file *) fd;

    pthread_mutex_lock(&ctx->mutex);
    if ((file->reopen_cmd == OPEN) && (file->ctx == ctx)){
	ctx->access_time = time(NULL);
	file->access_time = time(NULL);
	memcpy(ctx->shmem_ptr, buf, bufsize);
	msync(ctx->shmem_ptr, bufsize, MS_SYNC);
	error = smb_conn_process_fd_query(
			ctx, WRITE, file,
			&query.srv_fd,
			&query, sizeof(query),
			&reply, sizeof(reply));
	if ((error != 0) || (reply.bufsize > (ssize_t) bufsize)){
	    reply.bufsize = -1;
	    if (error == 0) error = EIO;
	}
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0) errno = error;
    return reply.bufsize;
}

int smb_conn_close(struct smb_conn_ctx *ctx, smb_conn_fd fd){
    int					error;
    struct smb_conn_file		*file;

    if (fd == NULL){
	errno = EINVAL;
	return -1;
    }

    error = EINVAL;
    file = (struct smb_conn_file *) fd;
    pthread_mutex_lock(&ctx->mutex);
    if ((file->reopen_cmd == OPEN) && (file->ctx == ctx)){
	ctx->access_time = time(NULL);
	if (file->srv_fd != NULL){
	    int				errno_value;
	    struct smb_conn_fd_query	query;

	    query.srv_fd = file->srv_fd;
	    smb_conn_process_query_lowlevel(
			ctx,
			CLOSE,
			&query, sizeof(query),
			&errno_value,
			NULL, 0,
			NULL);
	}
	remove_from_list(&ctx->smb_conn_file_list, &file->entries);
	free(file);
	error = 0;
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0) errno = error;
    return (error != 0) ? -1 : 0;
}

int smb_conn_unlink(struct smb_conn_ctx *ctx, const char *url){
    int					error;
    struct smb_conn_url_query		query;

    query.url_offs = sizeof(struct smb_conn_url_query);

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, UNLINK,
			&query, sizeof(query),
			NULL, 0,
			url, NULL);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    return 0;
}

int smb_conn_rename(struct smb_conn_ctx *ctx, const char *old_url, const char *new_url){
    int					error;
    struct smb_conn_rename_query	query;

    query.old_url_offs = sizeof(struct smb_conn_rename_query);
    query.new_url_offs = sizeof(struct smb_conn_rename_query) + strlen(old_url) + 1;

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, RENAME,
			&query, sizeof(query),
			NULL, 0,
			old_url, new_url, NULL);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    return 0;
}

smb_conn_fd smb_conn_opendir(struct smb_conn_ctx *ctx,
				const char *url){

    int					error;
    struct smb_conn_file		*file;
    struct smb_conn_url_query		query;
    struct smb_conn_fd_reply		reply;

    file = malloc(sizeof(struct smb_conn_file) + strlen(url) + 1);
    if (file == NULL){
	errno = ENOMEM;
	return NULL;
    }

    memset(&file->entries, 0, sizeof(LIST));
    file->access_time  = (time_t) 0;
    file->ctx          = ctx;
    file->url          = ((char *) file) + sizeof(struct smb_conn_file);
    file->reopen_cmd   = OPENDIR;
    file->reopen_flags = 0;
    file->srv_fd       = NULL;
    strcpy(file->url, url);

    query.url_offs = sizeof(struct smb_conn_url_query);

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    file->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, OPENDIR,
			&query, sizeof(query),
			&reply, sizeof(reply),
			url, NULL);
    if (error == 0){
	add_to_list(&ctx->smb_conn_file_list, &file->entries);
	file->srv_fd      = reply.srv_fd;
    }else{
	free(file);
	file = NULL;
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0) errno = error;
    return file;
}

int smb_conn_closedir(struct smb_conn_ctx *ctx, smb_conn_fd fd){
    int					error;
    struct smb_conn_file		*file;

    if (fd == NULL){
	errno = EINVAL;
	return -1;
    }

    error = EINVAL;
    file = (struct smb_conn_file *) fd;
    pthread_mutex_lock(&ctx->mutex);
    if ((file->reopen_cmd == OPENDIR) && (file->ctx == ctx)){
	ctx->access_time = time(NULL);
	if (file->srv_fd != NULL){
	    int				errno_value;
	    struct smb_conn_fd_query	query;

	    query.srv_fd = file->srv_fd;
	    smb_conn_process_query_lowlevel(
			ctx,
			CLOSEDIR,
			&query, sizeof(query),
			&errno_value,
			NULL, 0,
			NULL);
	}
	remove_from_list(&ctx->smb_conn_file_list, &file->entries);
	free(file);
	error = 0;
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0) errno = error;
    return (error != 0) ? -1 : 0;
}

ssize_t smb_conn_readdir(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, void *buf, size_t bufsize){

    int					error;
    struct smb_conn_file		*file;
    struct smb_conn_rw_query		query;
    struct smb_conn_buf_reply		reply;

    if ((fd == NULL) || (bufsize > ctx->shmem_size)){
	errno = EINVAL;
	return -1;
    }

    /* query.fd will be substituted in smb_conn_process_fd_query() */
    query.offset  = (off_t) (-1);
    query.bufsize = bufsize;

    error = EINVAL;
    reply.bufsize = -1;
    file = (struct smb_conn_file *) fd;

    pthread_mutex_lock(&ctx->mutex);
    if ((file->reopen_cmd == OPENDIR) && (file->ctx == ctx)){
	ctx->access_time = time(NULL);
	file->access_time = time(NULL);

	/* we cant reopen directory with non-zero offset, so use               */
	/* file->reopen_flags for indication of zero/non-zero directory offset */
	if (file->reopen_flags == 0){
	    /* =================================== */
	    /* reading from zero offset, use       */
	    /* function with connection recovery   */
	    /* =================================== */
	    error = smb_conn_process_fd_query(
			ctx,
			READDIR,
			file,
			&query.srv_fd,
			&query, sizeof(query),
			&reply, sizeof(reply));
	}else{
	    /* =================================== */
	    /* reading from non-zero offset,       */
	    /* connection recovery is not possible */
	    /* =================================== */

	    int	errno_value = 0;

	    if (file->srv_fd == NULL){
		errno = EIO;
		return -1;
	    }

	    errno_value = 0;
	    query.srv_fd  = file->srv_fd;
	    error = smb_conn_process_query_lowlevel(
			ctx,
			READDIR,
			&query, sizeof(query),
			&errno_value,
			&reply, sizeof(reply),
			NULL);
	    if (error == 0) error = errno_value;
	}
	if ((error == 0) && (reply.bufsize <= (ssize_t) bufsize) &&
	    (reply.bufsize % sizeof(struct smb_conn_dirent_rec) == 0)){
	    memcpy(buf, ctx->shmem_ptr, reply.bufsize);
	    file->reopen_flags++;
	}else{
	    reply.bufsize = -1;
	    if (error == 0) error = EIO;
	}
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0) errno = error;
    return reply.bufsize;
}

int smb_conn_mkdir(struct smb_conn_ctx *ctx, const char *url, mode_t mode){
    int					error;
    struct smb_conn_url_mode_query	query;

    query.url_offs = sizeof(struct smb_conn_url_mode_query);
    query.mode     = mode;

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, MKDIR,
			&query, sizeof(query),
			NULL, 0,
			url, NULL);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    return 0;
}

int smb_conn_rmdir(struct smb_conn_ctx *ctx, const char *url){
    int					error;
    struct smb_conn_url_query		query;

    query.url_offs = sizeof(struct smb_conn_url_query);

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, RMDIR,
			&query, sizeof(query),
			NULL, 0,
			url, NULL);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    return 0;
}

int smb_conn_stat(struct smb_conn_ctx *ctx, const char *url, struct stat *st){
    int					error;
    struct smb_conn_url_query		query;
    struct smb_conn_stat_reply		reply;

    query.url_offs = sizeof(struct smb_conn_url_query);

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, STAT,
			&query, sizeof(query),
			&reply, sizeof(reply),
			url, NULL);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    memcpy(st, &reply.stat, sizeof(struct stat));
    return 0;
}

int smb_conn_fstat(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, struct stat *st){

    int					error;
    struct smb_conn_file		*file;
    struct smb_conn_fd_query		query;
    struct smb_conn_stat_reply		reply;

    if (fd == NULL){
	errno = EINVAL;
	return -1;
    }

    /* query.fd will be substituted in smb_conn_process_fd_query() */

    error = EINVAL;
    file = (struct smb_conn_file *) fd;

    pthread_mutex_lock(&ctx->mutex);
    if ((file->reopen_cmd == OPEN) && (file->ctx == ctx)){
	ctx->access_time = time(NULL);
	file->access_time = time(NULL);
	error = smb_conn_process_fd_query(
			ctx, FSTAT, file,
			&query.srv_fd,
			&query, sizeof(query),
			&reply, sizeof(reply));
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    memcpy(st, &reply.stat, sizeof(struct stat));
    return 0;
}

int smb_conn_ftruncate(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, off_t size){

    int					error;
    struct smb_conn_file		*file;
    struct smb_conn_ftruncate_query	query;

    if (fd == NULL){
	errno = EINVAL;
	return -1;
    }

    /* query.fd will be substituted in smb_conn_process_fd_query() */
    query.offset = size;

    error = EINVAL;
    file = (struct smb_conn_file *) fd;

    pthread_mutex_lock(&ctx->mutex);
    if ((file->reopen_cmd == OPEN) && (file->ctx == ctx)){
	ctx->access_time = time(NULL);
	file->access_time = time(NULL);
	error = smb_conn_process_fd_query(
			ctx, FTRUNCATE, file,
			&query.srv_fd,
			&query, sizeof(query),
			NULL, 0);
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    return 0;
}

int smb_conn_chmod(struct smb_conn_ctx *ctx, const char *url, mode_t mode){
    int					error;
    struct smb_conn_url_mode_query	query;

    query.url_offs = sizeof(struct smb_conn_url_mode_query);
    query.mode     = mode;

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, CHMOD,
			&query, sizeof(query),
			NULL, 0,
			url, NULL);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    return 0;
}

int smb_conn_utimes(struct smb_conn_ctx *ctx, const char *url, struct timeval *tbuf){
    int					error;
    struct smb_conn_utimes_query	query;

    query.url_offs = sizeof(struct smb_conn_utimes_query);
    memcpy(&query.tbuf, tbuf, 2 * sizeof(struct timeval));

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, UTIMES,
			&query, sizeof(query),
			NULL, 0,
			url, NULL);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    return 0;
}

int smb_conn_setxattr(struct smb_conn_ctx *ctx, const char *url, const char *name,
                        const void *value, size_t size, int flags){

    int					error;
    struct smb_conn_setxattr_query	query;

    if (size > ctx->shmem_size){
	errno = EINVAL;
	return -1;
    }

    query.url_offs  = sizeof(struct smb_conn_setxattr_query);
    query.name_offs = sizeof(struct smb_conn_setxattr_query) + strlen(url) + 1;
    query.bufsize   = size;
    query.flags     = flags;

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    memcpy(ctx->shmem_ptr, value, size);
    msync(ctx->shmem_ptr, size, MS_SYNC);
    error = smb_conn_process_query(
			ctx, SETXATTR,
			&query, sizeof(query),
			NULL, 0,
			url, name, NULL);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    return 0;
}

int smb_conn_getxattr(struct smb_conn_ctx *ctx,
			const char *url, const char *name,
			void *value, size_t size){

    int					error;
    struct smb_conn_getxattr_query	query;
    struct smb_conn_buf_reply		reply;

    if (size > ctx->shmem_size){
	errno = EINVAL;
	return -1;
    }

    query.url_offs  = sizeof(struct smb_conn_getxattr_query);
    query.name_offs = sizeof(struct smb_conn_getxattr_query) + strlen(url) + 1;
    query.bufsize   = size;

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, GETXATTR,
			&query, sizeof(query),
			&reply, sizeof(reply),
			url, name, NULL);
    if ((error == 0) &&
	(reply.bufsize > 0) && 
	(reply.bufsize <= (ssize_t) size))
			memcpy(value, ctx->shmem_ptr, reply.bufsize);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    if (((size == 0) && (reply.bufsize > (ssize_t) ctx->shmem_size)) ||
	((size >  0) && (reply.bufsize > (ssize_t) size))){
	errno = EIO;
	return -1;
    }
    return reply.bufsize;
}

int smb_conn_listxattr(struct smb_conn_ctx *ctx,
			const char *url,
			char *list, size_t size){

    int					error;
    struct smb_conn_listxattr_query	query;
    struct smb_conn_buf_reply		reply;

    if (size > ctx->shmem_size){
	errno = EINVAL;
	return -1;
    }

    query.url_offs = sizeof(struct smb_conn_listxattr_query);
    query.bufsize  = size;

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, LISTXATTR,
			&query, sizeof(query),
			&reply, sizeof(reply),
			url, NULL);
    if ((error == 0) &&
	(reply.bufsize > 0) &&
	(reply.bufsize <= (ssize_t) size))
			memcpy(list, ctx->shmem_ptr, reply.bufsize);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    if (((size == 0) && (reply.bufsize > (ssize_t) ctx->shmem_size)) ||
	((size >  0) && (reply.bufsize > (ssize_t) size))){
	errno = EIO;
	return -1;
    }
    return reply.bufsize;
}

int smb_conn_removexattr(struct smb_conn_ctx *ctx,
			const char *url, const char *name){

    int					error;
    struct smb_conn_removexattr_query	query;

    query.url_offs  = sizeof(struct smb_conn_removexattr_query);
    query.name_offs = sizeof(struct smb_conn_removexattr_query) + strlen(url) + 1;

    pthread_mutex_lock(&ctx->mutex);
    ctx->access_time = time(NULL);
    error = smb_conn_process_query(
			ctx, GETXATTR,
			&query, sizeof(query),
			NULL, 0,
			url, name, NULL);
    pthread_mutex_unlock(&ctx->mutex);
    if (error != 0){
	errno = error;
	return -1;
    }
    return 0;
}
