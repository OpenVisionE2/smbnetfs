#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <iconv.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <libsmbclient.h>

#include "charset.h"
#include "smb_conn_proto.h"
#include "smb_conn_srv.h"

#define	DPRINTF(level, fmt, args...)	{ printf("srv(%d)->%s: " fmt, getpid(), __FUNCTION__, ## args); fflush(stdout); }

#ifndef HAVE_LIBSMBCLIENT_3_2
    #define	smbc_setDebug(ctx, level)				\
	((ctx)->debug = (level))
    #define smbc_setOptionUserData(ctx, data)				\
	smbc_option_set((ctx), "user_data", data)
    #define smbc_getOptionUserData(ctx)					\
	smbc_option_get((ctx), "user_data")
    #define	smbc_setOptionUseKerberos(ctx, status)			\
	((ctx)->flags = (status) ?					\
		((ctx)->flags | SMB_CTX_FLAG_USE_KERBEROS) :		\
		((ctx)->flags & ~SMB_CTX_FLAG_USE_KERBEROS))
    #define	smbc_setOptionFallbackAfterKerberos(ctx, status)	\
	((ctx)->flags = (status) ?					\
		((ctx)->flags | SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS) :	\
		((ctx)->flags & ~SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS))
    #define	smbc_setFunctionAuthDataWithContext(ctx, ctx_auth_fn)	\
	((ctx)->callbacks.auth_fn = (ctx_auth_fn##_old))
    #define	smbc_ftruncate(a, b)					\
	(EINVAL)
#endif

void smb_conn_srv_auth_fn(SMBCCTX *ctx,
		const char	*server,
		const char	*share,
		char		*wrkgrp, int wrkgrplen,
		char		*user,   int userlen,
		char		*passwd, int passwdlen){

    static char			buf[COMM_BUF_SIZE];
    static char			charset_buf[CHARSET_BUF_SIZE];
    struct smb_conn_srv_ctx	*srv_ctx;
    int				retval;
    ssize_t			bytes;
    fd_set			readfds, exceptfds;
    struct timeval		tv;
    struct iovec		iov[4];
    struct smb_conn_reply_hdr	reply_header;
    struct smb_conn_passwd_req	reply;
    struct smb_conn_query_hdr	*query_hdr;
    struct smb_conn_passwd	*passwd_hdr;
    const char			*domain, *username, *password;

    if (ctx == NULL) goto error;
    if ((srv_ctx = smbc_getOptionUserData(ctx)) == NULL) goto error;
    if ((server = charset_smb2local_r(server,
		charset_buf, sizeof(charset_buf))) == NULL) goto error;
    if ((server = strdup(server)) == NULL) goto error;
    if ((share  = charset_smb2local_r(share,
		charset_buf, sizeof(charset_buf))) == NULL) goto error;

    iov[0].iov_base = &reply_header;
    iov[0].iov_len  = sizeof(reply_header);
    iov[1].iov_base = &reply;
    iov[1].iov_len  = sizeof(reply);
    iov[2].iov_base = (char *) server;
    iov[2].iov_len  = strlen(server) + 1;
    iov[3].iov_base = (char *) share;
    iov[3].iov_len  = strlen(share) + 1;

    reply_header.reply_len   = iov[0].iov_len + iov[1].iov_len +
			       iov[2].iov_len + iov[3].iov_len;
    reply_header.reply_cmd   = PASSWORD;
    reply_header.errno_value = 0;
    reply.server_offs        = sizeof(reply);
    reply.share_offs         = sizeof(reply) + iov[2].iov_len;

    if (reply_header.reply_len > COMM_BUF_SIZE) goto error;

    /* send password request */
    bytes = writev(srv_ctx->conn_fd, iov, 4);
    if (bytes != (ssize_t) reply_header.reply_len) goto error;

    tv.tv_sec = srv_ctx->timeout;
    tv.tv_usec = 0;

    FD_ZERO(&readfds);
    FD_SET(srv_ctx->conn_fd, &readfds);

    FD_ZERO(&exceptfds);
    FD_SET(srv_ctx->conn_fd, &exceptfds);

    /* wait for password */
    retval = select(srv_ctx->conn_fd + 1, &readfds, NULL, &exceptfds, &tv);
    if ((retval <= 0) || FD_ISSET(srv_ctx->conn_fd, &exceptfds)) goto error;

    /* read password data */
    bytes = read(srv_ctx->conn_fd, buf, COMM_BUF_SIZE);
    if (buf[bytes - 1] != '\0' ) goto error;
    if (bytes < (ssize_t) sizeof(struct smb_conn_query_hdr)) goto error;

    /* check query */
    query_hdr = (struct smb_conn_query_hdr *) buf;
    if (bytes != (ssize_t) query_hdr->query_len) goto error;
    if (query_hdr->query_cmd != PASSWORD) goto error;

    bytes -= sizeof(struct smb_conn_query_hdr);
    if (bytes < (ssize_t) sizeof(struct smb_conn_passwd)) goto error;

    /* process password */
    passwd_hdr = (struct smb_conn_passwd *) (query_hdr + 1);
    if ((passwd_hdr->domain_offs   != sizeof(struct smb_conn_passwd)) ||
	(passwd_hdr->username_offs <= passwd_hdr->domain_offs) ||
	(passwd_hdr->password_offs <= passwd_hdr->username_offs) ||
	((ssize_t) passwd_hdr->password_offs >  bytes - 1)) goto error;
    bytes -= sizeof(struct smb_conn_passwd);

    domain = smb_conn_srv_get_url_from_query(passwd_hdr,
			passwd_hdr->domain_offs);
    username = smb_conn_srv_get_url_from_query(passwd_hdr,
			passwd_hdr->username_offs);
    password = smb_conn_srv_get_url_from_query(passwd_hdr,
			passwd_hdr->password_offs);
    if (bytes != (ssize_t) (strlen(domain) + strlen(username) +
		 strlen(password) + 3)) goto error;

    if (*domain != '\0'){
	strncpy(wrkgrp, domain, wrkgrplen);
	wrkgrp[wrkgrplen - 1] = '\0';
    }
    strncpy(user,   username, userlen); user[userlen - 1] = '\0';
    strncpy(passwd, password, passwdlen); passwd[passwdlen - 1] = '\0';
    DPRINTF(0, "url=smb://%s/%s, grp=%s, user=%s, passwd=%s\n",
			server, share, wrkgrp, user, "********");
    free((char *) server);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

#ifndef HAVE_LIBSMBCLIENT_3_2
void smb_conn_srv_auth_fn_old(
		const char	*server,
		const char	*share,
		char		*wrkgrp, int wrkgrplen,
		char		*user,   int userlen,
		char		*passwd, int passwdlen){

	smb_conn_srv_auth_fn(smbc_set_context(NULL),
				server, share,
				wrkgrp, wrkgrplen,
				user, userlen,
				passwd, passwdlen);
}
#endif

void smb_conn_srv_samba_init(struct smb_conn_srv_ctx *srv_ctx){
    SMBCCTX	*ctx;

    if ((ctx = smbc_new_context()) == NULL) goto error;
    if (smbc_init_context(ctx) == NULL) goto error;
    smbc_setDebug(ctx, srv_ctx->smb_debug_level);
    smbc_setFunctionAuthDataWithContext(ctx, smb_conn_srv_auth_fn);
    smbc_setOptionUserData(ctx, srv_ctx);
#if defined(SMB_CTX_FLAG_USE_KERBEROS) && defined(SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS)
    smbc_setOptionUseKerberos(ctx, 1);
    smbc_setOptionFallbackAfterKerberos(ctx, 1);
#endif
    smbc_set_context(ctx);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_listen(struct smb_conn_srv_ctx *ctx){

    static char				buf[COMM_BUF_SIZE];

    if (charset_init(ctx->local_charset,ctx->samba_charset) != 0)
	exit(EXIT_FAILURE);
    smb_conn_srv_samba_init(ctx);
    while(1){
	fd_set				readfds, exceptfds;
	struct timeval			tv;
	int				retval;
	void				*query;
	ssize_t				query_len;
	struct smb_conn_query_hdr	*query_hdr;

	tv.tv_sec = ctx->timeout;
	tv.tv_usec = 0;

	FD_ZERO(&readfds);
	FD_SET(ctx->conn_fd, &readfds);

	FD_ZERO(&exceptfds);
	FD_SET(ctx->conn_fd, &exceptfds);

	/* wait for query */
	retval = select(ctx->conn_fd + 1, &readfds, NULL, &exceptfds, &tv);
	if ((retval < 0)) goto error;
	if (retval == 0){
	    /* we treat timeout as signal to exit, */
	    /* no cleanup should be required       */
	    exit(EXIT_SUCCESS);
	}
	if (FD_ISSET(ctx->conn_fd, &exceptfds)) goto error;

	/* read query */
	query_len = read(ctx->conn_fd, buf, COMM_BUF_SIZE);
	if (query_len < (ssize_t) sizeof(struct smb_conn_query_hdr)) goto error;

	/* check query */
	query_hdr = (struct smb_conn_query_hdr *) buf;
	if (query_len != (ssize_t) query_hdr->query_len) goto error;

	/* process query */
	errno = 0;
	query = (void*) (query_hdr + 1);
	query_len -= sizeof(struct smb_conn_query_hdr);
	DPRINTF(0, "process query=%d, query_len=%d\n",
			query_hdr->query_cmd, (int) query_len);
	switch(query_hdr->query_cmd){
	    case OPEN:
		smb_conn_srv_open(ctx, query, query_len);
		break;
	    case CREAT:
		smb_conn_srv_creat(ctx, query, query_len);
		break;
	    case READ:
		smb_conn_srv_read(ctx, query, query_len);
		break;
	    case WRITE:
		smb_conn_srv_write(ctx, query, query_len);
		break;
	    case CLOSE:
		smb_conn_srv_close(ctx, query, query_len);
		break;
	    case UNLINK:
		smb_conn_srv_unlink(ctx, query, query_len);
		break;
	    case RENAME:
		smb_conn_srv_rename(ctx, query, query_len);
		break;
	    case OPENDIR:
		smb_conn_srv_opendir(ctx, query, query_len);
		break;
	    case CLOSEDIR:
		smb_conn_srv_closedir(ctx, query, query_len);
		break;
	    case READDIR:
		smb_conn_srv_readdir(ctx, query, query_len);
		break;
	    case MKDIR:
		smb_conn_srv_mkdir(ctx, query, query_len);
		break;
	    case RMDIR:
		smb_conn_srv_rmdir(ctx, query, query_len);
		break;
	    case STAT:
		smb_conn_srv_stat(ctx, query, query_len);
		break;
	    case FSTAT:
		smb_conn_srv_fstat(ctx, query, query_len);
		break;
	    case FTRUNCATE:
		smb_conn_srv_ftruncate(ctx, query, query_len);
		break;
	    case CHMOD:
		smb_conn_srv_chmod(ctx, query, query_len);
		break;
	    case UTIMES:
		smb_conn_srv_utimes(ctx, query, query_len);
		break;
	    case SETXATTR:
		smb_conn_srv_setxattr(ctx, query, query_len);
		break;
	    case GETXATTR:
		smb_conn_srv_getxattr(ctx, query, query_len);
		break;
	    case LISTXATTR:
		smb_conn_srv_listxattr(ctx, query, query_len);
		break;
	    case REMOVEXATTR:
		smb_conn_srv_removexattr(ctx, query, query_len);
		break;
	    default:
		/* unknown qery ? */
		goto error;
	}
    }

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
};

void smb_conn_srv_send_reply(struct smb_conn_srv_ctx *ctx,
				enum smb_conn_cmd reply_cmd,
				int errno_value,
				void *reply, size_t reply_len){

    int				iov_cnt;
    struct iovec		iov[2];
    struct smb_conn_reply_hdr	header;

    if (errno_value == 0){
	if (((reply == NULL) && (reply_len != 0)) ||
	    ((reply != NULL) && (reply_len == 0))) goto error;
    }else{
	if ((reply != NULL) || (reply_len != 0)) goto error;
    }

    iov_cnt = 1;
    header.reply_cmd   = reply_cmd;
    header.errno_value = errno_value;
    header.reply_len   = sizeof(struct smb_conn_reply_hdr);

    iov[0].iov_base = &header;
    iov[0].iov_len  = sizeof(struct smb_conn_reply_hdr);

    if (reply_len > 0){
	iov[iov_cnt].iov_base = reply;
	iov[iov_cnt].iov_len  = reply_len;
	header.reply_len += iov[iov_cnt].iov_len;
	iov_cnt++;
    }

    if (header.reply_len > COMM_BUF_SIZE) goto error;
    if (writev(ctx->conn_fd, iov, iov_cnt) != (ssize_t) header.reply_len)
	goto error;

    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_open(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_open_query *query, size_t query_len){

    const char			*url;
    struct smb_conn_srv_fd	*state;
    struct smb_conn_fd_reply	reply;

    if (query_len <= sizeof(struct smb_conn_open_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if (query->url_offs != sizeof(struct smb_conn_open_query)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_open_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if ((state = malloc(sizeof(struct smb_conn_srv_fd))) == NULL) goto error;

    state->type = SMB_CONN_FILE;
    state->offset = (off_t) (-1);
    state->fd = smbc_open(url, query->flags, query->mode);

    if (state->fd < 0){
	int	error = errno;

	free(state);
	switch(error){
	    case EACCES:
	    case EEXIST:
	    case EFAULT:
	    case EFBIG:
	    case EINTR:
	    case EISDIR:
	    case ELOOP:
	    case EMFILE:
	    case ENAMETOOLONG:
	    case ENFILE:
	    case ENODEV:
	    case ENOENT:
	    case ENOSPC:
	    case ENOTDIR:
	    case EPERM:
	    case EROFS:
	    case ETXTBSY:
		smb_conn_srv_send_reply(ctx, OPEN, error, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    reply.srv_fd = state;
    smb_conn_srv_send_reply(ctx, OPEN, 0, &reply, sizeof(reply));
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_creat(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_url_mode_query *query, size_t query_len){

    const char			*url;
    struct smb_conn_srv_fd	*state;
    struct smb_conn_fd_reply	reply;

    if (query_len <= sizeof(struct smb_conn_url_mode_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if (query->url_offs != sizeof(struct smb_conn_url_mode_query)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_url_mode_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if ((state = malloc(sizeof(struct smb_conn_srv_fd))) == NULL) goto error;

    state->type = SMB_CONN_FILE;
    state->offset = (off_t) (-1);
    state->fd = smbc_creat(url, query->mode);

    if (state->fd < 0){
	int	error = errno;

	free(state);
	switch(error){
	    case EACCES:
	    case EEXIST:
	    case EFAULT:
	    case EFBIG:
	    case EINTR:
	    case EISDIR:
	    case ELOOP:
	    case EMFILE:
	    case ENAMETOOLONG:
	    case ENFILE:
	    case ENODEV:
	    case ENOENT:
	    case ENOSPC:
	    case ENOTDIR:
	    case EPERM:
	    case EROFS:
	    case ETXTBSY:
		smb_conn_srv_send_reply(ctx, CREAT, error, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    reply.srv_fd = state;
    smb_conn_srv_send_reply(ctx, CREAT, 0, &reply, sizeof(reply));
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_read(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_rw_query *query, size_t query_len){

    struct smb_conn_srv_fd	*state;
    struct smb_conn_buf_reply	reply;

    if (query_len != sizeof(struct smb_conn_rw_query)) goto error;
    if ((query->offset == (off_t) (-1)) ||
	(query->bufsize > ctx->shmem_size) ||
	(query->srv_fd == NULL)) goto error;

    state = query->srv_fd;
    if ((state->fd < 0) || (state->type != SMB_CONN_FILE)) goto error;

    if (state->offset != query->offset){
	off_t	pos;

	pos = smbc_lseek(state->fd, query->offset, SEEK_SET);
	if (pos != query->offset) goto error;
	state->offset = query->offset;
    }

    reply.bufsize = smbc_read(state->fd, ctx->shmem_ptr, query->bufsize);
    if (reply.bufsize < 0){
	switch(errno){
	    case EAGAIN:
	    case EINTR:
	    case EISDIR:
		state->offset = (off_t) (-1);
		smb_conn_srv_send_reply(ctx, READ, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    state->offset += reply.bufsize;
    msync(ctx->shmem_ptr, reply.bufsize, MS_SYNC);
    smb_conn_srv_send_reply(ctx, READ, 0, &reply, sizeof(reply));
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_write(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_rw_query *query, size_t query_len){

    struct smb_conn_srv_fd	*state;
    struct smb_conn_buf_reply	reply;

    if (query_len != sizeof(struct smb_conn_rw_query)) goto error;
    if ((query->offset == (off_t) (-1)) ||
	(query->bufsize > ctx->shmem_size) ||
	(query->srv_fd == NULL)) goto error;

    state = query->srv_fd;
    if ((state->fd < 0) || (state->type != SMB_CONN_FILE)) goto error;

    if (state->offset != query->offset){
	off_t	pos;

	pos = smbc_lseek(state->fd, query->offset, SEEK_SET);
	if (pos != query->offset) goto error;
	state->offset = query->offset;
    }

    reply.bufsize = smbc_write(state->fd, ctx->shmem_ptr, query->bufsize);
    if (reply.bufsize < 0){
	switch(errno){
	    case EAGAIN:
	    case EINTR:
	    case EINVAL:
	    case EIO:
	    case ENOSPC:
	    case EISDIR:
		state->offset = (off_t) (-1);
		smb_conn_srv_send_reply(ctx, WRITE, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    state->offset += reply.bufsize;
    smb_conn_srv_send_reply(ctx, WRITE, 0, &reply, sizeof(reply));
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_close(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_fd_query *query, size_t query_len){

    struct smb_conn_srv_fd	*state;

    if (query_len != sizeof(struct smb_conn_fd_query)) goto error;
    if (query->srv_fd == NULL) goto error;

    state = query->srv_fd;
    if ((state->fd < 0) || (state->type != SMB_CONN_FILE)) goto error;

    if (smbc_close(state->fd) < 0){
	switch(errno){
	    case EINTR:
		smb_conn_srv_send_reply(ctx, CLOSE, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    free(state);
    smb_conn_srv_send_reply(ctx, CLOSE, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_unlink(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_url_query *query, size_t query_len){

    const char			*url;
    struct stat			st;

    if (query_len <= sizeof(struct smb_conn_url_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if (query->url_offs != sizeof(struct smb_conn_url_query)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_url_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_stat(url, &st) < 0){
	switch(errno){
	    case EACCES:
		/* try to continue */
		break;
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOTDIR:
		smb_conn_srv_send_reply(ctx, UNLINK, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }else{
	if (!S_ISREG(st.st_mode)){
	    smb_conn_srv_send_reply(ctx, UNLINK, EISDIR, NULL, 0);
	    return;
	}
	if ((st.st_mode & S_IWOTH) != S_IWOTH){
	    if (smbc_chmod(url, st.st_mode | S_IWOTH) < 0){
		switch(errno){
		    case EACCES:
		    case EIO:
		    case EPERM:
			/* try to continue */
			break;
		    case ELOOP:
		    case ENAMETOOLONG:
		    case ENOENT:
		    case ENOTDIR:
		    case EROFS:
			smb_conn_srv_send_reply(ctx, UNLINK, errno, NULL, 0);
			return;
		    default:
			goto error;
		};
	    }
	}
    }

    if (smbc_unlink(url) < 0){
	switch(errno){
	    case EACCES:
	    case EBUSY:
	    case EIO:
	    case EISDIR:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOTDIR:
	    case EPERM:
	    case EROFS:
		smb_conn_srv_send_reply(ctx, UNLINK, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, UNLINK, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_rename(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_rename_query *query, size_t query_len){

    int				error;
    int				count;
    const char			*old_url;
    const char			*new_url;
    const char			*pos;
    struct stat			old_st;
    struct stat			new_st;

    if (query_len <= sizeof(struct smb_conn_rename_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if ((query->old_url_offs != sizeof(struct smb_conn_rename_query)) ||
	(query->new_url_offs <= query->old_url_offs) ||
	(query->new_url_offs >= query_len - 1)) goto error;

    old_url = smb_conn_srv_get_url_from_query(query, query->old_url_offs);
    new_url = smb_conn_srv_get_url_from_query(query, query->new_url_offs);

    if (new_url != old_url + strlen(old_url) + 1) goto error;
    if (query_len != sizeof(struct smb_conn_rename_query) +
			strlen(old_url) + strlen(new_url) + 2) goto error;
    if ((new_url = charset_local2smb(new_url)) == NULL) goto error;
    if ((new_url = strdup(new_url)) == NULL) goto error;
    if ((old_url = charset_local2smb(old_url)) == NULL) goto error;

    /*
     * old_url and new_url should point to the same samba share
     * try find the position of 4-th '/' in "smb://server/share/path" and
     * compare samba resource names
     */
    for(count = 0, pos = old_url; *pos; pos++)
	if ((*pos == '/') && (++count == 4)) break;
    if (*pos != '/'){
	smb_conn_srv_send_reply(ctx, RENAME, EXDEV, NULL, 0);
	free((char*)new_url);
	return;
    }
    if (strncasecmp(old_url, new_url, pos - old_url + 1) != 0){
	smb_conn_srv_send_reply(ctx, RENAME, EXDEV, NULL, 0);
	free((char*)new_url);
	return;
    }

    error = 0;

    /* check the presence of old_url */
    if (smbc_stat(old_url, &old_st) < 0){
	switch(errno){
	    case EACCES:
		/* try to continue */
		goto rename;
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOTDIR:
		smb_conn_srv_send_reply(ctx, RENAME, errno, NULL, 0);
		free((char*)new_url);
		return;
	    default:
		goto error;
	}
    }

    /* check the presence of new_url, delete new_url if necessary */
    if (smbc_stat(new_url, &new_st) < 0){
	switch(errno){
	    case EACCES:
		/* try to continue */
		goto rename;
	    case ENOENT:
		/* OK, new path does not exist */
		goto rename;
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOTDIR:
		smb_conn_srv_send_reply(ctx, RENAME, errno, NULL, 0);
		free((char*)new_url);
		return;
	    default:
		goto error;
	}
    }

    /* rename dir to file is not possible */
    if (S_ISDIR(old_st.st_mode) && S_ISREG(new_st.st_mode)){
	smb_conn_srv_send_reply(ctx, RENAME, ENOTDIR, NULL, 0);
	free((char*)new_url);
	return;
    }

    /* rename dir to dir, if yes, try to delete new_url directory first */
    if (S_ISDIR(old_st.st_mode) && S_ISDIR(new_st.st_mode)){
	if (smbc_rmdir(new_url) != 0){
	    switch(errno){
		case EACCES:
		case EBUSY:
		case EPERM:
		    /* try to continue */
		    goto rename;
		case EINVAL:
		case ELOOP:
		case ENAMETOOLONG:
		case ENOENT:
		case ENOTDIR:
		case ENOTEMPTY:
		case EROFS:
		    smb_conn_srv_send_reply(ctx, RENAME, errno, NULL, 0);
		    free((char*)new_url);
		    return;
		default:
		    goto error;
	    }
	}
	goto rename;
    }

    /* rename file to file, if yes, try to delete new_url file first */
    if (S_ISREG(old_st.st_mode) && S_ISREG(new_st.st_mode)){
	if ((new_st.st_mode & S_IWOTH) != S_IWOTH){
	    if (smbc_chmod(new_url, new_st.st_mode | S_IWOTH) < 0){
		switch(errno){
		    case EACCES:
		    case EIO:
		    case EPERM:
		    case ENOENT:
		    case ENOTDIR:
			/* try to continue */
			break;
		    case ELOOP:
		    case ENAMETOOLONG:
		    case EROFS:
			smb_conn_srv_send_reply(ctx, RENAME, errno, NULL, 0);
			free((char*)new_url);
			return;
		    default:
			goto error;
		};
	    }
	}
	if (smbc_unlink(new_url) < 0){
	    switch(errno){
		case EACCES:
		case EBUSY:
		case EIO:
		case EISDIR:
		case ENOENT:
		case ENOTDIR:
		case EPERM:
		    /* try to continue */
		    break;
		case ELOOP:
		case ENAMETOOLONG:
		case EROFS:
		    smb_conn_srv_send_reply(ctx, UNLINK, errno, NULL, 0);
		    free((char*)new_url);
		    return;
		default:
		    goto error;
	    }
	}
    }

  rename:

    if (smbc_rename(old_url, new_url) < 0){
	switch(errno){
	    case EACCES:
	    case EBUSY:
	    case EINVAL:
	    case EISDIR:
	    case ELOOP:
	    case EMLINK:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOSPC:
	    case ENOTDIR:
	    case ENOTEMPTY:
	    case EEXIST:
	    case EPERM:
	    case EROFS:
	    case EXDEV:
		smb_conn_srv_send_reply(ctx, RENAME, errno, NULL, 0);
		free((char*)new_url);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, RENAME, 0, NULL, 0);
    free((char*)new_url);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_opendir(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_url_query *query, size_t query_len){

    const char			*url;
    struct smb_conn_srv_fd	*state;
    struct smb_conn_fd_reply	reply;

    if (query_len <= sizeof(struct smb_conn_url_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if (query->url_offs != sizeof(struct smb_conn_url_query)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_url_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if ((state = malloc(sizeof(struct smb_conn_srv_fd))) == NULL) goto error;

    state->type = SMB_CONN_DIR;
    state->offset = (off_t) (-1);
    state->fd = smbc_opendir(url);

    if (state->fd < 0){
	int	error = errno;

	free(state);
	switch(error){
	    case EACCES:
	    case EMFILE:
	    case ENOENT:
	    case ENOTDIR:
	    case EPERM:
	    case ENODEV:
		smb_conn_srv_send_reply(ctx, OPENDIR, error, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    reply.srv_fd = state;
    smb_conn_srv_send_reply(ctx, OPENDIR, 0, &reply, sizeof(reply));
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_closedir(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_fd_query *query, size_t query_len){

    struct smb_conn_srv_fd		*state;

    if (query_len != sizeof(struct smb_conn_fd_query)) goto error;
    if (query->srv_fd == NULL) goto error;

    state = query->srv_fd;
    if ((state->fd < 0) || (state->type != SMB_CONN_DIR)) goto error;

    if (smbc_closedir(state->fd) < 0) goto error;

    free(state);
    smb_conn_srv_send_reply(ctx, CLOSEDIR, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_readdir(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_rw_query *query, size_t query_len){

    const char			*name;
    struct smbc_dirent		*dirent;
    struct smb_conn_dirent_rec	*pos;
    struct smb_conn_srv_fd	*state;
    struct smb_conn_buf_reply	reply;


    if (query_len != sizeof(struct smb_conn_rw_query)) goto error;
    if ((query->offset != (off_t) (-1)) ||
	(query->bufsize > ctx->shmem_size) ||
	(query->srv_fd == NULL)) goto error;

    state = query->srv_fd;
    if ((state->fd < 0) ||
	(state->type != SMB_CONN_DIR) ||
	(state->offset != (off_t) (-1))) goto error;

    pos = (struct smb_conn_dirent_rec *) ctx->shmem_ptr;
    while((char *) (pos + 1) < ctx->shmem_ptr + query->bufsize){
	if ((dirent = smbc_readdir(state->fd)) == NULL) break;
	if (strcmp(dirent->name, "") == 0) continue;
	if (strcmp(dirent->name, ".") == 0) continue;
	if (strcmp(dirent->name, "..") == 0) continue;

	name = charset_smb2local(dirent->name);
	if (name == NULL){
	    /* the name can not be converted :-( */
	    continue;
	}
	if (strlen(name) + 1 > sizeof(pos->d_name)){
	    /* the name does not fit to struct smb_dirent_rec :-( */
	    continue;
	}

	pos->smbc_type = dirent->smbc_type;
	strcpy(pos->d_name, name);
	pos++;
    }

    reply.bufsize = ((char *) pos) - ctx->shmem_ptr;
    msync(ctx->shmem_ptr, reply.bufsize, MS_SYNC);
    smb_conn_srv_send_reply(ctx, READDIR, 0, &reply, sizeof(reply));
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_mkdir(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_url_mode_query *query, size_t query_len){

    const char			*url;

    if (query_len <= sizeof(struct smb_conn_url_mode_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if (query->url_offs != sizeof(struct smb_conn_url_mode_query)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_url_mode_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_mkdir(url, query->mode) < 0){
	switch(errno){
	    case EACCES:
	    case EEXIST:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOSPC:
	    case ENOTDIR:
	    case EPERM:
	    case EROFS:
		smb_conn_srv_send_reply(ctx, MKDIR, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, MKDIR, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_rmdir(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_url_query *query, size_t query_len){

    const char			*url;

    if (query_len <= sizeof(struct smb_conn_url_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if (query->url_offs != sizeof(struct smb_conn_url_query)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_url_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_rmdir(url) < 0){
	switch(errno){
	    case EACCES:
	    case EBUSY:
	    case EINVAL:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOTDIR:
	    case ENOTEMPTY:
	    case EPERM:
	    case EROFS:
		smb_conn_srv_send_reply(ctx, RMDIR, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, RMDIR, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_stat(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_url_query *query, size_t query_len){

    const char			*url;
    struct smb_conn_stat_reply	reply;

    if (query_len <= sizeof(struct smb_conn_url_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if (query->url_offs != sizeof(struct smb_conn_url_query)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_url_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_stat(url, &reply.stat) < 0){
	switch(errno){
	    case EACCES:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOTDIR:
		smb_conn_srv_send_reply(ctx, STAT, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, STAT, 0, &reply, sizeof(reply));
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_fstat(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_fd_query *query, size_t query_len){

    struct smb_conn_srv_fd	*state;
    struct smb_conn_stat_reply	reply;

    if (query_len != sizeof(struct smb_conn_fd_query)) goto error;
    if (query->srv_fd == NULL) goto error;

    state = query->srv_fd;
    if ((state->fd < 0) || (state->type != SMB_CONN_FILE)) goto error;

    if (smbc_fstat(state->fd, &reply.stat) < 0){
	switch(errno){
	    case EACCES:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOTDIR:
		state->offset = (off_t) (-1);
		smb_conn_srv_send_reply(ctx, FSTAT, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, FSTAT, 0, &reply, sizeof(reply));
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_ftruncate(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_ftruncate_query *query, size_t query_len){

    struct smb_conn_srv_fd	*state;

    if (query_len != sizeof(struct smb_conn_ftruncate_query)) goto error;
    if ((query->offset == (off_t) (-1)) || (query->srv_fd == NULL)) goto error;

    state = query->srv_fd;
    if ((state->fd < 0) || (state->type != SMB_CONN_FILE)) goto error;

    if (smbc_ftruncate(state->fd, query->offset) < 0){
	switch(errno){
	    case EACCES:
	    case EINTR:
	    case EINVAL:
	    case EIO:
	    case EISDIR:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOTDIR:
	    case EPERM:
	    case EROFS:
	    case ETXTBSY:
		state->offset = (off_t) (-1);
		smb_conn_srv_send_reply(ctx, FTRUNCATE, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    state->offset = (off_t) (-1);
    smb_conn_srv_send_reply(ctx, FTRUNCATE, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_chmod(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_url_mode_query *query, size_t query_len){

    const char			*url;

    if (query_len <= sizeof(struct smb_conn_url_mode_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if (query->url_offs != sizeof(struct smb_conn_url_mode_query)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_url_mode_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_chmod(url, query->mode) < 0){
	switch(errno){
	    case EACCES:
	    case EIO:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOTDIR:
	    case EPERM:
	    case EROFS:
		smb_conn_srv_send_reply(ctx, CHMOD, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, CHMOD, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_utimes(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_utimes_query *query, size_t query_len){

    const char			*url;

    if (query_len <= sizeof(struct smb_conn_utimes_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if (query->url_offs != sizeof(struct smb_conn_utimes_query)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_utimes_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_utimes(url, &query->tbuf) < 0){
	switch(errno){
	    case EACCES:
	    case ENOENT:
	    case EPERM:
	    case EROFS:
		smb_conn_srv_send_reply(ctx, UTIMES, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, UTIMES, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_setxattr(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_setxattr_query *query, size_t query_len){

    const char			*url;
    const char			*name;

    if (query_len <= sizeof(struct smb_conn_setxattr_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if ((query->url_offs != sizeof(struct smb_conn_setxattr_query)) ||
	(query->name_offs <= query->url_offs) ||
	(query->name_offs >= query_len - 1)) goto error;

    url  = smb_conn_srv_get_url_from_query(query, query->url_offs);
    name = smb_conn_srv_get_url_from_query(query, query->name_offs);

    if (name != url + strlen(url) + 1) goto error;
    if (query_len != sizeof(struct smb_conn_setxattr_query) +
			strlen(url) + strlen(name) + 2) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_setxattr(url, name, ctx->shmem_ptr, query->bufsize, query->flags) < 0){
	switch(errno){
	    case EEXIST:
	    case ENOATTR:
	    case EPERM:
	    case ENOTSUP:
	    case ENOSPC:
	    case EDQUOT:

	    case EACCES:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOTDIR:
		smb_conn_srv_send_reply(ctx, SETXATTR, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, SETXATTR, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_getxattr(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_getxattr_query *query, size_t query_len){

    const char			*url;
    const char			*name;

    if (query_len <= sizeof(struct smb_conn_getxattr_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if ((query->url_offs != sizeof(struct smb_conn_getxattr_query)) ||
	(query->name_offs <= query->url_offs) ||
	(query->name_offs >= query_len - 1)) goto error;

    url  = smb_conn_srv_get_url_from_query(query, query->url_offs);
    name = smb_conn_srv_get_url_from_query(query, query->name_offs);

    if (name != url + strlen(url) + 1) goto error;
    if (query_len != sizeof(struct smb_conn_getxattr_query) +
			strlen(url) + strlen(name) + 2) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_getxattr(url, name, ctx->shmem_ptr, query->bufsize) < 0){
	switch(errno){
	    case EEXIST:
	    case ENOATTR:
	    case EPERM:
	    case ENOTSUP:
	    case ERANGE:

	    case EACCES:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOTDIR:
		smb_conn_srv_send_reply(ctx, GETXATTR, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    msync(ctx->shmem_ptr, query->bufsize, MS_SYNC);
    smb_conn_srv_send_reply(ctx, GETXATTR, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_listxattr(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_listxattr_query *query, size_t query_len){

    const char			*url;

    if (query_len <= sizeof(struct smb_conn_listxattr_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if ((query->url_offs != sizeof(struct smb_conn_listxattr_query)) ||
	(query->bufsize > ctx->shmem_size)) goto error;

    url = smb_conn_srv_get_url_from_query(query, query->url_offs);
    if (query_len != sizeof(struct smb_conn_listxattr_query) + strlen(url) + 1) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_listxattr(url, ctx->shmem_ptr, query->bufsize) < 0){
	switch(errno){
	    case EPERM:
	    case ENOTSUP:
	    case ERANGE:

	    case EACCES:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOENT:
	    case ENOTDIR:
		smb_conn_srv_send_reply(ctx, LISTXATTR, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    msync(ctx->shmem_ptr, query->bufsize, MS_SYNC);
    smb_conn_srv_send_reply(ctx, LISTXATTR, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void smb_conn_srv_removexattr(struct smb_conn_srv_ctx *ctx,
			struct smb_conn_removexattr_query *query, size_t query_len){

    const char			*url;
    const char			*name;

    if (query_len <= sizeof(struct smb_conn_removexattr_query)) goto error;
    if ( *(((char *) query) + query_len - 1) != '\0' ) goto error;
    if ((query->url_offs != sizeof(struct smb_conn_getxattr_query)) ||
	(query->name_offs <= query->url_offs) ||
	(query->name_offs >= query_len - 1)) goto error;

    url  = smb_conn_srv_get_url_from_query(query, query->url_offs);
    name = smb_conn_srv_get_url_from_query(query, query->name_offs);

    if (name != url + strlen(url) + 1) goto error;
    if (query_len != sizeof(struct smb_conn_getxattr_query) +
			strlen(url) + strlen(name) + 2) goto error;
    if ((url = charset_local2smb(url)) == NULL) goto error;

    if (smbc_removexattr(url, name) < 0){
	switch(errno){
	    case ENOATTR:
	    case EPERM:
	    case ENOTSUP:

	    case EACCES:
	    case ELOOP:
	    case ENAMETOOLONG:
	    case ENOTDIR:
		smb_conn_srv_send_reply(ctx, REMOVEXATTR, errno, NULL, 0);
		return;
	    default:
		goto error;
	}
    }

    smb_conn_srv_send_reply(ctx, REMOVEXATTR, 0, NULL, 0);
    return;

  error:
    DPRINTF(0, "errno=%d, %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}
