#ifndef __SMB_CONN_PROTO_H__
#define __SMB_CONN_PROTO_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define	COMM_BUF_SIZE		4096
#define MAX_FILENAME_LEN	255

typedef void *		smb_conn_srv_fd;

enum smb_conn_cmd{
    DIE_MSG = -3,
    MESSAGE = -2,
    PASSWORD = -1,
    OPEN = 0,
    CREAT,
    READ,
    WRITE,
    CLOSE,
    UNLINK,
    RENAME,
    OPENDIR,
    CLOSEDIR,
    READDIR,
    MKDIR,
    RMDIR,
    STAT,
    FSTAT,
    FTRUNCATE,
    CHMOD,
    UTIMES,
    SETXATTR,
    GETXATTR,
    LISTXATTR,
    REMOVEXATTR
};

struct smb_conn_query_hdr{
    size_t			query_len;
    enum smb_conn_cmd		query_cmd;
    int				debug_level;
};

struct smb_conn_reply_hdr{
    size_t			reply_len;
    enum smb_conn_cmd		reply_cmd;
    int				errno_value;
};

struct smb_conn_dirent_rec{
    unsigned int		smbc_type;	/* see struct smbc_dirent from libsmbclient.h */
    char			d_name[MAX_FILENAME_LEN + 1];
};

/* ------------------------------- */

/* UNLINK, OPENDIR, RMDIR, STAT, */
struct smb_conn_url_query{
    size_t			url_offs;
};

/* CREAT, CHMOD, MKDIR */
struct smb_conn_url_mode_query{
    size_t			url_offs;
    mode_t			mode;
};

/* OPEN */
struct smb_conn_open_query{
    size_t			url_offs;
    mode_t			mode;
    int				flags;
};

/* RENAME */
struct smb_conn_rename_query{
    size_t			old_url_offs;
    size_t			new_url_offs;
};

/* UTIMES */
struct smb_conn_utimes_query{
    size_t			url_offs;
    struct timeval		tbuf[2];
};

/* CLOSE, CLOSEDIR, FSTAT */
struct smb_conn_fd_query{
    smb_conn_srv_fd		srv_fd;
};

/* FTRUNCATE */
struct smb_conn_ftruncate_query{
    smb_conn_srv_fd		srv_fd;
    off_t			offset;
};

/* READ, WRITE, READDIR */
struct smb_conn_rw_query{
    smb_conn_srv_fd		srv_fd;
    off_t			offset;
    size_t			bufsize;
};

/* LISTXATTR */
struct smb_conn_listxattr_query{
    size_t			url_offs;
    size_t			bufsize;
};

/* GETXATTR */
struct smb_conn_getxattr_query{
    size_t			url_offs;
    size_t			name_offs;
    size_t			bufsize;
};

/* SETXATTR */
struct smb_conn_setxattr_query{
    size_t			url_offs;
    size_t			name_offs;
    size_t			bufsize;
    int				flags;
};

/* REMOVEXATTR */
struct smb_conn_removexattr_query{
    size_t			url_offs;
    size_t			name_offs;
};

/* PASSWORD */
struct smb_conn_passwd{
    size_t			domain_offs;
    size_t			username_offs;
    size_t			password_offs;
};

/* ------------------------------- */

/* CLOSE, FTRUNCATE, UNLINK, RENAME, CLOSEDIR, MKDIR, RMDIR, CHMOD, UTIMES, SETXATTR, REMOVEXATTR */
struct smb_conn_no_reply{
};

/* OPEN, CREAT, OPENDIR */
struct smb_conn_fd_reply{
    smb_conn_srv_fd		srv_fd;
};

/* READ, WRITE, READDIR, GETXATTR, LISTXATTR */
struct smb_conn_buf_reply{
    ssize_t			bufsize;
};

/* STAT, FSTAT */
struct smb_conn_stat_reply{
    struct stat			stat;
};

/* PASSWORD */
struct smb_conn_passwd_req{
    size_t			server_offs;
    size_t			share_offs;
};

/* MESSAGE and DIE_MSG */
struct smb_conn_message_req{
    pid_t			pid;
    int				debug_level;
    size_t			msg_offs;
};


/* ------------------------------- */

struct smb_conn_srv_ctx{
    int				conn_fd;
    char			*shmem_ptr;
    size_t			shmem_size;
    int				timeout;
    int				smb_timeout;
    int				debug_level;
    int				smb_debug_level;
    const char			*local_charset;
    const char			*samba_charset;
};


void smb_conn_srv_listen(struct smb_conn_srv_ctx *ctx);

#endif /* __SMB_CONN_PROTO_H__ */
