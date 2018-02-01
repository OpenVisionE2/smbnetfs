#ifndef __SMB_CONN_H__
#define __SMB_CONN_H__

#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include "smb_conn_proto.h"
#include "list.h"

struct smb_conn_ctx{
    LIST			smb_conn_file_list;
    time_t			access_time;
    pthread_mutex_t		mutex;
    char			*shmem_ptr;
    size_t			shmem_size;
    int				conn_fd;
};

struct smb_conn_file{
    LIST			entries;
    time_t			access_time;	// file_handle acess time
    smb_conn_srv_fd		srv_fd;		// smb_conn_srv file descriptor
    struct smb_conn_ctx		*ctx;		// smb_conn context
    char			*url;		// samba url (without "smb:/")
    enum smb_conn_cmd		reopen_cmd;
    int				reopen_flags;
};

typedef struct smb_conn_file*	smb_conn_fd;


int smb_conn_set_max_retry_count(int count);
int smb_conn_set_max_passwd_query_count(int count);
int smb_conn_set_server_reply_timeout(int timeout);

int smb_conn_ctx_init(struct smb_conn_ctx *ctx, size_t shmem_size);
int smb_conn_ctx_destroy(struct smb_conn_ctx *ctx);

smb_conn_fd smb_conn_open(struct smb_conn_ctx *ctx,
			const char *url, int flags, mode_t mode);
smb_conn_fd smb_conn_creat(struct smb_conn_ctx *ctx,
			const char *url, mode_t mode);
ssize_t smb_conn_read(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, off_t offset,
			void *buf, size_t bufsize);
ssize_t smb_conn_write(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, off_t offset,
			const void *buf, size_t bufsize);
int smb_conn_close(struct smb_conn_ctx *ctx,
			smb_conn_fd fd);
int smb_conn_unlink(struct smb_conn_ctx *ctx,
			const char *url);
int smb_conn_rename(struct smb_conn_ctx *ctx,
			const char *old_url, const char *new_url);
smb_conn_fd smb_conn_opendir(struct smb_conn_ctx *ctx,
			const char *url);
int smb_conn_closedir(struct smb_conn_ctx *ctx,
			smb_conn_fd fd);
ssize_t smb_conn_readdir(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, void *buf, size_t bufsize);
int smb_conn_mkdir(struct smb_conn_ctx *ctx,
			const char *url, mode_t mode);
int smb_conn_rmdir(struct smb_conn_ctx *ctx,
			const char *url);
int smb_conn_stat(struct smb_conn_ctx *ctx,
			const char *url, struct stat *st);
int smb_conn_fstat(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, struct stat *st);
int smb_conn_ftruncate(struct smb_conn_ctx *ctx,
			smb_conn_fd fd, off_t size);
int smb_conn_chmod(struct smb_conn_ctx *ctx,
			const char *url, mode_t mode);
int smb_conn_utimes(struct smb_conn_ctx *ctx,
			const char *url, struct timeval *tbuf);
int smb_conn_setxattr(struct smb_conn_ctx *ctx,
			const char *url, const char *name,
			const void *value, size_t size, int flags);
int smb_conn_getxattr(struct smb_conn_ctx *ctx,
			const char *url, const char *name,
			void *value, size_t size);
int smb_conn_listxattr(struct smb_conn_ctx *ctx,
			const char *url,
			char *list, size_t size);
int smb_conn_removexattr(struct smb_conn_ctx *ctx,
			const char *url, const char *name);

#endif /* __SMB_CONN_H__ */
