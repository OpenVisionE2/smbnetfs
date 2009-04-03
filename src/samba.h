#ifndef __SAMBA_H__
#define __SAMBA_H__

#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include "smb_conn.h"

typedef smb_conn_fd	samba_fd;

int      samba_init(size_t max_rw_block_size);
int      samba_set_max_ctx_count(int count);
void     samba_allocate_ctxs(void);
void     samba_destroy_unused_ctxs(void);

samba_fd samba_open       (const char *url, int flags, mode_t mode);
samba_fd samba_creat      (const char *url, mode_t mode);
ssize_t  samba_read       (samba_fd fd, off_t offset, void *buf, size_t bufsize);
ssize_t  samba_write      (samba_fd fd, off_t offset, void *buf, size_t bufsize);
int      samba_close      (samba_fd fd);
int      samba_unlink     (const char *url);
int      samba_rename     (const char *old_url, const char *new_url);
samba_fd samba_opendir    (const char *url);
int      samba_closedir   (samba_fd fd);
ssize_t  samba_readdir    (samba_fd fd, void *buf, size_t bufsize);
int      samba_mkdir      (const char *url, mode_t mode);
int      samba_rmdir      (const char *url);
int      samba_stat       (const char *url, struct stat *st);
int      samba_fstat      (samba_fd fd, struct stat *st);
int      samba_ftruncate  (samba_fd fd, off_t size);
int      samba_chmod      (const char *url, mode_t mode);
int      samba_utimes     (const char *url, struct timeval *tbuf);
int      samba_setxattr   (const char *url, const char *name,
				const void *value, size_t size, int flags);
int      samba_getxattr   (const char *url, const char *name,
				void *value, size_t size);
int      samba_listxattr  (const char *url, char *list, size_t size);
int      samba_removexattr(const char *url, const char *name);

#endif /* __SAMBA_H__ */
