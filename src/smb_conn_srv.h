#ifndef __SMB_CONN_SRV_H__
#define __SMB_CONN_SRV_H__

#include "config.h"
#include <sys/types.h>
#include <unistd.h>
#include "smb_conn_proto.h"

/* gcc specific extension. does nothing on other compilers */
#if defined(__GNUC__)
  #define ATTRIB(x) __attribute__ (x)
#else
  #define ATTRIB(x) /* no attributes */
#endif

enum smb_conn_srv_fd_type{
    SMB_CONN_FILE,
    SMB_CONN_DIR
};

struct smb_conn_srv_fd{
    enum smb_conn_srv_fd_type	type;
    int				fd;
    off_t			offset;
};

void smb_conn_srv_debug_print(struct smb_conn_srv_ctx *ctx,
				enum smb_conn_cmd msg_type,
				int errno_value,
				int level, int no_fallback,
				const char *fmt, ...) ATTRIB((format(printf, 6, 7)));

void smb_conn_srv_send_reply(struct smb_conn_srv_ctx *ctx,
				enum smb_conn_cmd query_cmd,
				int errno_value,
				void *reply, size_t reply_len);

int smb_conn_srv_send_msg(struct smb_conn_srv_ctx *ctx,
				enum smb_conn_cmd msg_type,
				int errno_value,
				int level,
				const char *msg);

void smb_conn_srv_open       (struct smb_conn_srv_ctx *ctx, struct smb_conn_open_query        *query, size_t query_len);
void smb_conn_srv_creat      (struct smb_conn_srv_ctx *ctx, struct smb_conn_url_mode_query    *query, size_t query_len);
void smb_conn_srv_read       (struct smb_conn_srv_ctx *ctx, struct smb_conn_rw_query          *query, size_t query_len);
void smb_conn_srv_write      (struct smb_conn_srv_ctx *ctx, struct smb_conn_rw_query          *query, size_t query_len);
void smb_conn_srv_close      (struct smb_conn_srv_ctx *ctx, struct smb_conn_fd_query          *query, size_t query_len);
void smb_conn_srv_unlink     (struct smb_conn_srv_ctx *ctx, struct smb_conn_url_query         *query, size_t query_len);
void smb_conn_srv_rename     (struct smb_conn_srv_ctx *ctx, struct smb_conn_rename_query      *query, size_t query_len);
void smb_conn_srv_opendir    (struct smb_conn_srv_ctx *ctx, struct smb_conn_url_query         *query, size_t query_len);
void smb_conn_srv_closedir   (struct smb_conn_srv_ctx *ctx, struct smb_conn_fd_query          *query, size_t query_len);
void smb_conn_srv_readdir    (struct smb_conn_srv_ctx *ctx, struct smb_conn_rw_query          *query, size_t query_len);
void smb_conn_srv_mkdir      (struct smb_conn_srv_ctx *ctx, struct smb_conn_url_mode_query    *query, size_t query_len);
void smb_conn_srv_rmdir      (struct smb_conn_srv_ctx *ctx, struct smb_conn_url_query         *query, size_t query_len);
void smb_conn_srv_stat       (struct smb_conn_srv_ctx *ctx, struct smb_conn_url_query         *query, size_t query_len);
void smb_conn_srv_fstat      (struct smb_conn_srv_ctx *ctx, struct smb_conn_fd_query          *query, size_t query_len);
void smb_conn_srv_ftruncate  (struct smb_conn_srv_ctx *ctx, struct smb_conn_ftruncate_query   *query, size_t query_len);
void smb_conn_srv_chmod      (struct smb_conn_srv_ctx *ctx, struct smb_conn_url_mode_query    *query, size_t query_len);
void smb_conn_srv_utimes     (struct smb_conn_srv_ctx *ctx, struct smb_conn_utimes_query      *query, size_t query_len);
void smb_conn_srv_setxattr   (struct smb_conn_srv_ctx *ctx, struct smb_conn_setxattr_query    *query, size_t query_len);
void smb_conn_srv_getxattr   (struct smb_conn_srv_ctx *ctx, struct smb_conn_getxattr_query    *query, size_t query_len);
void smb_conn_srv_listxattr  (struct smb_conn_srv_ctx *ctx, struct smb_conn_listxattr_query   *query, size_t query_len);
void smb_conn_srv_removexattr(struct smb_conn_srv_ctx *ctx, struct smb_conn_removexattr_query *query, size_t query_len);

static inline const char* smb_conn_srv_get_url_from_query(const void *query, size_t url_offs){
    return  ((const char *) query) + url_offs;
}

#ifdef PRINTF_DEBUG
  #include <stdio.h>
  #define	DSRVPRINTF(ctx, level_value, fmt, args...)	{ \
								    fprintf(stderr, "srv(%d)->%s: " fmt, getpid(), __FUNCTION__, ## args); fflush(stderr); \
								    smb_conn_srv_debug_print(ctx, MESSAGE, 0, level_value, 1, "srv(%d)->%s: " fmt, getpid(), __FUNCTION__, ## args); \
								}
  #define	DSRVDIEMSG(ctx, errno_value, fmt, args...)	{ \
								    fprintf(stderr, "srv(%d)->%s: " fmt, getpid(), __FUNCTION__, ## args); fflush(stderr); \
								    smb_conn_srv_debug_print(ctx, DIE_MSG, errno_value, 0, 1, "srv(%d)->%s: " fmt, getpid(), __FUNCTION__, ## args); \
								}
#else
  #define	DSRVPRINTF(ctx, level_value, fmt, args...)	smb_conn_srv_debug_print(ctx, MESSAGE, 0, level_value, 0, "srv(%d)->%s: " fmt, getpid(), __FUNCTION__, ## args)
  #define	DSRVDIEMSG(ctx, errno_value, fmt, args...)	smb_conn_srv_debug_print(ctx, DIE_MSG, errno_value, 0, 0, "srv(%d)->%s: " fmt, getpid(), __FUNCTION__, ## args)
#endif

#endif /* __SMB_CONN_SRV_H__ */
