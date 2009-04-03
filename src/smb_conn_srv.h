#ifndef __SMB_CONN_SRV_H__
#define __SMB_CONN_SRV_H__

#include <sys/types.h>
#include <unistd.h>
#include "smb_conn_proto.h"

enum smb_conn_srv_fd_type{
    SMB_CONN_FILE,
    SMB_CONN_DIR
};

struct smb_conn_srv_fd{
    enum smb_conn_srv_fd_type	type;
    int				fd;
    off_t			offset;
};


void smb_conn_srv_send_reply(struct smb_conn_srv_ctx *ctx,
				enum smb_conn_cmd query_cmd,
				int errno_value,
				void *reply, size_t reply_len);

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

inline const char* smb_conn_srv_get_url_from_query(const void *query, size_t url_offs){
    return  ((const char *) query) + url_offs;
}

#endif /* __SMB_CONN_SRV_H__ */
