#ifndef __FUNCTION_H__
#define __FUNCTION_H__

#include <fuse/fuse.h>

extern	struct fuse_operations	smb_oper;

int function_set_free_space_size(size_t blocks_count);
int function_set_quiet_flag(int flag);
int function_set_dollar_share_visibility(int flag);
int function_set_hidden_hosts_visibility(int flag);
int function_set_kde_workaround_depth(int depth);

#endif /* __FUNCTION_H__ */
