#ifndef __EVENT_H__
#define __EVENT_H__

#include <fuse/fuse.h>

int  event_set_query_browser_flag(int flag);
int  event_set_time_step(int step);
int  event_set_smb_tree_scan_period(int period);
int  event_set_smb_tree_elements_ttl(int ttl);
int  event_set_config_update_period(int period);

void event_scan_smb_tree(void);

void event_set_event_handler(struct fuse_operations *file_oper);

#endif /* __EVENT_H__ */
