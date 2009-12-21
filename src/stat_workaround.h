#ifndef __STAT_WORKAROUND_H__
#define __STAT_WORKAROUND_H__

int stat_workaround_is_name_ignored(const char *path);

int  stat_workaround_add_name(const char *name, int case_sensitive, int depth);
int  stat_workaround_add_exception(const char *name);
void stat_workaround_add_default_entries(void);
void stat_workaround_delete_obsolete(time_t threshold);

int  stat_workaround_enable_default_entries(int new_status);
int  stat_workaround_set_default_depth(int depth);

#endif /* __STAT_WORKAROUND_H__ */
