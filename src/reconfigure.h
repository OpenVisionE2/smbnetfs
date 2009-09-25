#ifndef __RECONFIGURE_H__
#define	__RECONFIGURE_H__

#include <stdio.h>

extern int		special_config;
extern const char	*smbnetfs_option_list;

void reconfigure_set_default_login_and_configdir(void);
int  reconfigure_analyse_cmdline_option(const char *option, char *value);
int  reconfigure_read_config(int startup);

#endif /* __RECONFIGURE_H__ */
