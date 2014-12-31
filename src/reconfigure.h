#ifndef __RECONFIGURE_H__
#define	__RECONFIGURE_H__

#include <stdio.h>

#define CONFIG_OPT_STARTUP	0x01
#define CONFIG_OPT_CMDLINE	0x02
#define CONFIG_OPT_BASEFILE	0x04

extern const char	*smbnetfs_option_list;

void reconfigure_set_default_login_and_configdir(void);
int  reconfigure_analyse_cmdline_option(const char *option, char *value);
int  reconfigure_read_config(int flags);

#endif /* __RECONFIGURE_H__ */
