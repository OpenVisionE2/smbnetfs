#ifndef __RECONFIGURE_H__
#define	__RECONFIGURE_H__

extern const char	*config_file;

void reconfigure_set_config_dir(const char *path);
void set_default_login_and_configdir(void);
int  reconfigure_read_config_file(const char *filename, int startup);

#endif /* __RECONFIGURE_H__ */
