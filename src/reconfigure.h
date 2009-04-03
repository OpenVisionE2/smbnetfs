#ifndef __RECONFIGURE_H__
#define	__RECONFIGURE_H__

extern const char	*config_dir_posfix;
extern const char	config_file[1024];

void reconfigure_set_config_dir(const char *path);
int  reconfigure_read_config_file(const char *filename, int startup);

#endif /* __RECONFIGURE_H__ */
