#ifndef __CHARSET_H__
#define __CHARSET_H__

#include <sys/types.h>

#define CHARSET_BUF_SIZE	2048

int    charset_init(const char *local, const char *samba);
char * charset_local2smb(const char *src);
char * charset_smb2local(const char *src);
char * charset_local2smb_r(const char *src, char *dest, size_t dest_size);
char * charset_smb2local_r(const char *src, char *dest, size_t dest_size);

#endif /* __CHARSET_H__ */
