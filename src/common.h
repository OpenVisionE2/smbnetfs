#ifndef __COMMON_H__
#define	__COMMON_H__

#include <sys/types.h>
#include <unistd.h>

int  common_get_smbnetfs_debug_level(void);
int  common_set_smbnetfs_debug_level(int level);
int  common_set_log_file(const char *logfile);

void common_debug_print(int level, const char *fmt, ...);
void common_print_backtrace(void);

#ifdef PRINTF_DEBUG
  #include <stdio.h>
  #define	DPRINTF(level, fmt, args...)	{ fprintf(stderr, "%d->%s: " fmt, (int) getpid(), __FUNCTION__, ## args); fflush(stderr); }
#else
  #define	DPRINTF(level, fmt, args...)	common_debug_print(level, "%d->%s: " fmt, (int) getpid(), __FUNCTION__, ## args)
#endif

#ifndef HAVE_STRNDUP
  char* strndup(const char *s, size_t n);
#endif

#endif /* __COMMON_H__ */
