#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <execinfo.h>

#include "common.h"

int		common_debug_level	= 0;
pthread_mutex_t	m_common		= PTHREAD_MUTEX_INITIALIZER;

int common_set_smbnetfs_debug_level(int level){
    if ((level < 0) || (level > 10)) return 0;
    DPRINTF(8, "level=%d\n", level);
    pthread_mutex_lock(&m_common);
    common_debug_level = level;
    pthread_mutex_unlock(&m_common);
    return 1;
}

int common_get_smbnetfs_debug_level(void){
    int	level;

    pthread_mutex_lock(&m_common);
    level = common_debug_level;
    pthread_mutex_unlock(&m_common);
    DPRINTF(8, "level=%d\n", level);
    return level;
}

int common_set_log_file(const char *logfile){
    (void) logfile;

    return 1;
}

void common_debug_print(int level, const char *fmt, ...){
    va_list	ap;

    pthread_mutex_lock(&m_common);
    if ((level >= 0) && (level <= common_debug_level)){
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fflush(stderr);
	va_end(ap);
    }
    pthread_mutex_unlock(&m_common);
}

void common_print_backtrace(void){
    static char		buf[256];
    void		*array[200];
    size_t		size;
    int			fd;

    fd = fileno(stderr);

    snprintf(buf, sizeof(buf), "%d->%s: dumping ...\n", getpid(), __FUNCTION__);
    buf[sizeof(buf) - 2] = '\n';
    buf[sizeof(buf) - 1] = '\0';
    write(fd, buf, strlen(buf));

    size = backtrace(array, 200);
    backtrace_symbols_fd(array, size, fd);
    fsync(fd);
}
