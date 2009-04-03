#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <execinfo.h>

#include "common.h"

pthread_mutex_t	m_common	= PTHREAD_MUTEX_INITIALIZER;

int common_set_smbnetfs_debug_level(int level){
    (void) level;

    return 1;
}

int common_set_log_file(const char *logfile){
    (void) logfile;

    return 1;
}

void common_debug_print(int level, const char *fmt, ...){
    va_list	ap;

    (void) level;

    pthread_mutex_lock(&m_common);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    fflush(stdout);
    va_end(ap);
    pthread_mutex_unlock(&m_common);
}

void common_print_backtrace(void){
    void	*array[200];
    size_t	size;
    int		fd;

    size = backtrace(array, 200);

    fprintf(stderr, "%d->%s: dumping ...\n", getpid(), __FUNCTION__);
    fflush(stderr);

    fd = fileno(stderr);
    backtrace_symbols_fd(array, size, fd);
    fsync(fd);
}
