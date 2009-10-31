#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <execinfo.h>

#include "common.h"

int		common_debug_level	= 0;
FILE*		common_stdlog		= NULL;
char		common_logfile[256]	= "";
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
    int result;

    DPRINTF(7, "logfile=%s\n", logfile);

    result = 1;
    pthread_mutex_lock(&m_common);
    if ( ! ((logfile != NULL) && (strcmp(common_logfile, logfile) == 0))){
	if (common_stdlog != NULL){
	    fclose(common_stdlog);
	    memset(common_logfile, 0, sizeof(common_logfile));
	    common_stdlog = NULL;
	}

	if (logfile != NULL)
	    strncpy(common_logfile, logfile, sizeof(common_logfile) - 1);

	if (*common_logfile != '\0'){
	    common_stdlog = fopen(common_logfile, "a");
	    if (common_stdlog == NULL){
		memset(common_logfile, 0, sizeof(common_logfile));
		result = 0;
	    }
	}
    }
    pthread_mutex_unlock(&m_common);
    return result;
}

void common_debug_print(int level, const char *fmt, ...){
    va_list	ap;

    pthread_mutex_lock(&m_common);
    if ((level >= 0) && (level <= common_debug_level)){
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
	if (common_stdlog != NULL){
	    va_start(ap, fmt);
	    vfprintf(common_stdlog, fmt, ap);
	    va_end(ap);
	    fflush(common_stdlog);
	}
    }
    pthread_mutex_unlock(&m_common);
}

void common_print_backtrace(void){
    static char		buf[256];
    int			fd;
  #ifdef HAVE_BACKTRACE
    void		*array[200];
    size_t		size;
  #endif /* HAVE_BACKTRACE */

    snprintf(buf, sizeof(buf), "%d->%s: dumping ...\n", getpid(), __FUNCTION__);
    buf[sizeof(buf) - 2] = '\n';
    buf[sizeof(buf) - 1] = '\0';

  #ifdef HAVE_BACKTRACE
    size = backtrace(array, 200);
  #endif /* HAVE_BACKTRACE */

    fd = fileno(stderr);
    write(fd, buf, strlen(buf));
  #ifdef HAVE_BACKTRACE
    backtrace_symbols_fd(array, size, fd);
  #endif /* HAVE_BACKTRACE */
    fsync(fd);

    if (common_stdlog != NULL){
	fd = fileno(common_stdlog);
	write(fd, buf, strlen(buf));
      #ifdef HAVE_BACKTRACE
	backtrace_symbols_fd(array, size, fd);
      #endif /* HAVE_BACKTRACE */
	fsync(fd);
    }
}

#ifndef HAVE_STRNDUP
char* strndup(const char *s, size_t n){
    char	*p;

    if (strlen(s) <= n) return strdup(s);
    if ((p = malloc(n + 1)) == NULL) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}
#endif /* HAVE_STRNDUP */
