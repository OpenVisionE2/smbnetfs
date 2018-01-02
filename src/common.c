#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <execinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "common.h"

int			common_debug_level	= 0;
static int		common_logfd[2]		= {2, -1};
static char		common_logfile[256]	= "";
static pthread_mutex_t	m_common		= PTHREAD_MUTEX_INITIALIZER;


void common_init(void){
    common_logfd[0] = fileno(stderr);
    common_logfd[1] = -1;
}

int common_set_smbnetfs_debug_level(int level){
    if ((level < 0) || (level > 10)) return 0;
    DPRINTF(8, "level=%d\n", level);
    g_atomic_int_set(&common_debug_level, level);
    return 1;
}

int common_set_log_file(const char *logfile){
    DPRINTF(7, "logfile=%s\n", logfile);

    pthread_mutex_lock(&m_common);
    if ( ! ((logfile != NULL) && (strcmp(common_logfile, logfile) == 0))){
	if (common_logfd[1] != -1){
	    close(common_logfd[1]);
	    memset(common_logfile, 0, sizeof(common_logfile));
	    common_logfd[1] = -1;
	}

	if (logfile != NULL)
	    strncpy(common_logfile, logfile, sizeof(common_logfile) - 1);

	if (*common_logfile != '\0'){
	    common_logfd[1] = open(common_logfile, O_WRONLY | O_APPEND | O_CREAT, 0644);
	    if (common_logfd[1] == -1){
		memset(common_logfile, 0, sizeof(common_logfile));
		/* actually we get here if strcmp(common_logfile, logfile) != 0, *
		 * so we can use variable logfile instead of common_logfile      */
		pthread_mutex_unlock(&m_common);
		DPRINTF(0, "Can't open logfile '%s', error : %s.\n", logfile, strerror(errno));
		return 0;
	    }
	}
    }
    pthread_mutex_unlock(&m_common);
    return 1;
}

void common_debug_print(const char *fmt, ...){
    int		i;
    va_list	ap;

    pthread_mutex_lock(&m_common);
    for(i = 0; i < 2; i++){
	if (common_logfd[i] == -1) continue;
	va_start(ap, fmt);
	vdprintf(common_logfd[i], fmt, ap);
	va_end(ap);
    }
    pthread_mutex_unlock(&m_common);
}

void common_print_backtrace(void){
    int			i;
  #ifdef HAVE_BACKTRACE
    void		*array[200];
    size_t		size;

    size = backtrace(array, sizeof(array) / sizeof(array[0]));
  #endif /* HAVE_BACKTRACE */
    for(i = 0; i < 2; i++){
	if (common_logfd[i] == -1) continue;
	dprintf(common_logfd[i], "%d->%s: dumping ...\n", getpid(), __FUNCTION__);
      #ifdef HAVE_BACKTRACE
	backtrace_symbols_fd(array, size, common_logfd[i]);
      #endif /* HAVE_BACKTRACE */
    }
}
