#include "config.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "list.h"
#include "common.h"
#include "smbitem.h"
#include "stat_workaround.h"

struct stat_workaround_predefined{
	int	case_sensitive;	// is predefined name case sensitive?
	int	depth;		// name search depth
	char	*name;		// predefined name to be workarounded
};

struct stat_workaround{
	LIST	entries;
	time_t	touch_time;	// struct touch time
	int	case_sensitive;	// is name case sensitive?
	int	depth;		// name search depth
	int	len;		// calculated from the name
	char	name[1];	// name to be workarounded
};

struct stat_workaround_exception{
	LIST	entries;
	time_t	touch_time;	// struct touch time
	int	depth;		// calculated from the path
	int	len;		// calculated from the path
	char	path[1];	// exception path
};

static struct stat_workaround_predefined	stat_workaround_predefined_list[] = {
							{ 1, 3, ".directory" },
							{ 1, 3, ".git" },
							{ 1, 3, "HEAD" },
							{ 0, 3, "desktop.ini" },
							{ 1, 1, "autorun.inf" },
							{ 1, 1, ".xdg-volume-info" },
							{ 0, 0, NULL }
						};

static int		stat_workaround_default_entries	= 1;
static int		stat_workaround_default_depth	= 3;
static LIST		stat_workaround_list		= STATIC_LIST_INITIALIZER(stat_workaround_list);
static LIST		stat_workaround_exception_list	= STATIC_LIST_INITIALIZER(stat_workaround_exception_list);
static pthread_mutex_t m_stat_workaround		= PTHREAD_MUTEX_INITIALIZER;


int stat_workaround_enable_default_entries(int new_status){
    DPRINTF(7, "new_status=%s\n", new_status ? "true" : "false");
    pthread_mutex_lock(&m_stat_workaround);
    stat_workaround_default_entries = new_status;
    pthread_mutex_unlock(&m_stat_workaround);
    return 1;
}

int stat_workaround_set_default_depth(int depth){
    if (depth < -1) return 0;
    DPRINTF(7, "depth=%d\n", depth);
    pthread_mutex_lock(&m_stat_workaround);
    stat_workaround_default_depth = depth;
    pthread_mutex_unlock(&m_stat_workaround);
    return 1;
}

static int stat_workaround_add_name_internal(const char *name, int case_sensitive, int depth){
    LIST				*elem;
    struct stat_workaround		*workaround;

    DPRINTF(6, "name=%s, case_sensitive=%d, depth=%d\n",
	name, case_sensitive, depth);

    if (depth < -1) depth = stat_workaround_default_depth;

    elem = first_list_elem(&stat_workaround_list);
    while(is_valid_list_elem(&stat_workaround_list, elem)){
	workaround = list_entry(elem, struct stat_workaround, entries);
	if (strcmp(workaround->name, name) == 0) goto refresh_item;
	elem = elem->next;
    }

    workaround = malloc(sizeof(struct stat_workaround) + strlen(name));
    if (workaround == NULL) return 0;

    memset(workaround, 0, sizeof(struct stat_workaround) + strlen(name));
    strcpy(workaround->name, name);
    workaround->len = strlen(name);
    add_to_list_back(&stat_workaround_list, &workaround->entries);

  refresh_item:
    workaround->touch_time     = time(NULL);
    workaround->depth          = depth;
    workaround->case_sensitive = case_sensitive;
    return 1;
}

int stat_workaround_add_name(const char *name, int case_sensitive, int depth){
    int		result;

    pthread_mutex_lock(&m_stat_workaround);
    result = stat_workaround_add_name_internal(name, case_sensitive, depth);
    pthread_mutex_unlock(&m_stat_workaround);
    return result;
}

/********************************************************************
 * WARNING: stat_workaround_exception_list is sorted alphabetically *
 ********************************************************************/
static int stat_workaround_add_exception_internal_low(const char *path, size_t len, int depth){
    LIST				*elem;
    struct stat_workaround_exception	*exception;
    int					result = 1;

    for(; (len > 0) && (path[len - 1] == '/'); len--);

    elem = first_list_elem(&stat_workaround_exception_list);
    while(is_valid_list_elem(&stat_workaround_exception_list, elem)){
	exception = list_entry(elem, struct stat_workaround_exception, entries);
	if ((result = strncmp(exception->path, path, len)) < 0) break;
	if ((result == 0) && (exception->path[len] == '\0')) goto refresh_item;
	elem = elem->next;
    }

    exception = malloc(sizeof(struct stat_workaround_exception) + len);
    if (exception == NULL) return 0;

    memset(exception, 0, sizeof(struct stat_workaround_exception) + len);
    strncpy(exception->path, path, len);
    exception->len = len;
    exception->depth = depth;
    insert_to_list_before(&stat_workaround_exception_list, elem, &exception->entries);

  refresh_item:
    exception->touch_time = time(NULL);
    return 1;
}

static int stat_workaround_add_exception_internal(const char *path){
    size_t	pos;
    int		depth;

    DPRINTF(6, "path=%s\n", path);

    pos = 0;
    depth = 0;
    while(path[pos]){
	while(path[pos] == '/') pos++;
	if (path[pos] == '\0') break;
	while((path[pos] != '/') && (path[pos] != '\0')) pos++;

	if (!stat_workaround_add_exception_internal_low(path, pos, ++depth)) return 0;
    }

    int					i = 0;
    LIST				*elem;
    struct stat_workaround_exception	*exception;

    elem = first_list_elem(&stat_workaround_exception_list);
    while(is_valid_list_elem(&stat_workaround_exception_list, elem)){
	exception = list_entry(elem, struct stat_workaround_exception, entries);
	DPRINTF(6, "%d: path=%s, len=%d, depth=%d\n",
	    i, exception->path, exception->len, exception->depth);
	i++;
	elem = elem->next;
    }
    return 1;
}

int stat_workaround_add_exception(const char *path){
    int		result;

    pthread_mutex_lock(&m_stat_workaround);
    result = stat_workaround_add_exception_internal(path);
    pthread_mutex_unlock(&m_stat_workaround);
    return result;
}

void stat_workaround_add_default_entries(void){
    struct stat_workaround_predefined	*elem;

    pthread_mutex_lock(&m_stat_workaround);
    if (stat_workaround_default_entries){
	for(elem = stat_workaround_predefined_list; elem->name != NULL; elem++)
	    stat_workaround_add_name_internal(elem->name,
		elem->case_sensitive, elem->depth);
    }
    pthread_mutex_unlock(&m_stat_workaround);
}

void stat_workaround_delete_obsolete(time_t threshold){
    LIST				*elem;
    struct stat_workaround		*workaround;
    struct stat_workaround_exception	*exception;

    DPRINTF(6, "threshold=%d\n", (int)threshold);

    pthread_mutex_lock(&m_stat_workaround);

    /* check matching with exception list */
    elem = first_list_elem(&stat_workaround_exception_list);
    while(is_valid_list_elem(&stat_workaround_exception_list, elem)){
	exception = list_entry(elem, struct stat_workaround_exception, entries);
	elem = elem->next;

	if (exception->touch_time < threshold){
	    remove_from_list(&stat_workaround_exception_list, &exception->entries);
	    free(exception);
	}
    }

    /* check matching with workaround list */
    elem = first_list_elem(&stat_workaround_list);
    while(is_valid_list_elem(&stat_workaround_list, elem)){
	workaround = list_entry(elem, struct stat_workaround, entries);
	elem = elem->next;

	if (workaround->touch_time < threshold){
	    remove_from_list(&stat_workaround_list, &workaround->entries);
	    free(workaround);
	}
    }

    pthread_mutex_unlock(&m_stat_workaround);
}

static int stat_workaround_check_path(const char *path, int min_depth){
    LIST			*elem;
    struct stat_workaround	*workaround;
    const char			*path_start, *path_end;
    ssize_t			len;
    int				i;
    int				(*cmp_func)(const char *, const char *, size_t);

    DPRINTF(7, "path=%s, min_depth=%d\n", path, min_depth);

    /* check matching with workaround list */
    elem = first_list_elem(&stat_workaround_list);
    while(is_valid_list_elem(&stat_workaround_list, elem)){
	workaround = list_entry(elem, struct stat_workaround, entries);
	DPRINTF(7, "workaround->name=%s\n", workaround->name);

	cmp_func = workaround->case_sensitive ? strncmp : strncasecmp;

	path_start = path;
	len = strlen(workaround->name);
	for(i = min_depth; (i < workaround->depth) || (workaround->depth == -1); i++){
	    while(*path_start == '/') path_start++;
	    if (*path_start == '\0') break;

	    DPRINTF(7, "path_start=%s\n", path_start);
	    path_end = path_start;
	    while((*path_end != '/') && (*path_end != '\0')) path_end++;
	    if ((path_end - path_start == len) &&
		(cmp_func(path_start, workaround->name, len) == 0)) return 1;

	    path_start = path_end;
	}

	elem = elem->next;
    }
    return 0;
}

int stat_workaround_is_name_ignored(const char *path){
    LIST				*elem;
    struct stat_workaround_exception	*exception;
    ssize_t				len, min_len;
    int					result, ret;

    DPRINTF(7, "path=%s\n", path);

    for(len = strlen(path); (len > 1) && (path[len - 1] == '/'); len--);

    pthread_mutex_lock(&m_stat_workaround);

    /* check matching with exception list */
    elem = first_list_elem(&stat_workaround_exception_list);
    while(is_valid_list_elem(&stat_workaround_exception_list, elem)){
	exception = list_entry(elem, struct stat_workaround_exception, entries);

	min_len = (len <= exception->len) ? len : exception->len;
	ret = strncmp(exception->path, path, min_len);

	DPRINTF(7, "exception->path=%s, min_len=%zd, ret=%d\n",
			exception->path, min_len, ret);

	if (ret == 0){
	    if (min_len == len){
		if ((exception->path[len] == '/') || (exception->path[len] == '\0')){
		    /* path is a part of exception path, so do not ignore it */
		    result = 0;
		    goto end;
		}
	    }else{
		if (path[exception->len] == '/'){
		    /* path contain an exception path, so start */
		    /* scanning from exception->depth level     */
		    result = stat_workaround_check_path(path + min_len, exception->depth);
		    goto end;
		}
	    }
	}

	elem = elem->next;
    }

//  if (smbitem_is_name_exist(workaround->name)) continue;

    /* scan the full path for a pattern */
    result = stat_workaround_check_path(path, 0);

  end:
    pthread_mutex_unlock(&m_stat_workaround);

    DPRINTF(7, "path=%s, result=%d\n", path, result);
    return result;
}
