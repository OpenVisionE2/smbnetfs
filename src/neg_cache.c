#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>

#include "common.h"
#include "list.h"
#include "neg_cache.h"

struct neg_cache{
    LIST		usage_entries;
    LIST		time_entries;
    struct timeval	tv;
    int			errno_value;
    char		hostname[1];
};


static int		neg_cache_timeout	= 3000;
static int		neg_cache_enabled	= 1;

static LIST		neg_cache_usage_list	= STATIC_LIST_INITIALIZER(neg_cache_usage_list);
static LIST		neg_cache_time_list	= STATIC_LIST_INITIALIZER(neg_cache_time_list);
static pthread_mutex_t	m_neg_cache		= PTHREAD_MUTEX_INITIALIZER;


static void neg_cache_remove_outdate_tv(struct timeval *tv){
    LIST		*elem;
    struct neg_cache	*cache;
    struct timeval	res;

    while(1){
	elem = last_list_elem(&neg_cache_time_list);
	if (!is_valid_list_elem(&neg_cache_time_list, elem)) break;

	cache = list_entry(elem, struct neg_cache, time_entries);
	if (timercmp(tv, &cache->tv, <)) goto bad_time;

	timersub(tv, &cache->tv, &res);
	if (res.tv_usec / 1000 + res.tv_sec * 1000 < neg_cache_timeout) break;

      bad_time:
	remove_from_list(&neg_cache_usage_list, &cache->usage_entries);
	remove_from_list(&neg_cache_time_list, &cache->time_entries);
	free(cache);
    }
}

static struct neg_cache * neg_cache_find_by_name(const char *name, size_t len){
    LIST		*elem;
    struct neg_cache	*cache;

    elem = first_list_elem(&neg_cache_usage_list);
    while(is_valid_list_elem(&neg_cache_usage_list, elem)){
	cache = list_entry(elem, struct neg_cache, usage_entries);
	if ((strncmp(cache->hostname, name, len) == 0) && (cache->hostname[len] == '\0'))
	    return cache;
	elem = elem->next;
    }
    return NULL;
}

static inline void neg_cache_remove_outdate(void){
    struct timeval	tv;

    gettimeofday(&tv, NULL);
    neg_cache_remove_outdate_tv(&tv);
}

int neg_cache_set_timeout(int timeout){
    if (timeout <= 0) return 0;
    DPRINTF(7, "timeout=%d\n", timeout);
    pthread_mutex_lock(&m_neg_cache);
    neg_cache_timeout = timeout;
    neg_cache_remove_outdate();
    pthread_mutex_unlock(&m_neg_cache);
    return 1;
}

int neg_cache_enable(int status){
    DPRINTF(7, "status=%d\n", status);
    pthread_mutex_lock(&m_neg_cache);
    neg_cache_enabled = status;
    if (!status) neg_cache_flush();
    pthread_mutex_unlock(&m_neg_cache);
    return 1;
}

int neg_cache_check(const char *url){
    int			result = 0;
    size_t		len = 0;
    struct neg_cache	*cache;

    while(*url == '/') url++;
    while((url[len] != '/') && (url[len] != '\0')) len++;
    if (len == 0) return 0;

    pthread_mutex_lock(&m_neg_cache);
    if (!neg_cache_enabled) goto end;
    neg_cache_remove_outdate();
    cache = neg_cache_find_by_name(url, len);
    if (cache != NULL){
	remove_from_list(&neg_cache_usage_list, &cache->usage_entries);
	add_to_list(&neg_cache_usage_list, &cache->usage_entries);
	result = cache->errno_value;
    }
  end:
    pthread_mutex_unlock(&m_neg_cache);
    return result;
}

int neg_cache_store(const char *url, int errno_value){
    int			result = 0;
    size_t		len = 0;
    struct neg_cache	*cache;
    struct timeval	tv;

    while(*url == '/') url++;
    while((url[len] != '/') && (url[len] != '\0')) len++;
    if (len == 0) return 0;

    pthread_mutex_lock(&m_neg_cache);
    if (!neg_cache_enabled) goto end;

    gettimeofday(&tv, NULL);
    neg_cache_remove_outdate_tv(&tv);

    cache = neg_cache_find_by_name(url, len);
    if (cache != NULL){
	remove_from_list(&neg_cache_usage_list, &cache->usage_entries);
	remove_from_list(&neg_cache_time_list, &cache->time_entries);
    }else{
	cache = malloc(sizeof(struct neg_cache) + len);
	if (cache == NULL) goto end;
	memset(cache, 0, sizeof(struct neg_cache) + len);
	strncpy(cache->hostname, url, len);
    }
    cache->tv = tv;
    cache->errno_value = errno_value;
    add_to_list(&neg_cache_usage_list, &cache->usage_entries);
    add_to_list(&neg_cache_time_list, &cache->time_entries);
    result = 1;

  end:
    pthread_mutex_unlock(&m_neg_cache);
    return result;
}

void neg_cache_flush(void){
    LIST		*elem;
    struct neg_cache	*cache;

    pthread_mutex_lock(&m_neg_cache);
    while(1){
	elem = first_list_elem(&neg_cache_usage_list);
	if (!is_valid_list_elem(&neg_cache_usage_list, elem)) break;

	cache = list_entry(elem, struct neg_cache, usage_entries);
	remove_from_list(&neg_cache_usage_list, &cache->usage_entries);
	remove_from_list(&neg_cache_time_list, &cache->time_entries);
	free(cache);
    }
    pthread_mutex_unlock(&m_neg_cache);
}
