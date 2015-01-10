#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "list.h"
#include "smb_conn.h"
#include "samba.h"
#include "common.h"

struct samba_ctx{
    LIST		entries;
    int			ref_count;
    struct smb_conn_ctx	smb_ctx;
    char		name[128];
};

#define smb_conn_ctx_to_samba_ctx(ptr)	\
    (struct samba_ctx *)((char*)(ptr) - offsetof(struct samba_ctx, smb_ctx))

static size_t		samba_max_rw_block_size	= (48 * 1024);
static int		samba_ctx_count		= 0;
static int		samba_ctx_max_count	= 15;
static LIST		samba_ctx_list		= STATIC_LIST_INITIALIZER(samba_ctx_list);
static pthread_mutex_t	m_samba			= PTHREAD_MUTEX_INITIALIZER;


int samba_init(size_t max_rw_block_size){
    size_t	page_size;

    page_size = getpagesize();
    max_rw_block_size -= (max_rw_block_size % page_size);
    if (max_rw_block_size == 0) max_rw_block_size = page_size;

    samba_max_rw_block_size = max_rw_block_size;
    DPRINTF(7, "max_rw_block_size=%zd\n", samba_max_rw_block_size);
    return 1;
}

static void samba_set_context_name(struct samba_ctx *ctx, const char *name, size_t len){
    if (len >= sizeof(ctx->name)) len = sizeof(ctx->name) - 1;
    if (len > 0) strncpy(ctx->name, name, len);
    ctx->name[len] = '\0';
}

static struct samba_ctx * samba_add_new_context(const char *name, size_t len){
    struct samba_ctx	*ctx;

    ctx = malloc(sizeof(struct samba_ctx));
    if (ctx == NULL) return NULL;
    memset(ctx, 0, sizeof(struct samba_ctx));
    if (smb_conn_ctx_init(&ctx->smb_ctx, samba_max_rw_block_size) != 0){
	free(ctx);
	return NULL;
    }
    samba_set_context_name(ctx, name, len);
    add_to_list_back(&samba_ctx_list, &ctx->entries);
    samba_ctx_count++;
    return ctx;
}

static int samba_try_to_remove_context(struct samba_ctx *ctx){
    if (ctx->ref_count != 0) return -1;
    if (smb_conn_ctx_destroy(&ctx->smb_ctx) != 0) return -1;
    samba_ctx_count--;
    remove_from_list(&samba_ctx_list, &ctx->entries);
    return 0;
}

static struct samba_ctx * samba_find_by_name(const char *name, size_t len){
    struct samba_ctx	*ctx;
    LIST		*elem;

    if (len >= sizeof(ctx->name)) len = sizeof(ctx->name) - 1;
    elem = first_list_elem(&samba_ctx_list);
    while(is_valid_list_elem(&samba_ctx_list, elem)){
	ctx = list_entry(elem, struct samba_ctx, entries);
	if ((strncasecmp(ctx->name, name, len) == 0) &&
	    (ctx->name[len] == '\0')) return ctx;
	elem = elem->next;
    };
    return NULL;
}

static struct samba_ctx * samba_find_oldest(void){
    /* our list is sorted by the usage time, so the last element is oldest */
    LIST *elem = last_list_elem(&samba_ctx_list);
    if (is_valid_list_elem(&samba_ctx_list, elem))
	return list_entry(elem, struct samba_ctx, entries);
    return NULL;
}

static const char* samba_get_context_status_string(void){
    static char		buffer[4096];
    LIST		*elem;
    int			ret;
    size_t		len;
    char		*pos, *ptn;

    memset(buffer, 0, sizeof(buffer));
    len = sizeof(buffer); pos = buffer; ptn = "%s[%d], ";

    *pos++ = '('; len--;
    elem = first_list_elem(&samba_ctx_list);
    while(is_valid_list_elem(&samba_ctx_list, elem)){
	struct samba_ctx	*ctx;

	ctx = list_entry(elem, struct samba_ctx, entries);
	if (!is_valid_list_elem(&samba_ctx_list, elem->next)) ptn = "%s[%d]";
	ret = snprintf(pos, len, ptn, ctx->name, ctx->ref_count);
	if (ret < 0) goto error;
	if ((size_t) ret >= len) goto out_of_space;
	pos += ret; len -= ret;
	elem = elem->next;
    };
    if (len < 2) goto out_of_space;
    *pos++ = ')';
    *pos = '\0';
    return buffer;

  out_of_space:
    strcpy(buffer + sizeof(buffer) - 5, "...)");
    return buffer;

  error:
    return "(?error?)";
}

/* our list is sorted by the usage time, so touching is equivalent */
/* to the moving of element to the top of the list */
static inline void samba_touch_ctx_without_lock(struct samba_ctx *ctx){
    remove_from_list(&samba_ctx_list, &ctx->entries);
    add_to_list(&samba_ctx_list, &ctx->entries);
}

/* the same as above, but with locking */
static void samba_touch_ctx(struct samba_ctx *ctx){
    pthread_mutex_lock(&m_samba);
    samba_touch_ctx_without_lock(ctx);
    pthread_mutex_unlock(&m_samba);
}

int samba_set_max_ctx_count(int count){
    if (count < 3) return 0;
    DPRINTF(7, "count=%d\n", count);
    pthread_mutex_lock(&m_samba);
    samba_ctx_max_count = count;
    pthread_mutex_unlock(&m_samba);
    return 1;
}

void samba_allocate_ctxs(void){
    struct samba_ctx	*ctx;

    pthread_mutex_lock(&m_samba);
    while(samba_ctx_count < samba_ctx_max_count){
	if ((ctx = samba_add_new_context("", 0)) == NULL) break;
    }
    pthread_mutex_unlock(&m_samba);
}

void samba_destroy_unused_ctxs(void){
    LIST		*elem;
    struct samba_ctx	*ctx;

    pthread_mutex_lock(&m_samba);
    elem = first_list_elem(&samba_ctx_list);
    while(is_valid_list_elem(&samba_ctx_list, elem)){
	ctx = list_entry(elem, struct samba_ctx, entries);
	elem = elem->next;
	if (ctx->ref_count == 0) samba_try_to_remove_context(ctx);
    }
    DPRINTF(6, "ctx_total=%d, list=%s\n",
	samba_ctx_count, samba_get_context_status_string());
    pthread_mutex_unlock(&m_samba);
}

static struct samba_ctx * samba_get_ctx(const char *url){
    size_t		len;
    struct samba_ctx	*ctx;

    /* find a length of first component of url's path */
    for(len = 0; url[len] == '/'; len++);
    for(; (url[len] != '\0') && (url[len] != '/'); len++);
    DPRINTF(6, "name='%.*s'\n", (int) len, url);

    pthread_mutex_lock(&m_samba);
    if ((ctx = samba_find_by_name(url, len)) != NULL) goto exist;
    if (samba_ctx_count < samba_ctx_max_count)
	if ((ctx = samba_add_new_context(url, len)) != NULL) goto exist;
    if ((ctx = samba_find_oldest()) == NULL) goto shit_happens;

    /* reuse oldest context for new purpose */
    samba_set_context_name(ctx, url, len);

  exist:
    /* touch ctx and increase its ref_count */
    samba_touch_ctx_without_lock(ctx);
    ctx->ref_count++;

  shit_happens:
    DPRINTF(6, "ctx_total=%d, list=%s\n",
	samba_ctx_count, samba_get_context_status_string());
    pthread_mutex_unlock(&m_samba);
    return ctx;
}

static void samba_release_ctx(struct samba_ctx *ctx){
    pthread_mutex_lock(&m_samba);
    DPRINTF(6, "ctx->name=%s[%d]\n", ctx->name, ctx->ref_count);
    if (ctx->ref_count > 0){
	ctx->ref_count--;
	if ((samba_ctx_count > samba_ctx_max_count) && (ctx->ref_count == 0))
	    samba_try_to_remove_context(ctx);
    }else{
	DPRINTF(0, "WARNING! trying to release an unused context!\n");
    }
    DPRINTF(6, "ctx_total=%d, list=%s\n",
	samba_ctx_count, samba_get_context_status_string());
    pthread_mutex_unlock(&m_samba);
}

samba_fd samba_open(const char *url, int flags, mode_t mode){
    int			error;
    struct samba_ctx	*ctx;
    samba_fd		fd;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return NULL;
    }
    fd = smb_conn_open(&ctx->smb_ctx, url, flags, mode);
    error = errno;
    if (fd == NULL) samba_release_ctx(ctx);
    errno = error;
    return fd;
}

samba_fd samba_creat(const char *url, mode_t mode){
    int			error;
    struct samba_ctx	*ctx;
    samba_fd		fd;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return NULL;
    }
    fd = smb_conn_creat(&ctx->smb_ctx, url, mode);
    error = errno;
    if (fd == NULL) samba_release_ctx(ctx);
    errno = error;
    return fd;
}

ssize_t samba_read(samba_fd fd, off_t offset, void *buf, size_t bufsize){
    ssize_t	result = 0;

    if ((fd == NULL) || (fd->ctx == NULL)){
	errno = EINVAL;
	return -1;
    }
    samba_touch_ctx(smb_conn_ctx_to_samba_ctx(fd->ctx));
    while(bufsize > 0){
	ssize_t		res;
	size_t		count;

	count = (bufsize <= samba_max_rw_block_size) ?
			bufsize : samba_max_rw_block_size;
	res = smb_conn_read(fd->ctx, fd, offset, buf, count);
	if (res == (ssize_t) (-1)) return res;
	buf += res; offset += res; bufsize -= res;
	result += res;
	if (res != (ssize_t) count) break;
    }
    return result;
}

ssize_t samba_write(samba_fd fd, off_t offset, void *buf, size_t bufsize){
    ssize_t	result = 0;

    if ((fd == NULL) || (fd->ctx == NULL)){
	errno = EINVAL;
	return -1;
    }
    samba_touch_ctx(smb_conn_ctx_to_samba_ctx(fd->ctx));
    while(bufsize > 0){
	ssize_t		res;
	size_t		count;

	count = (bufsize <= samba_max_rw_block_size) ?
			bufsize : samba_max_rw_block_size;
	res = smb_conn_write(fd->ctx, fd, offset, buf, count);
	if (res == (ssize_t) (-1)) return res;
	buf += res; offset += res; bufsize -= res;
	result += res;
	if (res != (ssize_t) count) break;
    }
    return result;
}

int samba_close(samba_fd fd){
    int			error, result;
    struct smb_conn_ctx	*ctx;

    if ((fd == NULL) || (fd->ctx == NULL)){
	errno = EINVAL;
	return -1;
    }
    ctx = fd->ctx;
    result = smb_conn_close(ctx, fd);
    error = errno;
    if (result == 0) samba_release_ctx(smb_conn_ctx_to_samba_ctx(ctx));
    errno = error;
    return result;
}

int samba_unlink(const char *url){
    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_unlink(&ctx->smb_ctx, url);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

int samba_rename(const char *old_url, const char *new_url){
    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(old_url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_rename(&ctx->smb_ctx, old_url, new_url);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

samba_fd samba_opendir(const char *url){
    int			error;
    struct samba_ctx	*ctx;
    samba_fd		fd;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return NULL;
    }
    fd = smb_conn_opendir(&ctx->smb_ctx, url);
    error = errno;
    if (fd == NULL) samba_release_ctx(ctx);
    errno = error;
    return fd;
}

int samba_closedir(samba_fd fd){
    int			error, result;
    struct smb_conn_ctx	*ctx;

    if ((fd == NULL) || (fd->ctx == NULL)){
	errno = EINVAL;
	return -1;
    }
    ctx = fd->ctx;
    result = smb_conn_closedir(ctx, fd);
    error = errno;
    if (result == 0) samba_release_ctx(smb_conn_ctx_to_samba_ctx(ctx));
    errno = error;
    return result;
}

ssize_t samba_readdir(samba_fd fd, void *buf, size_t bufsize){
    if ((fd == NULL) || (fd->ctx == NULL)){
	errno = EINVAL;
	return -1;
    }
    samba_touch_ctx(smb_conn_ctx_to_samba_ctx(fd->ctx));
    return smb_conn_readdir(fd->ctx, fd, buf, bufsize);
}

int samba_mkdir(const char *url, mode_t mode){
    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_mkdir(&ctx->smb_ctx, url, mode);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

int samba_rmdir(const char *url){
    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_rmdir(&ctx->smb_ctx, url);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

int samba_stat (const char *url, struct stat *st){
    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_stat(&ctx->smb_ctx, url, st);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

int samba_fstat(samba_fd fd, struct stat *st){
    if ((fd == NULL) || (fd->ctx == NULL)){
	errno = EINVAL;
	return -1;
    }
    samba_touch_ctx(smb_conn_ctx_to_samba_ctx(fd->ctx));
    return smb_conn_fstat(fd->ctx, fd, st);
}

int samba_ftruncate(samba_fd fd, off_t size){
    if ((fd == NULL) || (fd->ctx == NULL)){
	errno = EINVAL;
	return -1;
    }
    samba_touch_ctx(smb_conn_ctx_to_samba_ctx(fd->ctx));
    return smb_conn_ftruncate(fd->ctx, fd, size);
}

int samba_chmod(const char *url, mode_t mode){
    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_chmod(&ctx->smb_ctx, url, mode);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

int samba_utimes(const char *url, struct timeval *tbuf){
    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_utimes(&ctx->smb_ctx, url, tbuf);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

int samba_setxattr(const char *url, const char *name,
		const void *value, size_t size, int flags){

    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_setxattr(&ctx->smb_ctx, url, name, value, size, flags);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

int samba_getxattr(const char *url, const char *name,
		void *value, size_t size){

    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_getxattr(&ctx->smb_ctx, url, name, value, size);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

int samba_listxattr(const char *url, char *list, size_t size){
    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_listxattr(&ctx->smb_ctx, url, list, size);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}

int samba_removexattr(const char *url, const char *name){
    int			error, result;
    struct samba_ctx	*ctx;

    if ((ctx = samba_get_ctx(url)) == NULL){
	errno = ENOMEM;
	return -1;
    }
    result = smb_conn_removexattr(&ctx->smb_ctx, url, name);
    error = errno;
    samba_release_ctx(ctx);
    errno = error;
    return result;
}
