#ifndef __NEG_CACHE_H__
#define __NEG_CACHE_H__

int  neg_cache_set_timeout(int timeout);
int  neg_cache_enable(int status);

int  neg_cache_check(const char *url);
int  neg_cache_store(const char *url, int error);
void neg_cache_flush(void);

#endif /* __NEG_CACHE_H__ */
