#include "config.h"
#include <errno.h>
#include <iconv.h>
#include <string.h>
#include "charset.h"

static char	charset_buf[CHARSET_BUF_SIZE];

static char	charset_hex_digit[]	= "0123456789ABCDEF";
static iconv_t	charset_local2samba	= (iconv_t) (-1);
static iconv_t	charset_samba2local	= (iconv_t) (-1);


int charset_init(const char *local, const char *samba){
    charset_local2samba = iconv_open(samba, local);
    if (charset_local2samba == (iconv_t) (-1)) return -1;

    charset_samba2local = iconv_open(local, samba);
    if (charset_samba2local == (iconv_t) (-1)){
	iconv_close(charset_local2samba);
	charset_local2samba = (iconv_t) (-1);
	return -1;
    }
    return 0;
}

static char * charset_samba_to_local(iconv_t cd,
				const char *str, size_t str_len,
				char *buf, size_t buf_len){
    size_t	i, r, len, out_len;
    char	*in, *out;

    if ((buf == NULL) || (buf_len == 0) || (cd == (iconv_t)(-1))) return NULL;

    len = 0;
    while(str_len > 0){
	in = (char*) str;
	out = buf + len;
	out_len = buf_len - len;
	if (out_len == 0) return NULL;

	for(i = 1; i <= str_len; i++){
	    r = iconv(cd, &in, &i, &out, &out_len);

	    /* conversion error */
	    if (r == (size_t)(-1)){
		if (errno == E2BIG) return NULL;
		if (errno == EINVAL) continue;
		goto conversion_is_bad;
	    }

	    /* conversion is ok, but not reversable */
	    if (r != 0) goto conversion_is_bad;

	    /* conversion is ok */
	    switch(buf[len]){
		case ':':
		case '@':
		case '%':
		case '/':
		case '\\':
		    /* this characters is not allowed in names */
		    goto conversion_is_bad;

		default:
		    goto conversion_is_ok;
	    };
	}

      conversion_is_bad:
	if (buf_len - len < 3) return NULL;
	buf[len++] = '%';
	buf[len++] = charset_hex_digit[(*str & 0xF0) >> 4];
	buf[len++] = charset_hex_digit[*str & 0x0F];
	str++; str_len--;
	continue;

      conversion_is_ok:
	str_len -= (in - str); str = in;
	len = out - buf;
	continue;
    }
    return buf;
}

static char * charset_local_to_samba(iconv_t cd,
				const char *str, size_t str_len,
				char *buf, size_t buf_len){
    size_t	i, r, len, out_len;
    char	*in, *out;

    if ((buf == NULL) || (buf_len == 0) || (cd == (iconv_t)(-1))) return NULL;

    len = 0;
    while(str_len > 0){
	in = (char*) str;
	out = buf + len;
	out_len = buf_len - len;
	if (out_len == 0) return NULL;

	for(i = 1; i <= str_len; i++){
	    r = iconv(cd, &in, &i, &out, &out_len);
	    if (r != (size_t)(-1)) goto conversion_is_ok;
	    if (errno == E2BIG) return NULL;
	    if (errno == EINVAL) continue;
	    break;
	}

	/* conversion is bad */
	return NULL;

      conversion_is_ok:
	str_len -= (in - str); str = in;
	len = out - buf;
	continue;
    }
    return buf;
}

char * charset_local2smb_r(const char *src, char *dst, size_t dst_len){
    const char		*smb_prefix	= "smb:/";
    const int		smb_prefix_len	= 5;
    char		*res;

    memset(dst, 0, dst_len);
    strcpy(dst, smb_prefix);
    res = charset_local_to_samba(
			charset_local2samba,
			src, strlen(src),
			dst + smb_prefix_len, dst_len - smb_prefix_len - 1);
    return (res != NULL) ? dst : NULL;
}

char * charset_smb2local_r(const char *src, char *dst, size_t dst_len){
    char *res;

    memset(dst, 0, dst_len);
    res = charset_samba_to_local(
			charset_samba2local,
			src, strlen(src),
			dst, dst_len - 1);
    return (res != NULL) ? dst : NULL;
}

char * charset_local2smb(const char *src){
    return charset_local2smb_r(src,
			charset_buf,
			sizeof(charset_buf));
}

char * charset_smb2local(const char *src){
    return charset_smb2local_r(src,
			charset_buf,
			sizeof(charset_buf));
}
