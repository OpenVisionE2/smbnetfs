#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/statvfs.h>
#include <time.h>
#include <pthread.h>
#include <libsmbclient.h>
#ifdef HAVE_SETXATTR
  #include <sys/xattr.h>
#endif
#include <glib.h>

#include "common.h"
#include "smbitem.h"
#include "samba.h"
#include "stat_workaround.h"
#include "function.h"

static size_t		function_free_space_size	= 0;
static int		function_quiet_flag		= 1;
static int		function_show_dollar_shares	= 0;
static int		function_show_hidden_hosts	= 0;

static pthread_mutex_t	m_function		= PTHREAD_MUTEX_INITIALIZER;

int function_set_free_space_size(size_t blocks_count){
    DPRINTF(7, "blocks_count=%zd\n", blocks_count);
    pthread_mutex_lock(&m_function);
    function_free_space_size = blocks_count;
    pthread_mutex_unlock(&m_function);
    return 1;
}

static size_t function_get_free_space_size(void){
    size_t blocks_count;

    pthread_mutex_lock(&m_function);
    blocks_count = function_free_space_size;
    pthread_mutex_unlock(&m_function);
    return blocks_count;
}

int function_set_quiet_flag(int flag){
    DPRINTF(7, "flag=%d\n", flag);
    g_atomic_int_set(&function_quiet_flag, flag);
    return 1;
}

static inline int function_get_quiet_flag(void){
    return g_atomic_int_get(&function_quiet_flag);
}

int function_set_dollar_share_visibility(int flag){
    DPRINTF(7, "flag=%d\n", flag);
    g_atomic_int_set(&function_show_dollar_shares, flag);
    return 1;
}

static inline int function_get_dollar_share_visibility(void){
    return g_atomic_int_get(&function_show_dollar_shares);
}

int function_set_hidden_hosts_visibility(int flag){
    DPRINTF(7, "flag=%d\n", flag);
    g_atomic_int_set(&function_show_hidden_hosts, flag);
    return 1;
}

static inline int function_get_hidden_hosts_visibility(void){
    return g_atomic_int_get(&function_show_hidden_hosts);
}

static inline int function_check_xattr_name(const char *name){
    static char	*xattr_name = "system.nt_sec_desc.";
    return (strncmp(name, xattr_name, strlen(xattr_name)) == 0);
}

static inline samba_fd function_get_fd(struct fuse_file_info *fi){
    return (samba_fd) fi->fh;
}

static inline void function_store_fd(struct fuse_file_info *fi, samba_fd fd){
    fi->fh = (uint64_t) fd;
}

static int function_open(const char *path, struct fuse_file_info *fi){
    samba_fd	fd;

    DPRINTF(5, "(%s, flags=%o, fh=%llx)\n", path, fi->flags, (long long) fi->fh);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;

    if ((fd = samba_open(path, fi->flags, 0777)) == NULL) return -errno;
    function_store_fd(fi, fd);
    return 0;
}

static int function_creat(const char *path, mode_t mode,
			struct fuse_file_info *fi){
    samba_fd	fd;

    DPRINTF(5, "(%s, mode=%0x, flags=%o, fh=%llx)\n", path, mode,
	fi->flags, (long long) fi->fh);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;

    if ((fd = samba_creat(path, fi->flags)) == NULL) return -errno;
    function_store_fd(fi, fd);
    return 0;
}

static int function_read(const char *path, char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi){
    int		result;
    samba_fd	fd;

    DPRINTF(5, "(%s, %zd, fh=%llx, offset=%lld, flags=%o)\n", path, size,
	(long long) fi->fh, (long long) offset, fi->flags);

    if ((fd = function_get_fd(fi)) == NULL) return -EBADF;
    result = samba_read(fd, offset, buf, size);
    if (result == (ssize_t) (-1)) return -errno;
    return result;
}

static int function_write(const char *path, const char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi){
    int		result;
    samba_fd	fd;

    DPRINTF(5, "(%s, %zd, fh=%llx, offset=%lld, flags=%o)\n", path, size,
	(long long) fi->fh, (long long) offset, fi->flags);

    if ((fd = function_get_fd(fi)) == NULL) return -EBADF;
    result = samba_write(fd, offset, (char *) buf, size);
    if (result == (ssize_t) (-1)) return -errno;
    return result;
}

static int function_close(const char *path, struct fuse_file_info *fi){
    samba_fd	fd;

    DPRINTF(5, "(%s, fh=%llx, flags=%o)\n", path, (long long) fi->fh, fi->flags);

    if ((fd = function_get_fd(fi)) == NULL) return -EBADF;
    if (samba_close(fd) != 0) return -errno;
    return 0;
}

static int function_unlink(const char *path){
    DPRINTF(5, "(%s)\n", path);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;
    if (samba_unlink(path) != 0) return -errno;
    return 0;
}

static int function_rename(const char *from, const char *to){
    DPRINTF(5, "(%s, %s)\n", from, to);
    if (smbitem_what_is(from) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;
    if (smbitem_what_is(to) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;
    if (samba_rename(from, to) != 0) return -errno;
    return 0;
}

static int function_opendir(const char *path, struct fuse_file_info *fi){
    samba_fd	fd;

    DPRINTF(5, "(%s, flags=%o, fh=%llx)\n", path, fi->flags, (long long) fi->fh);
    switch(smbitem_what_is(path)){
	case SMBITEM_SMBNETFS_DIR:
	    function_store_fd(fi, (samba_fd) (-1));
	    return 0;

	case SMBITEM_SMB_NAME:
	case SMBITEM_SMB_SHARE:
	case SMBITEM_SMB_SHARE_ITEM:
	    if ((fd = samba_opendir(path)) == NULL) return -errno;
	    function_store_fd(fi, fd);
	    return 0;

	default:
	    return -ENOTDIR;
    }
}

static int function_closedir(const char *path, struct fuse_file_info *fi){
    samba_fd	fd;

    DPRINTF(5, "(%s, fh=%llx, flags=%o)\n", path, (long long) fi->fh, fi->flags);
    if ((fd = function_get_fd(fi)) == NULL) return -EBADF;
    if (fd == (samba_fd) (-1)) return 0;
    if (samba_closedir(fd) != 0) return -errno;
    return 0;
}

static int function_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi){
    samba_fd		fd;
    int			error, rec_cnt;
    struct stat 	st;

    (void) offset;
    DPRINTF(5, "(%s)\n", path);

    memset(&st, 0, sizeof(st));
    if ((fd = function_get_fd(fi)) == NULL) return -EBADF;
    if (fd == (samba_fd) (-1)){
	int			i, show_hidden_hosts;
	struct smbitem		*dir;

	while(*path == '/') path++;
	if ((dir = smbitem_getdir(path)) == NULL) return -EBADF;

	error = EINVAL;
	st.st_mode = S_IFDIR;
	if (filler(buf, ".",  &st, 0)) goto error0;
	if (filler(buf, "..", &st, 0)) goto error0;

	show_hidden_hosts = function_get_hidden_hosts_visibility();
	for(i = 0; i < dir->child_cnt; i++){
	    switch(dir->childs[i]->type){
		case SMBITEM_GROUP:
		    st.st_mode = S_IFDIR;
		    break;
		case SMBITEM_HOST:
		    st.st_mode = S_IFDIR;
		    if (! show_hidden_hosts) continue;
		    break;
		case SMBITEM_LINK:
		    st.st_mode = S_IFLNK;
		    break;
		default:
		    goto error0;
	    }
	    if (filler(buf, dir->childs[i]->name,  &st, 0)) goto end;
	}
	error = 0;

      error0:
	smbitem_release_dir(dir);
	return -error;
    }

    rec_cnt = 0;
    while(*path == '/') path++;

    while(1){
	int				count;
	char				readdir_buf[4096];
	char				name[1024];
	char				link[1024];
	struct smb_conn_dirent_rec	*rec;

	count = samba_readdir(fd, readdir_buf, sizeof(readdir_buf));
	if (count == 0) break;
	if (count < 0){
	    error = errno;
	    goto end;
	}

	rec = (struct smb_conn_dirent_rec *) readdir_buf;
	for( ; count >= (int) sizeof(struct smb_conn_dirent_rec);
			count -= sizeof(struct smb_conn_dirent_rec)){

	    if (strcmp(rec->d_name, "") == 0) goto next_record;
	    if (strcmp(rec->d_name, ".") == 0) goto next_record;
	    if (strcmp(rec->d_name, "..") == 0) goto next_record;

	    switch(rec->smbc_type){
		case SMBC_WORKGROUP:
		    error = EBADF;
		    goto end;

		case SMBC_SERVER:
		    st.st_mode = S_IFDIR;
		    snprintf(name, sizeof(name), "%s/%s", path, rec->d_name);
		    snprintf(link, sizeof(link), "../%s", rec->d_name);
		    smbitem_mkgroup(path, SMBITEM_SAMBA_TREE);
		    smbitem_mkhost(rec->d_name, path, 1, SMBITEM_SAMBA_TREE);
		    smbitem_mklink(name, link, SMBITEM_SAMBA_TREE);
		    break;

		case SMBC_FILE_SHARE:
		    st.st_mode = S_IFDIR;
		    if ((rec->d_name[strlen(rec->d_name) - 1] == '$') &&
			! function_get_dollar_share_visibility())
			    goto next_record;
		    break;

		case SMBC_DIR:
		    st.st_mode = S_IFDIR;
		    break;

		case SMBC_FILE:
		    st.st_mode = S_IFREG;
		    break;

		default:
		    goto next_record;
	    }
	    if (rec_cnt == 0){
		struct stat	st;

		error = EINVAL;
		memset(&st, 0, sizeof(st));
		st.st_mode = S_IFDIR;
		if (filler(buf, ".",  &st, 0)) goto end;
		if (filler(buf, "..", &st, 0)) goto end;
		rec_cnt += 2;
	    }
	    if (filler(buf, rec->d_name, &st, 0)){
		error = EINVAL;
		goto end;
	    }
	    rec_cnt++;

	  next_record:
	    rec++;
	}
    }

    if (rec_cnt == 0){
	error = EINVAL;
	st.st_mode = S_IFDIR;
	if (filler(buf, ".",  &st, 0)) goto end;
	if (filler(buf, "..", &st, 0)) goto end;
	rec_cnt += 2;
    }
    error = 0;

  end:
    return -error;
}

static int function_mkdir(const char *path, mode_t mode){
    DPRINTF(5, "(%s, %o)\n", path, mode);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;
    if (samba_mkdir(path, mode) != 0) return -errno;
    return 0;
}

static int function_rmdir(const char *path){
    DPRINTF(5, "(%s)\n", path);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;
    if (samba_rmdir(path) != 0) return -errno;
    return 0;
}

static int function_stat(const char *path, struct stat *stbuf){
    int			i, count;
    size_t		len;
    struct smbitem	*dir;
    char		buf[2048];

    DPRINTF(5, "(%s)\n", path);
    if (stat_workaround_is_name_ignored(path)) return -ENOENT;
    switch(smbitem_what_is(path)){
	case SMBITEM_SMBNETFS_DIR:
	    while(*path == '/') path++;

	    count = 2;
	    if ((dir = smbitem_getdir(path)) == NULL) return -EINVAL;
	    for(i = 0; i < dir->child_cnt; i++)
		switch(dir->childs[i]->type){
		    case SMBITEM_HOST:
		    case SMBITEM_GROUP:
			count++;
			break;
		    default:
			break;
		}
	    smbitem_release_dir(dir);

	    memset(stbuf, 0, sizeof(struct stat));
	    stbuf->st_mode = 0040777;	/* protection */
	    stbuf->st_nlink = count;	/* number of hard links */
	    stbuf->st_uid = 0;		/* user ID of owner */
	    stbuf->st_gid = 0;		/* group ID of owner */
	    stbuf->st_size = 0;		/* total size, in bytes */
	    stbuf->st_blksize = 4096;	/* blocksize for filesystem I/O */
	    return 0;

	case SMBITEM_SMBNETFS_LINK:
	    DPRINTF(5, "link:(%s)\n", path);
	    if (smbitem_readlink(path, buf, sizeof(buf)) != 0) return -EINVAL;
	    len = strlen(buf);

	    memset(stbuf, 0, sizeof(struct stat));
	    stbuf->st_mode = 0120777;	/* protection */
	    stbuf->st_nlink = 1;	/* number of hard links */
	    stbuf->st_uid = 0;		/* user ID of owner */
	    stbuf->st_gid = 0;		/* group ID of owner */
	    stbuf->st_size = len;	/* total size, in bytes */
	    stbuf->st_blksize = 4096;	/* blocksize for filesystem I/O */
	    return 0;

	case SMBITEM_SMB_NAME:
	case SMBITEM_SMB_SHARE:
	    memset(stbuf, 0, sizeof(struct stat));
	    stbuf->st_mode = 0040777;	/* protection */
	    stbuf->st_nlink = 2;	/* number of hard links */
	    stbuf->st_uid = 0;		/* user ID of owner */
	    stbuf->st_gid = 0;		/* group ID of owner */
	    stbuf->st_size = 0;		/* total size, in bytes */
	    stbuf->st_blksize = 4096;	/* blocksize for filesystem I/O */
	    return 0;

	case SMBITEM_SMB_SHARE_ITEM:
	    if (samba_stat(path, stbuf) != 0) return -errno;
	    return 0;

	default:
	    return -EINVAL;
    }
}

static int function_fstat(const char *path, struct stat *stbuf,
			struct fuse_file_info *fi){
    int			i, count;
    struct smbitem	*dir;
    samba_fd		fd;

    (void) path;

    DPRINTF(5, "(%s)\n", path);
    if ((fd = function_get_fd(fi)) == NULL) return -EBADF;
    if (fd == (samba_fd) (-1)){
	/* SMBNETFS_DIR */

	while(*path == '/') path++;

	count = 2;
	if ((dir = smbitem_getdir(path)) == NULL) return -EBADF;
	for(i = 0; i < dir->child_cnt; i++)
	    switch(dir->childs[i]->type){
		case SMBITEM_HOST:
		case SMBITEM_GROUP:
		    count++;
		    break;
		default:
		    break;
	    }
	smbitem_release_dir(dir);

	memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_mode = 0040777;	/* protection */
	stbuf->st_nlink = count;	/* number of hard links */
	stbuf->st_uid = 0;		/* user ID of owner */
	stbuf->st_gid = 0;		/* group ID of owner */
	stbuf->st_size = 0;		/* total size, in bytes */
	stbuf->st_blksize = 4096;	/* blocksize for filesystem I/O */
	return 0;
    }

    if (samba_fstat(fd, stbuf) != 0) return -errno;
    return 0;
}

static int function_ftruncate(const char *path, off_t size,
			struct fuse_file_info *fi){
    samba_fd	fd;

    DPRINTF(5, "(%s, %lld)\n", path, (long long) size);
    if (size < 0) return -EINVAL;
    if ((fd = function_get_fd(fi)) == NULL) return -EBADF;
    if (samba_ftruncate(fd, size) != 0) return -errno;
    return 0;
}

static int function_chmod(const char *path, mode_t mode){
    DPRINTF(5, "(%s, %o)\n", path, mode);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;
    if (samba_chmod(path, mode) != 0) return -errno;
    return 0;
}

static int function_utimes(const char *path, struct utimbuf *buffer){
    struct timeval	tbuf[2];

    DPRINTF(5, "(%s, %u)\n", path, (unsigned int)buffer->modtime);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;

    tbuf[0].tv_sec = buffer->actime;
    tbuf[0].tv_usec = 0;
    tbuf[1].tv_sec = buffer->modtime;
    tbuf[1].tv_usec = 0;

    if (samba_utimes(path, tbuf) != 0) return -errno;
    return 0;
}

/* libfuse does not support lsetxattr() and fsetxattr(), but samba does */
static int function_setxattr(const char *path, const char *name,
			    const char *value, size_t size, int flags){
    DPRINTF(5, "(%s, name=%s, value=%s, size=%zd, flags=%o)\n", path,
	name, value, size, flags);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -ENOTSUP;
    if (!function_check_xattr_name(name)) return -ENOTSUP;
    if (samba_setxattr(path, name, value, size, flags) != 0) return -errno;
    return 0;
}

/* libfuse does not support lgetxattr() and fgetxattr(), but samba does */
static int function_getxattr(const char *path, const char *name,
			    char *value, size_t size){
    DPRINTF(5, "(%s, name=%s, size=%zd)\n", path, name, size);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -ENOTSUP;
    if (!function_check_xattr_name(name)) return -ENOTSUP;
    if (samba_getxattr(path, name, value, size) != 0) return -errno;
    return 0;
}

/* libfuse does not support llistxattr() and flistxattr(), but samba does */
static int function_listxattr(const char *path, char *list, size_t size){
    DPRINTF(5, "(%s, size=%zd)\n", path, size);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -ENOTSUP;
    if (samba_listxattr(path, list, size) != 0) return -errno;
    return 0;
}

/* libfuse does not support lremovexattr() and fremovexattr(), but samba does */
static int function_removexattr(const char *path, const char *name){
    DPRINTF(5, "(%s, name=%s)\n", path, name);
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -ENOTSUP;
    if (!function_check_xattr_name(name)) return -ENOTSUP;
    if (samba_removexattr(path, name) != 0) return -errno;
    return 0;
}

static int function_readlink(const char *path, char *buf, size_t size){
    DPRINTF(5, "(%s, %zd)\n", path, size);
    if (smbitem_what_is(path) != SMBITEM_SMBNETFS_LINK) return -EINVAL;
    if (smbitem_readlink(path, buf, size) != 0) return -EINVAL;
    return 0;
}

static int function_mknod(const char *path, mode_t mode, dev_t rdev){
    samba_fd	fd;

    (void) rdev;

    DPRINTF(5, "(%s, %o)\n", path, mode);
    if ((mode & S_IFMT) != S_IFREG) return -EPERM;
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;
    if ((fd = samba_creat(path, mode)) == NULL) return -errno;
    if (samba_close(fd) != 0) return -errno;
    return 0;
}

static int function_chown(const char *path, uid_t uid, gid_t gid){
    (void) path;
    (void) uid;
    (void) gid;

    DPRINTF(5, "(%s, uid=%d, gid=%d)\n", path, uid, gid);
    if (function_get_quiet_flag()) return 0;
    else return -EPERM;
}

static int function_truncate(const char *path, off_t size){
    samba_fd	fd;

    DPRINTF(5, "(%s, %lld)\n", path, (long long) size);
    if (size < 0) return -EINVAL;
    if (smbitem_what_is(path) != SMBITEM_SMB_SHARE_ITEM) return -EINVAL;
    if ((fd = samba_open(path, O_RDWR, 0777)) == NULL) return -errno;
    if (samba_ftruncate(fd, size) != 0){
	int	error = errno;
	samba_close(fd);
	return -error;
    }
    if (samba_close(fd) != 0) return -errno;
    return 0;
}

static int function_statfs(const char *path, struct statvfs *stbuf){
    int	free_space_blocks;

    DPRINTF(5, "(%s)\n", path);

    free_space_blocks = function_get_free_space_size();
    memset(stbuf, 0, sizeof(struct statvfs));
    stbuf->f_bsize = 4096;
    stbuf->f_frsize = 4096;
    if (free_space_blocks > 0){
	stbuf->f_blocks = free_space_blocks;
	stbuf->f_bfree = free_space_blocks;
	stbuf->f_bavail = free_space_blocks;
	stbuf->f_ffree = 32768;
	stbuf->f_favail = 32768;
    }
    stbuf->f_namemax = FILENAME_MAX;
    return 0;
}

struct fuse_operations smb_oper = {
    .open	= function_open,
    .create	= function_creat,
    .read	= function_read,
    .write	= function_write,
    .release	= function_close,
    .unlink	= function_unlink,
    .rename	= function_rename,
    .opendir	= function_opendir,
    .releasedir	= function_closedir,
    .readdir	= function_readdir,
    .mkdir	= function_mkdir,
    .rmdir	= function_rmdir,
    .getattr	= function_stat,
    .fgetattr	= function_fstat,
    .ftruncate	= function_ftruncate,
    .chmod	= function_chmod,
    .utime	= function_utimes,
    .setxattr	= function_setxattr,
    .getxattr	= function_getxattr,
    .listxattr	= function_listxattr,
    .removexattr= function_removexattr,
    .readlink	= function_readlink,
    .mknod	= function_mknod,
    .chown	= function_chown,
    .truncate	= function_truncate,
    .statfs	= function_statfs,
//    .init	= function_init,	/* event.c */
//    .destroy	= function_destroy,	/* event.c */
//    .fsyncdir	= function_fsyncdir,
//    .access	= function_access,
};
