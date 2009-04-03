#ifndef __SMBITEM_H__
#define __SMBITEM_H__

#include <time.h>

enum smbitem_t{
    SMBITEM_LINK,
    SMBITEM_HOST,
    SMBITEM_GROUP
};

enum smbitem_tree_t{
    SMBITEM_USER_TREE,
    SMBITEM_SAMBA_TREE
};

enum smbitem_path_t{
    SMBITEM_UNKNOWN,
    SMBITEM_SMBNETFS_DIR,
    SMBITEM_SMBNETFS_LINK,
    SMBITEM_SMB_NAME,
    SMBITEM_SMB_SHARE,
    SMBITEM_SMB_SHARE_ITEM
};

struct smbitem{
    char			*name;		// item name
    enum smbitem_t		type;		// item type: comp/link/group
    time_t			touch_time;	// item touch time 
    int				ref_count;	// the number of item references
    union{
	struct{
	    int			is_hidden;	// host: is item hidden? 
	    struct smbitem	*parent_group;	// host: pointer parent group
	};
	struct{
	    int			child_cnt;	// group: subitems in group
	    int			max_child_cnt;	// group: maximum number of smbitems
	    struct smbitem	**childs;	// group: sorted list of subitems
	};
	struct{
	    char		*linkpath;		// link: link value
	};
    };
};

int                 smbitem_init(void);
void                smbitem_done(void);

int                 smbitem_mkgroup(const char *path,
				enum smbitem_tree_t tree);
int                 smbitem_mkhost(const char *path,
				const char *group, int is_hidden,
				enum smbitem_tree_t tree);
int                 smbitem_mklink(const char *path,
				const char *linkpath,
				enum smbitem_tree_t tree);

struct smbitem *    smbitem_getdir(const char *path);
struct smbitem *    smbitem_get_samba_groups(void);
void                smbitem_release_dir(struct smbitem *item);
void                smbitem_delete_obsolete(time_t threshold,
				enum smbitem_tree_t tree);

enum smbitem_path_t smbitem_what_is(const char *path);
int                 smbitem_readlink(const char *path, char *buf, size_t size);
int                 smbitem_get_group(const char *host, char *buf, size_t size);

#endif /* __SMBITEM_H__ */
