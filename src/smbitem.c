#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common.h"
#include "smbitem.h"

struct trees{
    struct smbitem	*samba;
    struct smbitem	*user;
};

struct trees	trees			= { NULL, NULL };
pthread_mutex_t m_smbitem		= PTHREAD_MUTEX_INITIALIZER;

struct smbitem* smbitem_new_host(const char *name, int is_hidden){
    struct smbitem	*item;

    item = malloc(sizeof(struct smbitem) + strlen(name) + 1);
    if (item == NULL) return NULL;

    memset(item, 0 , sizeof(struct smbitem));
    item->ref_count = 1;
    item->name = (char *) (item + 1);
    strcpy(item->name, name);
    item->type = SMBITEM_HOST;
    item->touch_time = time(NULL);
    item->is_hidden = is_hidden;
    return item;
}

struct smbitem* smbitem_new_group(const char *name){
    struct smbitem	*item;

    item = malloc(sizeof(struct smbitem) + strlen(name) + 1);
    if (item == NULL) return NULL;

    memset(item, 0 , sizeof(struct smbitem));
    item->ref_count = 1;
    item->name = (char *) (item + 1);
    strcpy(item->name, name);
    item->type = SMBITEM_GROUP;
    item->touch_time = time(NULL);
    return item;
}

struct smbitem* smbitem_new_link(const char *name, const char *linkpath){
    struct smbitem	*item;

    item = (struct smbitem*) malloc(sizeof(struct smbitem) +
	strlen(name) + strlen(linkpath) + 2);
    if (item == NULL) return NULL;

    memset(item, 0 , sizeof(struct smbitem));
    item->ref_count = 1;
    item->name = (char *) (item + 1);
    strcpy(item->name, name);
    item->type = SMBITEM_LINK;
    item->touch_time = time(NULL);
    item->linkpath = item->name + strlen(name) + 1;
    strcpy(item->linkpath, linkpath);
    return item;
}

static inline void smbitem_delete_item(struct smbitem *item){
    free(item);
}

static inline void smbitem_aquire_item(struct smbitem *item){
    item->ref_count++;
}

static void smbitem_release_item(struct smbitem *item){
    item->ref_count--;
    if (item->ref_count == 0){
	switch(item->type){
	    case SMBITEM_HOST:
		if (item->parent_group != NULL)
		    smbitem_release_item(item->parent_group);
		break;

	    case SMBITEM_GROUP:
		if (item->childs != NULL){
		    int		i;

		    for(i = 0; i < item->child_cnt; i++)
			smbitem_release_item(item->childs[i]);
		    free(item->childs);
		}
		break;

	    case SMBITEM_LINK:
		break;

	    default:
		DPRINTF(0, "ERROR: item '%s' is damaged\n", item->name);
		return;
	}
	smbitem_delete_item(item);
    }
}

void smbitem_delete_obsolete_items(struct smbitem *group, time_t threshold){
    int		i;

    for(i = group->child_cnt - 1; i >= 0; i--){
	if (group->childs[i]->type == SMBITEM_GROUP){
	    smbitem_delete_obsolete_items(group->childs[i], threshold);
	}
	if (group->childs[i]->touch_time < threshold){
	    smbitem_release_item(group->childs[i]);
	    if (i != group->child_cnt - 1){
		memmove(&group->childs[i],
			&group->childs[i + 1],
			(group->child_cnt - i - 1) * sizeof(struct smbitem *));
	    }
	    group->child_cnt--;
	}
    }
}

/*
 * This function search for an item in specified SMBNetFS group,
 * group items MUST be sorted alphabetically, so we can bisect.
 * 'first' is the search starting position (usually zero)
 *
 * return:
 *   a) item position, if item with specified name was found
 *   b) negative value -(pos+1), if item was not found,
 *      where 'pos' is the position to insert the new element
 */
int smbitem_find_in_group_wl(struct smbitem *group, const char *name,
				size_t name_len, int first){
    int	last = group->child_cnt - 1;

    while(first <= last){
	int i		= (first + last) >> 1;
	int result	= strncasecmp(group->childs[i]->name, name, name_len);

	if ((result == 0) &&
	    (group->childs[i]->name[name_len] == '\0')) return i;
	if (result < 0) first = i + 1;
	else last = i - 1;
    }
    return -(first + 1);
}

inline int smbitem_find_in_group(struct smbitem *group, const char *name, int first){
    return smbitem_find_in_group_wl(group, name, strlen(name), first);
}

/*
 * This function insert an element to specified SMBNetFS group,
 * insert position MUST be obtained with smbitem_find_in_group().
 *
 * return:
 *   a) zero, if no errors
 *   b) (-1), if insertion failed
 */
int smbitem_insert_to_group(struct smbitem *group, struct smbitem *item, int pos){
    if ((pos > group->child_cnt) || (pos < 0)) return -1;

    if (group->max_child_cnt == group->child_cnt){
	struct smbitem	**new_childs;
	int		new_max_cnt;

	new_max_cnt = (group->max_child_cnt == 0) ?
			64 : 2 * group->max_child_cnt;
	new_childs = realloc(group->childs,
			new_max_cnt * sizeof(struct smbitem *));
	if (new_childs == NULL) return -1;

	group->max_child_cnt = new_max_cnt;
	group->childs = new_childs;
    }

    if (pos < group->child_cnt){
	memmove(&group->childs[pos + 1],
		&group->childs[pos],
		(group->child_cnt - pos) * sizeof(struct smbitem *));
    }
    group->childs[pos] = item;
    group->child_cnt++;
    group->touch_time = time(NULL);
    return 0;
}

int smbitem_init(void){
    int		result = -1;

    pthread_mutex_lock(&m_smbitem);
	if ((trees.samba  = smbitem_new_group("/")) == NULL) goto error;
	if ((trees.user   = smbitem_new_group("/")) == NULL){
	    smbitem_release_item(trees.samba);
	    trees.samba = NULL;
	    goto error;
	}
	result = 0;
      error:
    pthread_mutex_unlock(&m_smbitem);
    return result;
}

void smbitem_done(void){
    pthread_mutex_lock(&m_smbitem);
    smbitem_release_item(trees.samba);
    smbitem_release_item(trees.user);
    trees.samba = trees.user = NULL;
    pthread_mutex_unlock(&m_smbitem);
}

int smbitem_mkgroup(const char *path, enum smbitem_tree_t tree){
    int			pos, result;
    struct smbitem	*dir;

    DPRINTF(6, "path=%s, tree=%d\n", path, tree);

    dir = (tree == SMBITEM_SAMBA_TREE) ? trees.samba : trees.user;

    if ((path == NULL) || (*path == '\0') ||
	(strchr(path, '/') != NULL) ||
	(strcmp(path, ".")  == 0) ||
	(strcmp(path, "..") == 0)) return -1;

    result = -1;
    pthread_mutex_lock(&m_smbitem);
	pos = smbitem_find_in_group(dir, path, 0);
	if (pos >= 0){
	    if (dir->childs[pos]->type == SMBITEM_GROUP){
		/* group already exist, touch it */
		dir->childs[pos]->touch_time = time(NULL);
	    }else{
		/* replace founded item with a new group */
		struct smbitem *item = smbitem_new_group(path);
		if (item == NULL) goto error;

		smbitem_release_item(dir->childs[pos]);
		dir->childs[pos] = item;
	    }
	}else{
	    /* create new group and add it to a directory */
	    struct smbitem *item = smbitem_new_group(path);
	    if (item == NULL) goto error;
	    if (smbitem_insert_to_group(dir, item, -(pos + 1)) != 0){
		smbitem_release_item(item);
		goto error;
	    }
	}
	dir->touch_time = time(NULL);
	result = 0;
      error:
    pthread_mutex_unlock(&m_smbitem);
    return result;
}

int smbitem_mkhost(const char *path, const char *group,
		int is_hidden, enum smbitem_tree_t tree){

    int			pos, result;
    struct smbitem	*dir, *item, *parent_group;

    DPRINTF(6, "path=%s, group=%s, is_hidden=%d, tree=%d\n",
	path, group, is_hidden, tree);

    dir = (tree == SMBITEM_SAMBA_TREE) ? trees.samba : trees.user;

    if ((path == NULL) || (*path == '\0') ||
	(strchr(path, '/') != NULL) ||
	(strcmp(path, ".")  == 0) ||
	(strcmp(path, "..") == 0)) return -1;

    if (group != NULL){
	if ((strchr(group, '/') != NULL) ||
	    (strcmp(group, ".")  == 0) ||
	    (strcmp(group, "..") == 0)) return -1;
    }

    result = -1;
    pthread_mutex_lock(&m_smbitem);
	if (group != NULL){
	    pos = smbitem_find_in_group(dir, group, 0);
	    if ((pos < 0) || (dir->childs[pos]->type != SMBITEM_GROUP)){
		DPRINTF(5, "ERROR: group '%s' was not found\n", group);
		goto error;
	    }
	    parent_group = dir->childs[pos];
	}else parent_group = NULL;

	pos = smbitem_find_in_group(dir, path, 0);
	if (pos >= 0){
	    if (dir->childs[pos]->type == SMBITEM_HOST){
		/* host already exist, update it */
		item = dir->childs[pos];
		if ((item->parent_group != NULL) &&
		    (item->parent_group != parent_group)){

		    smbitem_release_item(item->parent_group);
		    item->parent_group = NULL;
		}
		item->is_hidden = is_hidden;
		item->touch_time = time(NULL);
	    }else{
		/* replace founded item with a new host */
		item = smbitem_new_host(path, is_hidden);
		if (item == NULL) goto error;

		smbitem_release_item(dir->childs[pos]);
		dir->childs[pos] = item;
	    }
	}else{
	    /* create new host and add it to a directory */
	    item = smbitem_new_host(path, is_hidden);
	    if (item == NULL) goto error;
	    if (smbitem_insert_to_group(dir, item, -(pos + 1)) != 0){
		smbitem_release_item(item);
		goto error;
	    }
	}
	if (parent_group != NULL){
	    smbitem_aquire_item(parent_group);
	    parent_group->touch_time = time(NULL);
	    item->parent_group = parent_group;
	}
	dir->touch_time = time(NULL);
	result = 0;
      error:
    pthread_mutex_unlock(&m_smbitem);
    return result;
}

int smbitem_mklink(const char *path, const char *linkpath, enum smbitem_tree_t tree){
    int			pos, result;
    size_t		dirname_len;
    const char		*tmp, *dirname;
    struct smbitem	*dir;

    DPRINTF(6, "path=%s, linkpath=%s, tree=%d\n", path, linkpath, tree);

    dir = (tree == SMBITEM_SAMBA_TREE) ? trees.samba : trees.user;

    if ((linkpath == NULL) || (*linkpath == '\0')) return -1;
    if ((path == NULL) || (*path == '\0')) return -1;

    if ((tmp = strchr(path, '/')) != NULL){
	dirname = path;
	dirname_len = tmp - path;
	path = tmp + 1;
    }else{
	dirname = NULL;
	dirname_len = 0;
    }

    if ((*path == '\0') ||
	(strchr(path, '/') != NULL) ||
	(strcmp(path, ".")  == 0) ||
	(strcmp(path, "..") == 0)){

	return -1;
    }

    result = -1;
    pthread_mutex_lock(&m_smbitem);
	if (dirname != NULL){
	    pos = smbitem_find_in_group_wl(dir, dirname, dirname_len, 0);
	    if ((pos < 0) || (dir->childs[pos]->type != SMBITEM_GROUP)){
		DPRINTF(5, "ERROR: group '%.*s' was not found\n",
		    (int) dirname_len, dirname);
		goto error;
	    }
	    dir = dir->childs[pos];
	}

	pos = smbitem_find_in_group(dir, path, 0);
	if (pos >= 0){
	    if ((dir->childs[pos]->type == SMBITEM_LINK) &&
		(strcmp(dir->childs[pos]->linkpath, linkpath) == 0)){

		/* link already exist, update it */
		dir->childs[pos]->touch_time = time(NULL);
	    }else{
		/* replace founded item with a new link */
		struct smbitem *item = smbitem_new_link(path, linkpath);
		if (item == NULL) goto error;

		smbitem_release_item(dir->childs[pos]);
		dir->childs[pos] = item;
	    }
	}else{
	    /* create new link and add it to a directory */
	    struct smbitem *item = smbitem_new_link(path, linkpath);
	    if (item == NULL) goto error;
	    if (smbitem_insert_to_group(dir, item, -(pos + 1)) != 0){
		smbitem_release_item(item);
		goto error;
	    }
	}
	dir->touch_time = time(NULL);
	result = 0;
      error:
    pthread_mutex_unlock(&m_smbitem);
    return result;
}

struct smbitem * smbitem_get_samba_groups(void){
    int			i;
    struct smbitem	*dir;

    dir = NULL;
    pthread_mutex_lock(&m_smbitem);
	/* create new group */
	dir = smbitem_new_group("/");
	if (dir == NULL) goto end;

	/* add samba groups only */
	for(i = 0; i < trees.samba->child_cnt; i++){
	    if (trees.samba->childs[i]->type != SMBITEM_GROUP) continue;
	    if (smbitem_insert_to_group(dir,
			trees.samba->childs[i], dir->child_cnt) != 0) goto error;
	    smbitem_aquire_item(trees.samba->childs[i]);
	}
	goto end;

      error:
        if (dir != NULL) smbitem_release_item(dir);
        dir = NULL;
      end:
    pthread_mutex_unlock(&m_smbitem);
    return dir;
}

struct smbitem * smbitem_getdir(const char *path){
    int			i, pos;
    struct smbitem	*dir_user, *dir_samba, *dir;

    if ((path == NULL) ||
	(strchr(path, '/') != NULL) ||
	(strcmp(path, ".")  == 0) ||
	(strcmp(path, "..") == 0)) return NULL;

    dir = NULL;
    pthread_mutex_lock(&m_smbitem);
	if (*path != '\0'){
	    /* find dir in user configured tree */
	    dir_user = NULL;
	    pos = smbitem_find_in_group(trees.user, path, 0);
	    if (pos >= 0){
		if (trees.user->childs[pos]->type == SMBITEM_GROUP){
		    dir_user = trees.user->childs[pos];
		}else{
		    DPRINTF(5, "ERROR: '%s' is not a group\n", path);
		    goto error;
		}
	    }

	    /* find dir in samba scanned tree */
	    dir_samba = NULL;
	    pos = smbitem_find_in_group(trees.samba, path, 0);
	    if (pos >= 0){
		if (trees.samba->childs[pos]->type == SMBITEM_GROUP){
		    dir_samba = trees.samba->childs[pos];
		}else if (dir_user == NULL){
		    DPRINTF(5, "ERROR: '%s' is not a group\n", path);
		    goto error;
		}
	    }
	}else{
	    dir_user = trees.user;
	    dir_samba = trees.samba;
	}

	/* create new group */
	dir = smbitem_new_group(path);
	if (dir == NULL) goto error;

	/* copy contents of dir_user to dir */
	if ((dir_user != NULL) && (dir_user->child_cnt > 0)){
	    dir->childs = malloc(dir_user->max_child_cnt * sizeof(struct smbitem *));
	    if (dir->childs == NULL) goto error;

	    dir->max_child_cnt = dir_user->max_child_cnt;
	    dir->child_cnt = dir_user->child_cnt;
	    memcpy(dir->childs, dir_user->childs,
		dir_user->child_cnt * sizeof(struct smbitem *));

	    for(i = 0; i < dir_user->child_cnt; i++)
		smbitem_aquire_item(dir->childs[i]);
	}

	/* merge with dir_samba */
	if ((dir_samba != NULL) && (dir_samba->child_cnt > 0)){
	    pos = 0;
	    for(i = 0; i < dir_samba->child_cnt; i++){
		pos = smbitem_find_in_group(dir, dir_samba->childs[i]->name, pos);
		if (pos < 0){
		    pos = -(pos + 1);
		    if (smbitem_insert_to_group(dir, dir_samba->childs[i], pos) != 0)
			goto error;
		    smbitem_aquire_item(dir_samba->childs[i]);
		}
		pos++;
	    }
	}
	goto end;

      error:
        if (dir != NULL) smbitem_release_item(dir);
        dir = NULL;
      end:
    pthread_mutex_unlock(&m_smbitem);
    return dir;
}

void smbitem_release_dir(struct smbitem *item){
    if (item->type != SMBITEM_GROUP){
	DPRINTF(5, "ERROR: item is not a group\n");
	return;
    }
    pthread_mutex_lock(&m_smbitem);
	smbitem_release_item(item);
    pthread_mutex_unlock(&m_smbitem);
}

void smbitem_delete_obsolete(time_t threshold, enum smbitem_tree_t tree){
    struct smbitem	*dir;

    DPRINTF(6, "threshold=%d, tree=%d\n", (int)threshold, tree);

    dir = (tree == SMBITEM_SAMBA_TREE) ? trees.samba : trees.user;

    pthread_mutex_lock(&m_smbitem);
	smbitem_delete_obsolete_items(dir, threshold);
    pthread_mutex_unlock(&m_smbitem);
}

inline const char * smbitem_get_path_end(const char *path){
    const char *next = strchr(path, '/');
    return (next != NULL) ? next : path + strlen(path);
}

enum smbitem_path_t smbitem_what_is(const char *path){
    int			pos;
    struct smbitem	*dir, *tmp_dir;
    const char		*next;

    if (path == NULL) return SMBITEM_UNKNOWN;

    DPRINTF(6, "path=%s\n", path);

    while(*path == '/') path++;
    if (*path == '\0') return SMBITEM_SMBNETFS_DIR;
    next = smbitem_get_path_end(path);

    if ((dir = smbitem_getdir("")) == NULL) return SMBITEM_UNKNOWN;

    if ((pos = smbitem_find_in_group_wl(dir, path, next - path, 0)) >= 0){
	switch(dir->childs[pos]->type){
	    case SMBITEM_HOST:
		goto smbitem_host;

	    case SMBITEM_GROUP:
		while(*next == '/') next++;
		if (*next == '\0') goto smbitem_smbnetfs_dir;

		tmp_dir = smbitem_getdir(dir->childs[pos]->name);
		if (tmp_dir == NULL) goto error;

		smbitem_release_dir(dir);
		dir = tmp_dir;
		path = next;
		next = smbitem_get_path_end(next);

		pos = smbitem_find_in_group_wl(dir, path, next - path, 0);
		if (pos < 0) goto error;
		if (dir->childs[pos]->type != SMBITEM_LINK) goto error;

	    case SMBITEM_LINK:
		goto smbitem_smbnetfs_link;

	    default:
		goto error;
	}
    }

  smbitem_host:
    smbitem_release_dir(dir);

    while(*next == '/') next++;
    if (*next == '\0') return SMBITEM_SMB_NAME;
    next = smbitem_get_path_end(next);

    while(*next == '/') next++;
    if (*next == '\0') return SMBITEM_SMB_SHARE;
    return SMBITEM_SMB_SHARE_ITEM;

  smbitem_smbnetfs_dir:
    if (*next != '\0') goto error;
    smbitem_release_dir(dir);
    return SMBITEM_SMBNETFS_DIR;

  smbitem_smbnetfs_link:
    if (*next != '\0') goto error;
    smbitem_release_dir(dir);
    return SMBITEM_SMBNETFS_LINK;

  error:
    smbitem_release_dir(dir);
    return SMBITEM_UNKNOWN;
}

int smbitem_readlink(const char *path, char *buf, size_t size){
    int			pos;
    struct smbitem	*dir, *tmp_dir;
    const char		*next;

    if (path == NULL) return -1;

    DPRINTF(6, "path=%s\n", path);

    while(*path == '/') path++;
    if (*path == '\0') return -1;
    next = smbitem_get_path_end(path);

    if ((dir = smbitem_getdir("")) == NULL) return -1;

    if ((pos = smbitem_find_in_group_wl(dir, path, next - path, 0)) >= 0){
	switch(dir->childs[pos]->type){
	    case SMBITEM_GROUP:
		while(*next == '/') next++;
		if (*next == '\0') goto error;

		tmp_dir = smbitem_getdir(dir->childs[pos]->name);
		if (tmp_dir == NULL) goto error;

		smbitem_release_dir(dir);
		dir = tmp_dir;
		path = next;
		next = smbitem_get_path_end(next);

		pos = smbitem_find_in_group_wl(dir, path, next - path, 0);
		if (pos < 0) goto error;
		if (dir->childs[pos]->type != SMBITEM_LINK) goto error;

	    case SMBITEM_LINK:
		if (*next != '\0') goto error;
		strncpy(buf, dir->childs[pos]->linkpath, size);
		buf[size - 1] = '\0';
		smbitem_release_dir(dir);
		return 0;

	    default:
		goto error;
	}
    }

  error:
    smbitem_release_dir(dir);
    return -1;
}

int smbitem_get_group(const char *host, char *buf, size_t size){
    int			pos, result;
    struct smbitem	*item;

    if (host == NULL) return -1;

    DPRINTF(6, "group=%s\n", host);

    while(*host == '/') host++;
    if (*host == '\0') return -1;
    if ((strcmp(host, ".") == 0) || (strcmp(host, "..") == 0)) return -1;

    result = -1;
    pthread_mutex_lock(&m_smbitem);
	item = trees.user;
	if ((pos = smbitem_find_in_group(item, host, 0)) >= 0) goto ok;
	item = trees.samba;
	if ((pos = smbitem_find_in_group(item, host, 0)) <  0) goto end;

      ok:
	item = item->childs[pos];
	if (item->type != SMBITEM_HOST) goto end;
	if (item->parent_group == NULL) goto end;

	item = item->parent_group;
	strncpy(buf, item->name, size);
	buf[size - 1] = '\0';
	result = 0;

      end:
    pthread_mutex_unlock(&m_smbitem);
    return result;
}
