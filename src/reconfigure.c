#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

#include "common.h"
#include "smbitem.h"
#include "auth.h"
#include "process.h"
#include "smb_conn.h"
#include "samba.h"
#include "function.h"
#include "event.h"
#include "reconfigure.h"

#define FIELD_MAX	4
#define PATTERN_SIZE	20
#define LINE_SIZE	200

enum config_read_mode{
    DELIMITER,
    PLAIN,
    QUOTED
};

const char	*config_dir_postfix	= "/.smb/";
const char	*config_file		= "smbnetfs.conf";
char		config_dir[2048]	= "/";

void reconfigure_set_config_dir(const char *path){
    struct stat buf;

    if (strlen(path) + 2 > sizeof(config_dir)){
	DPRINTF(5, "path too long\n");
	return;
    }
    strcpy(config_dir, path);
    if (path[strlen(path) - 1] != '/') strcat(config_dir, "/");
    if ((stat(config_dir, &buf) == 0) && S_ISDIR(buf.st_mode)){
	DPRINTF(5, "config_dir=%s\n", config_dir);
	return;
    }
    fprintf(stderr,
	"WARNING!!! Configuration directory ~%s is not found. Please create it.\n"
	"This directory should contain at least two files: smb.conf and smbnetfs.conf.\n"
	"You may copy smb.conf from the /etc/samba directory. You can find a sample of\n"
	"smbnetfs.conf in the doc directory of original SMBNetFS distribution.\n\n"
	"Using default settings for now.\n", config_dir_postfix);
}

void set_default_login_and_configdir(void){
    char			buf[1024];
    register struct passwd	*pwd;
    const char			*home, *user, *dir;

    pwd = getpwuid(getuid());

    user = getenv("USER");
    if ((user == NULL) || (*user == '\0')) user = getenv("LOGNAME");
    if ((user == NULL) || (*user == '\0')){
	user = ((pwd != NULL) && 
	        (pwd->pw_name != NULL) &&
	        (pwd->pw_name != '\0')) ? pwd->pw_name : "anonymous";
	setenv("USER", user, 1);
	setenv("LOGNAME", user, 1);
    }
    auth_set_default_login_name(user);

    home = getenv("HOME");
    if ((home == NULL) || (*home != '/')){
	home = ((pwd != NULL) && 
	        (pwd->pw_dir  != NULL) &&
	        (*pwd->pw_dir == '/')) ? pwd->pw_dir : "/";
	setenv("HOME", home, 1);
    }

    dir = config_dir_postfix;
    if (strlen(home) + strlen(dir) + 1 > sizeof(buf)) home = "/";
    strcpy(buf, home);
    strcat(buf, (home[strlen(home) - 1] == '/') ? dir + 1 : dir);
    reconfigure_set_config_dir(buf);
}

int reconfigure_get_number(char *value, int *result){
    char *endptr;

    *result = strtol(value, &endptr, 0);
    if (*endptr == '\0') return 1;
    else return 0;
}

int reconfigure_set_number(char *value, int (*func)(int)){
    int result;

    if (reconfigure_get_number(value, &result)) return func(result);
    else return 0;
}

int reconfigure_get_size(char *value, size_t *result){
    char *endptr;

    *result = strtol(value, &endptr, 0);
    if (*endptr == '\0') return 1;
    else return 0;
}

int reconfigure_set_size(char *value, int (*func)(size_t)){
    size_t result;

    if (reconfigure_get_size(value, &result)) return func(result);
    else return 0;
}

int reconfigure_set_kb_size(char *value, int (*func)(size_t)){
    size_t result;

    if (reconfigure_get_size(value, &result)) return func(result * 1024);
    else return 0;
}

int reconfigure_get_boolean(char *value, int *result){
    if ((strcasecmp(value, "true") == 0) || (strcasecmp(value, "yes") == 0)){
	*result = 1;
	return 1;
    }
    if ((strcasecmp(value, "false") == 0) || (strcasecmp(value, "no") == 0)){
	*result = 0;
	return 1;
    }
    return 0;
}

int reconfigure_set_boolean(char *value, int (*func)(int)){
    int result;

    if (reconfigure_get_boolean(value, &result)) return func(result);
    else return 0;
}

int reconfigure_split_line(const char *line,
				char *arg[], size_t arg_len[], int arg_cnt){

    enum config_read_mode	mode;
    const char			*orig_line;
    char			quote_char;
    size_t			cur_arg_len;
    int				cnt;

    for(cnt = 0; cnt < arg_cnt; cnt++) memset(arg[cnt], 0, arg_len[cnt]);

    cnt = 0;
    orig_line = line;
    mode = DELIMITER;
    cur_arg_len = 0;
    quote_char = '\0';
    while(1){
	switch(mode){
	    case DELIMITER:
		if ((*line == '\0') || (*line == '#')) return cnt;
		if ((*line == '\t') || (*line == ' ')){
		    line++;
		    continue;
		}
		mode = PLAIN;
		cur_arg_len = 0;
		if ((*line == '\'') || (*line == '"')){
		    mode = QUOTED;
		    quote_char = *line++;
		}
		continue;

	    case PLAIN:
		if (*line == '\0') return cnt + 1;
		if ((*line == '\t') || (*line == ' ')){
		    mode = DELIMITER;
		    cnt++;
		    continue;
		}
		break;

	    case QUOTED:
		if (*line == '\0') return -(line - orig_line + 1);
		if (*line == quote_char){
		    line++;
		    if ((*line != ' ' ) &&
			(*line != '\t') &&
			(*line != '\0')) return -(line - orig_line + 1);;
		    mode = DELIMITER;
		    cnt++;
		    continue;
		}
		if ((*line == '\\') &&
		    ((*(line + 1) == '\\') ||
		     (*(line + 1) == quote_char))) line++;
		break;

	    default:
		return -(line - orig_line + 1);
	}

	if (cnt < arg_cnt){
	    if (cur_arg_len + 1 >= arg_len[cnt]) return -(line - orig_line + 1);
	    arg[cnt][cur_arg_len++] = *line;
	}
	line++;
    }
    return -1;
}

int reconfigure_read_config_file(const char *filename, int startup){
    FILE	*file;
    int		cnt, ok_permission;
    char	s[LINE_SIZE];
    char	pattern[PATTERN_SIZE];
    char	fields[FIELD_MAX][LINE_SIZE], *arg[FIELD_MAX];
    size_t	arg_len[FIELD_MAX];
    struct stat	st;

    if ((filename == NULL) || (*filename == '\0')){
	errno = EINVAL;
	return -1;
    }
    if (*filename == '/'){
	if ((filename = strdup(filename)) == NULL) return -1;
    }else{
	char *tmp = malloc(strlen(config_dir) + strlen(filename) + 1);
	if (tmp == NULL) return -1;
	strcpy(tmp, config_dir);
	strcat(tmp, filename);
	filename = tmp;
    }

    for(cnt = 0; cnt < FIELD_MAX; cnt++){
	arg[cnt]     = fields[cnt];
	arg_len[cnt] = LINE_SIZE;
    }
    snprintf(pattern, sizeof(pattern), "%%%d[^\n]\n", (int) sizeof(s) - 1);

    DPRINTF(7, "reading file: %s\n", filename);
    if ((file = fopen(filename, "r")) == NULL){
	int error = errno;
	DPRINTF(3, "Open file %s error : %s.\n", filename, strerror(error));
	free((char *) filename);
	errno = error;
	return -1;
    }

    ok_permission = 0;
    if (fstat(fileno(file), &st) == 0)
	ok_permission = ((st.st_uid == getuid()) && ((st.st_mode & 0177) == 0));
    else DPRINTF(3, "Stat file %s error : %s\n", filename, strerror(errno));

    fscanf(file, "%[\n]", s);
    while(!feof(file)){
	memset(s, 0, sizeof(s));
	fscanf(file, pattern, s);
	cnt = reconfigure_split_line(s, arg, arg_len, FIELD_MAX);
	if (cnt < 0){
	    DPRINTF(0, "Error: (file: %s), Syntax error at pos=%d in line : %s\n", filename, -(cnt + 1), s);
	    continue;
	}
	if (cnt == 0) continue;

	if (cnt == 2){
	    if (strcasecmp(arg[0], "include") == 0){
		reconfigure_read_config_file(arg[1], startup);
		continue;
	    }

	    /* common.h */
	    if (strcasecmp(arg[0], "smbnetfs_debug") == 0)
		if (reconfigure_set_number(arg[1],
				common_set_smbnetfs_debug_level)) continue;
	    if (strcasecmp(arg[0], "log_file") == 0)
		if (common_set_log_file(arg[1])) continue;

	    /* process.h */
	    if (strcasecmp(arg[0], "listen_timeout") == 0)
		if (reconfigure_set_number(arg[1],
				process_set_server_listen_timeout)) continue;
	    if (strcasecmp(arg[0], "smb_debug_level") == 0)
		if (reconfigure_set_number(arg[1],
				process_set_server_smb_debug_level)) continue;
	    if (strcasecmp(arg[0], "local_charset") == 0)
		if (process_set_server_local_charset(arg[1])) continue;
	    if (strcasecmp(arg[0], "samba_charset") == 0)
		if (process_set_server_samba_charset(arg[1])) continue;

	    /* smb_conn.h */
	    if (strcasecmp(arg[0], "max_retry_count") == 0)
		if (reconfigure_set_number(arg[1],
				smb_conn_set_max_retry_count)) continue;
	    if (strcasecmp(arg[0], "max_passwd_query_count") == 0)
		if (reconfigure_set_number(arg[1],
				smb_conn_set_max_passwd_query_count)) continue;
	    if (strcasecmp(arg[0], "reply_timeout") == 0)
		if (reconfigure_set_number(arg[1],
				smb_conn_set_server_reply_timeout)) continue;

	    /* samba.h */
	    if (strcasecmp(arg[0], "max_rw_block_size") == 0){
		if (startup){
		    if (reconfigure_set_kb_size(arg[1], samba_init)) continue;
		}else continue;
	    }
	    if (strcasecmp(arg[0], "max_ctx_count") == 0)
		if (reconfigure_set_number(arg[1],
				samba_set_max_ctx_count)) continue;

	    /* event.h */
	    if (strcasecmp(arg[0], "time_step") == 0)
		if (reconfigure_set_number(arg[1],
				event_set_time_step)) continue;
	    if (strcasecmp(arg[0], "smb_tree_scan_period") == 0)
		if (reconfigure_set_number(arg[1],
				event_set_smb_tree_scan_period)) continue;
	    if (strcasecmp(arg[0], "smb_tree_elements_ttl") == 0)
		if (reconfigure_set_number(arg[1],
				event_set_smb_tree_elements_ttl)) continue;
	    if (strcasecmp(arg[0], "config_update_period") == 0)
		if (reconfigure_set_number(arg[1],
				event_set_config_update_period)) continue;
	    if (strcasecmp(arg[0], "smb_query_browsers") == 0)
		if (reconfigure_set_boolean(arg[1],
				event_set_query_browser_flag)) continue;

	    /* function.h */
	    if (strcasecmp(arg[0], "free_space_size") == 0)
		if (reconfigure_set_size(arg[1],
				function_set_free_space_size)) continue;
	    if (strcasecmp(arg[0], "quiet_flag") == 0)
		if (reconfigure_set_boolean(arg[1],
				function_set_quiet_flag)) continue;
	    if (strcasecmp(arg[0], "show_$_shares") == 0)
		if (reconfigure_set_boolean(arg[1],
				function_set_dollar_share_visibility)) continue;
	    if (strcasecmp(arg[0], "show_hidden_hosts") == 0)
		if (reconfigure_set_boolean(arg[1],
				function_set_hidden_hosts_visibility)) continue;
	    if (strcasecmp(arg[0], "stat_workaround_depth") == 0)
		if (reconfigure_set_number(arg[1],
				function_set_stat_workaround_depth)) continue;
	}
	if ((cnt >= 3) && (cnt <= 4) && (strcasecmp(arg[0], "auth") == 0)){
	    char	*comp, *share;
	    char	*domain, *user, *password;
	    int		shift;

	    if (!ok_permission) goto insecure_permission;

	    /* server and share */
	    if (cnt == 4){
		if (*arg[1] == '/') goto error;

		shift = 1;
		comp = arg[1];
		if ((share = strchr(comp, '/')) == NULL){
		    share = "";
		}else{
		    *share++ = '\0';
		    if ((*share == '\0') || (strchr(share, '/') != NULL))
			goto error;
		}
	    }else{
		comp = "";
		share = "";
		shift = 0;
	    };

	    /* domain and user */
	    if (*arg[1 + shift] == '/') goto error;
	    domain = "";
	    if ((user = strchr(arg[1 + shift], '/')) == NULL){
		user = arg[1 + shift];
	    }else{
		domain = arg[1 + shift];
		*user++ = '\0';
		if ((*user == '\0') || (strchr(user, '/') != NULL))
		    goto error;
	    }

	    /* password */
	    password = arg[2 + shift];

	    if (auth_store_auth_data(comp, share, domain, user, password) == 0)
		continue;
	}
	if ((cnt >= 2) && (cnt <= 4) && (strcasecmp(arg[0], "host") == 0)){
	    const char	*group_ptn	= "parent_group=";
	    const char	*visible_ptn	= "visible=";
	    char	*parent_group;
	    int		i, visibility;
	    size_t	len;

	    if (!ok_permission) goto insecure_permission;
	    if (strchr(arg[1], '/') != NULL) goto error;

	    parent_group = NULL;
	    visibility = -1;
	    for(i = 2; i < cnt; i++){
		len = strlen(group_ptn);
		if (strncasecmp(arg[i], group_ptn, len) == 0){
		    if (parent_group != NULL) goto error;
		    parent_group = arg[i] + len;
		    if ((*parent_group == '\0') ||
			(strchr(parent_group, '/') != NULL)) goto error;
		}
		len = strlen(visible_ptn);
		if (strncasecmp(arg[i], visible_ptn, len) == 0){
		    if (visibility != -1) goto error;
		    if (! reconfigure_get_boolean(arg[i] + len, &visibility))
			goto error;
		}
	    }
	    if (visibility == -1) visibility = 1;

	    if (smbitem_mkhost(arg[1], parent_group,
		visibility, SMBITEM_USER_TREE) == 0) continue;
	}
	if ((cnt == 2) && (strcasecmp(arg[0], "group") == 0)){
	    if (!ok_permission) goto insecure_permission;
	    if (strchr(arg[1], '/') != NULL) goto error;

	    if (smbitem_mkgroup(arg[1], SMBITEM_USER_TREE) == 0) continue;
	}
	if ((cnt >= 2) && (cnt <= 3) && (strcasecmp(arg[0], "link") == 0)){
	    char	*name;

	    if (!ok_permission) goto insecure_permission;
	    if (*arg[1] == '/') goto error;

	    name = strchr(arg[1], '/');
	    if (name == NULL){
		if (*arg[2] == '\0') goto error;
	    }else{
		name++;
		if ((*name == '\0') || (strchr(name, '/') != NULL)) goto error;
	    }

	    if (*arg[2] == '\0'){
		if (strlen(name) + 4 > arg_len[2]) goto error;
		strcpy(arg[2], "../");
		strcat(arg[2], name);
	    }
	    if (smbitem_mklink(arg[1], arg[2], SMBITEM_USER_TREE) == 0)
		continue;
	}

      error:
	DPRINTF(0, "Error: (file: %s) Invalid input line : %s\n", filename, s);
	continue;
	
      insecure_permission:
	DPRINTF(0, "Error: Insecure config file permission.\n"
	    "Can't apply '%s' directive.\n"
	    "Run 'chmod 600 %s' to fix it.\n", arg[0], filename);
        continue;
    }
    fclose(file);
    free((char *) filename);
    return 0;
}
