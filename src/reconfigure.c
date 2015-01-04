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
#include "auth-gnome-keyring.h"
#include "auth.h"
#include "process.h"
#include "smb_conn.h"
#include "samba.h"
#include "stat_workaround.h"
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


static const char	*config_dir_postfix	= "/.smb";
static char		config_file[256]	= "smbnetfs.conf";
static char		config_dir[2048]	= "/";
static int		config_cmd_opts_cnt	= 0;
static int		config_cmd_opts_max_cnt	= 32;
static char		**config_cmd_opts	= NULL;

const char *smbnetfs_option_list =
	"    -o config=PATH               path to config (~/.smb/smbnetfs.conf)\n"
	"    -o smbnetfs_debug=N          SMBNetFS debug level (N<=10)\n"
	"    -o smb_debug_level=N         Samba debug level (N<=10)\n"
	"    -o log_file=PATH             File to store SMBNetFS debug messages\n"
	"    -o local_charset=CHARSET     Local charset (autodetected)\n"
	"    -o samba_charset=CHARSET     Charset used by samba (utf-8)\n"
#ifdef HAVE_GNOME_KEYRING
	"    -o use_gnome_keyring=BOOL    Enable/disable usage of gnome-keyring\n"
	"    -o gnome_keyring_timeout=T   auth retrieving timeout for gnome_keyring (500ms)\n"
#endif /* HAVE_GNOME_KEYRING */
	"    -o max_rw_block_size=N       Maximum size of r/w block in Kb (autodetected)\n"
	"    -o smb_tree_scan_period=T    Period of scanning samba network tree (300s)\n"
	"    -o smb_tree_elements_ttl=T   TTL of scanned elements in samba tree (900s)\n"
	"    -o smb_query_browsers=BOOL   Enable/disable scanning of samba tree (on)\n"
	"    -o show_$_shares=BOOL        Enable/disable showing of hidden shares (off)\n"
	"    -o show_hidden_hosts=BOOL    See in documentation (off)\n"
	"    -o free_space_size=N         Free space size in pages (0)\n"
	"    -o quiet_flag=BOOL           Do not fail on chown/chgroup (on)\n"
	"    -o stat_workaround_depth=N   konquerror and gnome termal hack (3)\n"
	"    -o time_step=T               Scheduler sleep interval (10s)\n"
	"    -o config_update_period=T    Configuration update interval (300s)\n"
	"    -o max_ctx_count=N           Maximum number of childs (15)\n"
	"    -o max_retry_count=N         Number of retries before fail (3)\n"
	"    -o listen_timeout=T          Child process inactivity timeout (300s)\n"
	"    -o reply_timeout=T           Child process reply timeout (30s)\n"
	"    -o max_passwd_query_count=N  See in documentation (10)\n";


static void reconfigure_set_config_dir(const char *path){
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
	"WARNING!!! Configuration directory %s is not found. Please create it.\n"
	"This directory should contain at least two files: smb.conf and smbnetfs.conf.\n"
	"You may copy smb.conf from the /etc/samba directory. You can find a sample of\n"
	"smbnetfs.conf in the doc directory of original SMBNetFS distribution.\n\n"
	"Using default settings for now.\n", path);
}

void reconfigure_set_default_login_and_configdir(void){
    char			buf[2048];
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

static int reconfigure_get_number(char *value, int *result){
    char *endptr;

    *result = strtol(value, &endptr, 0);
    if (*endptr == '\0') return 1;
    else return 0;
}

static int reconfigure_set_number(char *value, int (*func)(int)){
    int result;

    if (reconfigure_get_number(value, &result)) return func(result);
    else return 0;
}

static int reconfigure_get_size(char *value, size_t *result){
    char *endptr;

    *result = strtol(value, &endptr, 0);
    if (*endptr == '\0') return 1;
    else return 0;
}

static int reconfigure_set_size(char *value, int (*func)(size_t)){
    size_t result;

    if (reconfigure_get_size(value, &result)) return func(result);
    else return 0;
}

static int reconfigure_set_kb_size(char *value, int (*func)(size_t)){
    size_t result;

    if (reconfigure_get_size(value, &result)) return func(result * 1024);
    else return 0;
}

static int reconfigure_get_boolean(char *value, int *result){
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

static int reconfigure_set_boolean(char *value, int (*func)(int)){
    int result;

    if (reconfigure_get_boolean(value, &result)) return func(result);
    else return 0;
}

static int reconfigure_find_cmd_opt(const char *option){
    int	i;

    for(i = 0; i < config_cmd_opts_cnt; i++){
	if (strcasecmp(config_cmd_opts[i], option) == 0) return 1;
    }
    return 0;
}

static int reconfigure_add_cmd_opt(const char *option){
    char	*opt;
    char	**new_ptr;
    int		new_max_cnt;

    if (reconfigure_find_cmd_opt(option)) return 1;

    if (config_cmd_opts == NULL){
	config_cmd_opts = malloc(16 * sizeof(char*));
	if (config_cmd_opts == NULL) return 0;
	config_cmd_opts_max_cnt = 16;
    }
    if (config_cmd_opts_cnt == config_cmd_opts_max_cnt){
	new_max_cnt = 2 * config_cmd_opts_max_cnt;
	new_ptr = realloc(config_cmd_opts, new_max_cnt * sizeof(char*));
	if (new_ptr == NULL) return 0;

	config_cmd_opts_max_cnt = new_max_cnt;
	config_cmd_opts = new_ptr;
    }

    opt = strdup(option);
    if (opt == NULL) return 0;
    config_cmd_opts[config_cmd_opts_cnt++] = opt;
    return 1;
}

static int reconfigure_split_line(const char *line,
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

static int reconfigure_analyse_simple_option(const char *option, char *value, int flags){
    if ( ! (flags & CONFIG_OPT_CMDLINE) && reconfigure_find_cmd_opt(option)){
	DPRINTF(8, "ignore overriding of command line option '%s'.\n", option);
	return 1;
    }

    /* common.h */
    if (strcasecmp(option, "smbnetfs_debug") == 0)
	return reconfigure_set_number(value, common_set_smbnetfs_debug_level);
    if (strcasecmp(option, "log_file") == 0)
        return common_set_log_file(value);

#ifdef HAVE_GNOME_KEYRING
    /* auth-gnome-keyring.h */
    if (strcasecmp(option, "use_gnome_keyring") == 0)
	return reconfigure_set_boolean(value, gnome_keyring_enable);
    if (strcasecmp(option, "gnome_keyring_timeout") == 0)
	return reconfigure_set_number(value, gnome_keyring_set_request_timeout);
#endif /* HAVE_GNOME_KEYRING */

    /* process.h */
    if (strcasecmp(option, "listen_timeout") == 0)
	return reconfigure_set_number(value, process_set_server_listen_timeout);
    if (strcasecmp(option, "smb_timeout") == 0)
	return reconfigure_set_number(value, process_set_server_smb_timeout);
    if (strcasecmp(option, "smb_debug_level") == 0)
	return reconfigure_set_number(value, process_set_server_smb_debug_level);
    if (strcasecmp(option, "local_charset") == 0)
	return process_set_server_local_charset(value);
    if (strcasecmp(option, "samba_charset") == 0)
	return process_set_server_samba_charset(value);

    /* smb_conn.h */
    if (strcasecmp(option, "max_retry_count") == 0)
	return reconfigure_set_number(value, smb_conn_set_max_retry_count);
    if (strcasecmp(option, "max_passwd_query_count") == 0)
	return reconfigure_set_number(value, smb_conn_set_max_passwd_query_count);
    if (strcasecmp(option, "reply_timeout") == 0)
	return reconfigure_set_number(value, smb_conn_set_server_reply_timeout);

    /* samba.h */
    if (strcasecmp(option, "max_rw_block_size") == 0){
	if ( ! (flags & CONFIG_OPT_STARTUP)) return 1;	/* ignore this option*/
	return reconfigure_set_kb_size(value, samba_init);
    }
    if (strcasecmp(option, "max_ctx_count") == 0)
	return reconfigure_set_number(value, samba_set_max_ctx_count);

    /* event.h */
    if (strcasecmp(option, "time_step") == 0)
	return reconfigure_set_number(value, event_set_time_step);
    if (strcasecmp(option, "smb_tree_scan_period") == 0)
	return reconfigure_set_number(value, event_set_smb_tree_scan_period);
    if (strcasecmp(option, "smb_tree_elements_ttl") == 0)
	return reconfigure_set_number(value, event_set_smb_tree_elements_ttl);
    if (strcasecmp(option, "config_update_period") == 0)
	return reconfigure_set_number(value, event_set_config_update_period);
    if (strcasecmp(option, "smb_query_browsers") == 0)
	return reconfigure_set_boolean(value, event_set_query_browser_flag);

    /* stat_workaround.h */
    if (strcasecmp(option, "stat_workaround_depth") == 0)
	return reconfigure_set_number(value, stat_workaround_set_default_depth);
    if (strcasecmp(option, "stat_workaround_enable_default_entries") == 0)
	return reconfigure_set_boolean(value, stat_workaround_enable_default_entries);

    /* function.h */
    if (strcasecmp(option, "free_space_size") == 0)
	return reconfigure_set_size(value, function_set_free_space_size);
    if (strcasecmp(option, "quiet_flag") == 0)
	return reconfigure_set_boolean(value, function_set_quiet_flag);
    if (strcasecmp(option, "show_$_shares") == 0)
	return reconfigure_set_boolean(value, function_set_dollar_share_visibility);
    if (strcasecmp(option, "show_hidden_hosts") == 0)
	return reconfigure_set_boolean(value, function_set_hidden_hosts_visibility);

    /* unknown option */
    return 0;
}

int reconfigure_analyse_cmdline_option(const char *option, char *value){
    int		ret;

    if (reconfigure_find_cmd_opt(option))
	fprintf(stderr, "WARNING: duplicate option '%s' found.\n", option);

    if (strcmp(option, "config") == 0){
	char	*pos, *name, path[2048];
	size_t	len;

	len = 0;
	memset(path, 0, sizeof(path));
	if (*value != '/'){
	    if (getcwd(path, sizeof(path) - 1) == NULL) goto error;

	    len = strlen(path);
	    if (path[len - 1] != '/'){
		if (len + 2 > sizeof(path)) goto error;
		strcat(path, "/");
		len++;
	    }
	}

	name = value;
	if ((pos = strrchr(name, '/')) != NULL){
	    pos++;
	    if (len + (pos - name) + 1 > sizeof(path)) goto error;
	    strncat(path, name, pos - name);
	    name = pos;
	}
	if (*name == '\0') goto error;

	/* set config dir */
	if (strlen(path) + 1  > sizeof(config_dir))  goto error;
	reconfigure_set_config_dir(path);

	/* set config file name */
	if (strlen(name) + 1 > sizeof(config_file)) goto error;
	strcpy(config_file, name);
	reconfigure_add_cmd_opt(option);
	return 1;

      error:
	reconfigure_add_cmd_opt(option);
	fprintf(stderr, "Can't set alternative configuration file '%s'.\nUse default one instead.\n", value);
	return 1;
    }

    ret = reconfigure_analyse_simple_option(option, value,
			(CONFIG_OPT_STARTUP | CONFIG_OPT_CMDLINE));
    if (ret == 1) reconfigure_add_cmd_opt(option);
    return ret;
}

/*===========================================================*/
/* WARNING: the value[i] can be changed inside this function */
/*===========================================================*/
static int reconfigure_parse_auth_option(char *value[], int count){
    char	*comp = "", *share = "";
    char	*domain = "", *user, *password;
    int		user_pos = 0;

    if ((count < 2) || (count > 3)) return 0;

    /* server and share */
    if (count == 3){
	if (*value[0] == '/') return 0;

	user_pos = 1;
	comp = value[0];
	if ((share = strchr(comp, '/')) != NULL){
	    *share++ = '\0';
	    if ((*share == '\0') || (strchr(share, '/') != NULL)) return 0;
	}else{
	    share = "";
	}
    };

    /* domain and user */
    if (*value[user_pos] == '/') return 0;
    if ((user = strchr(value[user_pos], '/')) != NULL){
	domain = value[user_pos];
	*user++ = '\0';
	if ((*user == '\0') || (strchr(user, '/') != NULL)) return 0;
    }else{
	user = value[user_pos];
    }

    /* password */
    password = value[user_pos + 1];

    return (auth_store_auth_data(comp, share, domain, user, password) == 0);
}

static int reconfigure_parse_stat_workaround_name_option(char *value[], int count){
    const char	*case_ptn	= "case_sensitive=";
    const char	*depth_ptn	= "depth=";
    int		case_sensitive	= -1;
    int		depth		= -2;
    int		i;
    size_t	len;

    if ((count < 1) || (count > 3)) return 0;

    for(i = 1; i < count; i++){
	len = strlen(case_ptn);
	if (strncasecmp(value[i], case_ptn, len) == 0){
	    if (case_sensitive != -1) return 0;
	    if (! reconfigure_get_boolean(value[i] + len, &case_sensitive))
		return 0;
	}
	len = strlen(depth_ptn);
	if (strncasecmp(value[i], depth_ptn, len) == 0){
	    if (depth != -2) return 0;
	    if (! reconfigure_get_number(value[i] + len, &depth))
		return 0;
	}
    }
    if (case_sensitive == -1) case_sensitive = 1;

    return stat_workaround_add_name(value[0], case_sensitive, depth);
}

static int reconfigure_parse_host_option(char *value[], int count){
    const char	*group_ptn	= "parent_group=";
    const char	*visible_ptn	= "visible=";
    const char	*parent_group	= NULL;
    int		visibility	= -1;
    int		i;
    size_t	len;

    if ((count < 1) || (count > 3)) return 0;

    if (strchr(value[0], '/') != NULL) return 0;

    for(i = 1; i < count; i++){
	len = strlen(group_ptn);
	if (strncasecmp(value[i], group_ptn, len) == 0){
	    if (parent_group != NULL) return 0;
	    parent_group = value[i] + len;
	    if ((*parent_group == '\0') ||
		(strchr(parent_group, '/') != NULL)) return 0;
	}
	len = strlen(visible_ptn);
	if (strncasecmp(value[i], visible_ptn, len) == 0){
	    if (visibility != -1) return 0;
	    if (! reconfigure_get_boolean(value[i] + len, &visibility))
		return 0;
	}
    }
    if (visibility == -1) visibility = 1;

    return (smbitem_mkhost(value[0], parent_group,
			visibility, SMBITEM_USER_TREE) == 0);
}

static int reconfigure_parse_link_option(char *value[], int count){
    char	*name;
    int		result;

    if ((count < 1) || (count > 2)) return 0;
    if (*value[0] == '/') return 0;

    name = strchr(value[0], '/');
    if (name == NULL){
	if (*value[1] == '\0') return 0;
    }else{
	name++;
	if ((*name == '\0') || (strchr(name, '/') != NULL)) return 0;
    }

    if (*value[1] == '\0'){
	char	*link = malloc(strlen(name) + 4);

	if (link == NULL) return 0;
	strcpy(link, "../");
	strcat(link, name);
	result = (smbitem_mklink(value[0], link, SMBITEM_USER_TREE) == 0);
	free(link);
    }else{
	result = (smbitem_mklink(value[0], value[1], SMBITEM_USER_TREE) == 0);
    }
    return result;
}

static int reconfigure_parse_group_option(char *value[], int count){
    if (count != 1) return 0;
    if (strchr(value[0], '/') != NULL) return 0;
    return (smbitem_mkgroup(value[0], SMBITEM_USER_TREE) == 0);
}

static int reconfigure_read_config_file(const char *filename, int flags){
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
    snprintf(pattern, sizeof(pattern), "%%%zd[^\n]\n", sizeof(s) - 1);

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

	if (strcasecmp(arg[0], "stat_workaround_name") == 0){
	    if (reconfigure_parse_stat_workaround_name_option(arg + 1, cnt - 1)) continue;
	}
	if (strcasecmp(arg[0], "stat_workaround_exception") == 0){
	    if ((cnt == 2) && stat_workaround_add_exception(arg[1])) continue;
	}

	if (cnt == 2){
	    if (strcasecmp(arg[0], "include") == 0){
		reconfigure_read_config_file(arg[1], flags);
		continue;
	    }
	    if (reconfigure_analyse_simple_option(arg[0], arg[1], flags)) continue;
	}

	if (strcasecmp(arg[0], "auth") == 0){
	    if (!ok_permission) goto insecure_permission;
	    /* WARNING: this function can change the contents of arg[i] */
	    if (reconfigure_parse_auth_option(arg + 1, cnt - 1)) continue;
	}
	if (strcasecmp(arg[0], "host") == 0){
	    if (!ok_permission) goto insecure_permission;
	    if (reconfigure_parse_host_option(arg + 1, cnt - 1)) continue;
	}
	if (strcasecmp(arg[0], "link") == 0){
	    if (!ok_permission) goto insecure_permission;
	    if (reconfigure_parse_link_option(arg + 1, cnt - 1)) continue;
	}
	if (strcasecmp(arg[0], "group") == 0){
	    if (!ok_permission) goto insecure_permission;
	    if (reconfigure_parse_group_option(arg + 1, cnt - 1)) continue;
	}

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

int reconfigure_read_config(int flags){
    int status;

    status = reconfigure_read_config_file(config_file, flags);
    stat_workaround_add_default_entries();
    return status;
}
