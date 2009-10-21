#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <pthread.h>
#include <libsmbclient.h>
#include <pwd.h>

#include "common.h"
#include "smbitem.h"
#include "auth.h"
#include "process.h"
#include "samba.h"
#include "function.h"
#include "event.h"
#include "reconfigure.h"


void check_samba_version(void){
    const char	*samba_version;

    samba_version = smbc_version();
    if (strncmp(samba_version, "3.", 2) != 0){
	fprintf(stderr, "Unknown libsmbclient version: %s\n", samba_version);
	exit(EXIT_FAILURE);
    }
}

inline size_t get_default_rw_block_size(void){
    return (strncmp(smbc_version(), "3.0.", 4) == 0) ? 48 : 128;
}

void sig_handler(int signum){
    fprintf(stderr, "%d->%s: signal %d received\n",
	getpid(), __FUNCTION__, signum);
    common_print_backtrace();
    exit(signum);
}

void set_signal_reactions(void){
    struct{
	int	signum;
	char	*name;
    }			sig[]	= { {SIGILL,  "SIGILL" },
				    {SIGSEGV, "SIGSEGV"},
				    {SIGABRT, "SIGABRT"} };
    int			i;
    struct sigaction	action;

    sigemptyset(&action.sa_mask);
    action.sa_handler = sig_handler;
    action.sa_flags = SA_RESTART;

    for(i = 0; i < 3; i++){
	if (sigaction(sig[i].signum, &action, NULL) < 0){
	    fprintf(stderr, "Can't set %s handler\n", sig[i].name);
	    exit(EXIT_FAILURE);
	}
    }

    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGHUP);
    sigaddset(&action.sa_mask, SIGCHLD);
    if (pthread_sigmask(SIG_BLOCK, &action.sa_mask, NULL) != 0){
	fprintf(stderr, "Can't block SIGHUP and SIGCHLD signals.\n");
	exit(EXIT_FAILURE);
    }
}

void print_help(struct fuse_args *outargs){
    fprintf(stderr,
	"usage: %s mountpoint [options]\n"
	"\n"
	"general options:\n"
	"    -o opt,[opt...]        mount options\n"
	"    -h   --help            print help\n"
	"    -V   --version         print version\n"
	"\n"
	"SMBNetFS options:\n"
	"%s"
	"\n", outargs->argv[0], smbnetfs_option_list);
    fuse_opt_add_arg(outargs, "-ho");
    fuse_main(outargs->argc, outargs->argv, &smb_oper, NULL);
}

static int smbnetfs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs){
    const char	*value;
    char	*name;
    int		result;

    (void) data;
    (void) key;

    if ((strcmp(arg, "--version") == 0) || (strcmp(arg, "-V") == 0)){
	fprintf(stderr, "SMBNetFS version " PACKAGE_VERSION "\n");
	fprintf(stderr, "libsmbclient version %s\n", smbc_version());
	fuse_opt_add_arg(outargs, "--version");
	fuse_main(outargs->argc, outargs->argv, &smb_oper, NULL);
	exit(EXIT_SUCCESS);
    }
    if ((strcmp(arg, "--help") == 0) || (strcmp(arg, "-h") == 0)){
	print_help(outargs);
	exit(EXIT_FAILURE);
    }

    if ((value = strchr(arg, '=')) == NULL) return 1;
    if (value++ == arg) return 1;
    if (strlen(value) == 0) return 1;
    if ((name = strndup(arg, value - arg - 1)) == NULL) return 1;

    /* check for specific SMBNetFS options */
    result = reconfigure_analyse_cmdline_option(name, (char*) value);

    free(name);
    return result ? 0 : 1;
}

int main(int argc, char *argv[]){
    struct fuse_args	args = FUSE_ARGS_INIT(argc, argv);

    setlocale(LC_ALL, "");
    check_samba_version();
    set_signal_reactions();

    /* init all subsystems with their default values */
    reconfigure_set_default_login_and_configdir();
    smbitem_init();
    process_init();
    samba_init(1024 * get_default_rw_block_size());
    event_set_event_handler(&smb_oper);

    /* parse command line options */
    if (fuse_opt_parse(&args, NULL, NULL, smbnetfs_opt_proc) == -1){
	fprintf(stderr, "Can't parse command line, please verify it.\n");
	exit(EXIT_FAILURE);
    }

    if (!special_config) reconfigure_read_config(1);
    samba_allocate_ctxs();

    fuse_main(args.argc, args.argv, &smb_oper, NULL);
    samba_destroy_unused_ctxs();
    smbitem_delete_obsolete(time(NULL) + 10, SMBITEM_SAMBA_TREE);
    smbitem_delete_obsolete(time(NULL) + 10, SMBITEM_USER_TREE);
    auth_delete_obsolete(time(NULL) + 10);
    smbitem_done();
    process_cleanup_from_zombies();
    return 0;
}
