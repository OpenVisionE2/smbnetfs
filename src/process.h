#ifndef __PROCESS_H__
#define __PROCESS_H__

int  process_init(void);

void process_disable_new_smb_conn_starting(void);
int  process_set_server_listen_timeout(int timeout);
int  process_set_server_smb_debug_level(int level);
int  process_set_server_samba_charset(const char *charset);
int  process_set_server_local_charset(const char *charset);

int  process_start_new_smb_conn(char *shmem_ptr, size_t shmem_size);
int  process_is_smb_conn_alive(int fd);
void process_kill_all(void);
void process_kill_by_smb_conn_fd(int fd);
void process_cleanup_from_zombies(void);

#endif /* __PROCESS_H__ */
