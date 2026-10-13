#include <sys/types.h>
int mp_spawn(const char *path, char *const argv[], char *const envp[], const char *cwd,
             int tty, int rows, int cols, pid_t *pid, int *input, int *output, int *error);
int mp_resize(int fd, int rows, int cols);
int mp_wait(pid_t pid);
int mp_parent(pid_t pid);
int mp_path(pid_t pid, char *buffer, int size);
