#include "Native.h"
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <signal.h>
#include <util.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <libproc.h>

int mp_resize(int fd, int rows, int cols) {
    struct winsize ws = {.ws_row = rows, .ws_col = cols};
    return ioctl(fd, TIOCSWINSZ, &ws);
}

int mp_spawn(const char *path, char *const argv[], char *const envp[], const char *cwd,
             int tty, int rows, int cols, pid_t *pid, int *input, int *output, int *error) {
    int in[2] = {-1,-1}, out[2] = {-1,-1}, err[2] = {-1,-1};
    if (tty) {
        int master, slave;
        struct winsize ws = {.ws_row = rows, .ws_col = cols};
        if (openpty(&master, &slave, NULL, NULL, &ws) < 0) return errno;
        fcntl(master, F_SETFD, FD_CLOEXEC);
        fcntl(slave, F_SETFD, FD_CLOEXEC);
        int maxfd = getdtablesize();
        sigset_t empty;
        sigemptyset(&empty);
        pid_t child = fork();
        if (child == 0) {
            // Keep the child path to system calls until exec. No Swift or allocation here.
            setsid();
            if (ioctl(slave, TIOCSCTTY, 0) < 0 || chdir(cwd) < 0) _exit(126);
            dup2(slave, 0); dup2(slave, 1); dup2(slave, 2);
            for (int fd = 3; fd < maxfd; fd++) close(fd);
            sigprocmask(SIG_SETMASK, &empty, NULL);
            struct sigaction action = {.sa_handler = SIG_DFL};
            sigemptyset(&action.sa_mask);
            for (int number = 1; number < NSIG; number++) sigaction(number, &action, NULL);
            execve(path, argv, envp);
            _exit(126);
        }
        int saved = errno;
        close(slave);
        if (child < 0) { close(master); return saved; }
        *pid = child; *output = master; *input = dup(master); *error = -1;
        fcntl(*input, F_SETFD, FD_CLOEXEC);
        return 0;
    }
    int result = 0;
    if (pipe(in) || pipe(out) || pipe(err)) { result = errno; goto cleanup; }
    for (int i = 0; i < 2; i++) {
        fcntl(in[i], F_SETFD, FD_CLOEXEC); fcntl(out[i], F_SETFD, FD_CLOEXEC); fcntl(err[i], F_SETFD, FD_CLOEXEC);
    }
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_init(&actions); posix_spawnattr_init(&attributes);
    posix_spawn_file_actions_adddup2(&actions, in[0], 0);
    posix_spawn_file_actions_adddup2(&actions, out[1], 1);
    posix_spawn_file_actions_adddup2(&actions, err[1], 2);
    posix_spawn_file_actions_addchdir_np(&actions, cwd);
    sigset_t mask, defaults;
    sigemptyset(&mask); sigfillset(&defaults);
    posix_spawnattr_setsigmask(&attributes, &mask);
    posix_spawnattr_setsigdefault(&attributes, &defaults);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    posix_spawnattr_setpgroup(&attributes, 0);
    result = posix_spawn(pid, path, &actions, &attributes, argv, envp);
    posix_spawnattr_destroy(&attributes); posix_spawn_file_actions_destroy(&actions);
    if (result) goto cleanup;
    close(in[0]); close(out[1]); close(err[1]);
    *input = in[1]; *output = out[0]; *error = err[0];
    return 0;
cleanup:
    for (int i = 0; i < 2; i++) { if (in[i] >= 0) close(in[i]); if (out[i] >= 0) close(out[i]); if (err[i] >= 0) close(err[i]); }
    return result;
}

int mp_wait(pid_t pid) {
    int status;
    while (waitpid(pid, &status, 0) < 0) { if (errno != EINTR) return 255; }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
int mp_parent(pid_t pid) {
    struct proc_bsdinfo info;
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == sizeof(info) ? info.pbi_ppid : -1;
}
int mp_path(pid_t pid, char *buffer, int size) { return proc_pidpath(pid, buffer, size); }
