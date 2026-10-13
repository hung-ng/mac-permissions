#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <libproc.h>
#include <string.h>
#include <sys/stat.h>
#ifndef MP_VERSION
#define MP_VERSION 1
#endif
volatile int fixture_version = MP_VERSION;

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    int fd = open(argv[1], O_RDONLY | O_NOFOLLOW);
    int error = fd < 0 ? errno : 0;
    char byte;
    int read_error = 0;
    struct stat st;
    if (fd >= 0 && fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode) && read(fd, &byte, 1) < 0) read_error = errno;
    if (fd >= 0) close(fd);
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    proc_pidpath(getppid(), path, sizeof(path));
    printf("{\"pid\":%d,\"ppid\":%d,\"parent\":\"%s\",\"version\":%d,\"openErrno\":%d,\"readErrno\":%d,\"success\":%s}\n",
        getpid(), getppid(), path, fixture_version, error, read_error, error || read_error ? "false" : "true");
    return error || read_error ? 77 : 0;
}
