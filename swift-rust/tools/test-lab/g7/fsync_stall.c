#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>

static int stall_us(void) {
    const char *e = getenv("G7_FSYNC_STALL_US");
    if (!e || !*e) return 5000000;
    return atoi(e);
}

int fsync(int fd) {
    static int (*real_fsync)(int) = 0;
    if (!real_fsync) real_fsync = dlsym(RTLD_NEXT, "fsync");
    usleep((useconds_t)stall_us());
    return real_fsync(fd);
}

int fdatasync(int fd) {
    static int (*real_fdatasync)(int) = 0;
    if (!real_fdatasync) real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    usleep((useconds_t)stall_us());
    return real_fdatasync(fd);
}
