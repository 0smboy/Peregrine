#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Isolated G7 storage faults. Loaded only into g6-rust object/container
 * processes. Never /usr/local/bin.
 *
 * G7_FAULT=enospc | eio | fsync_stall
 * G7_FSYNC_STALL_US=5000000
 */

static int mode(void) {
    const char *m = getenv("G7_FAULT");
    if (!m) return 0;
    if (!strcmp(m, "enospc")) return 1;
    if (!strcmp(m, "eio")) return 2;
    if (!strcmp(m, "fsync_stall")) return 3;
    return 0;
}

static int stall_us(void) {
    const char *e = getenv("G7_FSYNC_STALL_US");
    if (!e || !*e) return 5000000;
    return atoi(e);
}

static int on_object_fd(int fd) {
    char link[64], path[512];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path) - 1);
    if (n < 0) return 0;
    path[n] = 0;
    return strstr(path, "/srv/") != NULL || strstr(path, "objects") != NULL ||
           strstr(path, ".db") != NULL;
}

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t);
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    int m = mode();
    if (m == 1 && on_object_fd(fd) && count > 0) {
        errno = ENOSPC;
        return -1;
    }
    if (m == 2 && on_object_fd(fd) && count > 0) {
        errno = EIO;
        return -1;
    }
    return real_write(fd, buf, count);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t off) {
    static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
    if (!real_pwrite) real_pwrite = dlsym(RTLD_NEXT, "pwrite");
    int m = mode();
    if (m == 1 && on_object_fd(fd) && count > 0) {
        errno = ENOSPC;
        return -1;
    }
    if (m == 2 && on_object_fd(fd) && count > 0) {
        errno = EIO;
        return -1;
    }
    return real_pwrite(fd, buf, count, off);
}

int fsync(int fd) {
    static int (*real_fsync)(int);
    if (!real_fsync) real_fsync = dlsym(RTLD_NEXT, "fsync");
    if (mode() == 3) usleep((useconds_t)stall_us());
    return real_fsync(fd);
}

int fdatasync(int fd) {
    static int (*real_fdatasync)(int);
    if (!real_fdatasync) real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    if (mode() == 3) usleep((useconds_t)stall_us());
    return real_fdatasync(fd);
}
