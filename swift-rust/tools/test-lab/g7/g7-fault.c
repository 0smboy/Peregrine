#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

static int hits;

static void bump(void) {
    const char *path = getenv("G7_FAULT_HITS");
    if (!path || !*path) path = "/var/run/g6-rust/g7-fault-hits";
    hits++;
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%d\n", hits);
    fclose(f);
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
        bump();
        errno = ENOSPC;
        return -1;
    }
    if (m == 2 && on_object_fd(fd) && count > 0) {
        bump();
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
        bump();
        errno = ENOSPC;
        return -1;
    }
    if (m == 2 && on_object_fd(fd) && count > 0) {
        bump();
        errno = EIO;
        return -1;
    }
    return real_pwrite(fd, buf, count, off);
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t off) {
    static ssize_t (*real_pwrite64)(int, const void *, size_t, off64_t);
    if (!real_pwrite64) real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
    int m = mode();
    if ((m == 1 || m == 2) && on_object_fd(fd) && count > 0) {
        bump();
        errno = m == 1 ? ENOSPC : EIO;
        return -1;
    }
    return real_pwrite64(fd, buf, count, off);
}

static struct timespec stall_t0;

static void stall_init(void) __attribute__((constructor));
static void stall_init(void) {
    clock_gettime(CLOCK_MONOTONIC, &stall_t0);
}

static int stall_ready(void) {
    /* Skip fsyncs in the first second of process life (startup). */
    struct timespec n;
    clock_gettime(CLOCK_MONOTONIC, &n);
    double sec = (double)(n.tv_sec - stall_t0.tv_sec) + (double)(n.tv_nsec - stall_t0.tv_nsec) / 1e9;
    return sec > 1.0;
}

static void maybe_stall(int fd) {
    static int stalled;
    if (mode() == 3 && on_object_fd(fd) && stall_ready() && stalled < 1) {
        stalled++;
        bump();
        usleep((useconds_t)stall_us());
    }
}

int fsync(int fd) {
    static int (*real_fsync)(int);
    if (!real_fsync) real_fsync = dlsym(RTLD_NEXT, "fsync");
    maybe_stall(fd);
    return real_fsync(fd);
}

int fdatasync(int fd) {
    static int (*real_fdatasync)(int);
    if (!real_fdatasync) real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    maybe_stall(fd);
    return real_fdatasync(fd);
}
