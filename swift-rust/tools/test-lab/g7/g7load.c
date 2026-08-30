#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef IP_BIND_ADDRESS_NO_PORT
#define IP_BIND_ADDRESS_NO_PORT 24
#endif

enum { ST_NEW = 0, ST_CONN = 1, ST_SEND = 2, ST_RECV = 3, ST_HOLD = 4, ST_FAIL = 5 };

struct conn {
    int fd;
    unsigned char st;
    unsigned char src;
    unsigned short off;
    unsigned short got;
};

struct src {
    struct sockaddr_in addr;
};

struct sampler {
    volatile int run;
    volatile int go; /* 0 until the SUT workload is held; health p99 is hold-only */
    char host[64];
    int port;
    int n;
    int ok;
    double *ms;
};

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int set_nb(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int parse_srcs(char *csv, struct src *out, int cap) {
    int n = 0;
    char *p = csv;
    while (p && *p && n < cap) {
        char *comma = strchr(p, ',');
        if (comma) *comma = 0;
        memset(&out[n].addr, 0, sizeof(out[n].addr));
        out[n].addr.sin_family = AF_INET;
        out[n].addr.sin_port = 0;
        if (inet_pton(AF_INET, p, &out[n].addr.sin_addr) != 1) {
            fprintf(stderr, "bad src ip %s\n", p);
            return -1;
        }
        n++;
        p = comma ? comma + 1 : NULL;
    }
    return n;
}

static int open_conn(const struct sockaddr_in *dst, const struct src *src) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
    if (src) {
        if (bind(fd, (struct sockaddr *)&src->addr, sizeof(src->addr)) != 0) {
            close(fd);
            return -1;
        }
    }
    set_nb(fd);
    int rc = connect(fd, (struct sockaddr *)dst, sizeof(*dst));
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static void *health_thread(void *arg) {
    struct sampler *s = arg;
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)s->port);
    inet_pton(AF_INET, s->host, &dst.sin_addr);
    char req[256];
    int reqn = snprintf(req, sizeof(req),
                        "HEAD /healthcheck HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                        s->host);
    int i = 0;
    while (s->run && !s->go) usleep(10000);
    while (s->run && i < s->n) {
        double t0 = now_ms();
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            usleep(10000);
            continue;
        }
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        int good = 0;
        if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
            if (write(fd, req, reqn) > 0) {
                char buf[512];
                ssize_t r = read(fd, buf, sizeof(buf));
                if (r >= 12 && !memcmp(buf, "HTTP/1.1 200", 12)) {
                    good = 1;
                    s->ok++;
                }
            }
        }
        s->ms[i++] = now_ms() - t0;
        (void)good;
        close(fd);
        usleep(20000);
    }
    s->n = i;
    return NULL;
}

static void usage(void) {
    fprintf(stderr,
            "usage:\n"
            "  g7load idle <host> <port> <n> <hold_ms> --src ip,ip [--path /healthcheck]\n"
            "  g7load slowloris <host> <port> <n> <interval_ms> <hold_ms> --src ip,ip\n"
            "  g7load slowput <host> <port> <n> <rate_bps> <body> --src ip,ip --path PATH --token T\n"
            "  g7load accept <bind> <port>\n");
}

static int run_accept(const char *bind_ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_ip, &a.sin_addr) != 1) return 1;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(fd, 65535) != 0) {
        perror("listen");
        return 1;
    }
    set_nb(fd);
    fprintf(stderr, "g7-accept listening %s:%d\n", bind_ip, port);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
    epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    struct epoll_event evs[1024];
    char ok[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
    for (;;) {
        int n = epoll_wait(ep, evs, 1024, -1);
        for (int i = 0; i < n; i++) {
            int cfd = evs[i].data.fd;
            if (cfd == fd) {
                for (;;) {
                    int c = accept(fd, NULL, NULL);
                    if (c < 0) break;
                    int one = 1;
                    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    set_nb(c);
                    struct epoll_event cev = {.events = EPOLLIN | EPOLLRDHUP, .data.fd = c};
                    epoll_ctl(ep, EPOLL_CTL_ADD, c, &cev);
                }
            } else {
                char buf[4096];
                ssize_t r = read(cfd, buf, sizeof(buf));
                if (r <= 0) {
                    epoll_ctl(ep, EPOLL_CTL_DEL, cfd, NULL);
                    close(cfd);
                } else if (r >= 4) {
                    write(cfd, ok, sizeof(ok) - 1);
                }
            }
        }
    }
}

static int run_idle(int argc, char **argv) {
    if (argc < 5) {
        usage();
        return 2;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);
    int target = atoi(argv[3]);
    int hold_ms = atoi(argv[4]);
    const char *path = "/healthcheck";
    char srcbuf[256] = "";
    for (int i = 5; i < argc; i++) {
        if (!strcmp(argv[i], "--src") && i + 1 < argc) strncpy(srcbuf, argv[++i], sizeof(srcbuf) - 1);
        else if (!strcmp(argv[i], "--path") && i + 1 < argc) path = argv[++i];
    }
    struct src srcs[8];
    int nsrc = srcbuf[0] ? parse_srcs(srcbuf, srcs, 8) : 0;
    if (nsrc < 0) return 2;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &dst.sin_addr) != 1) {
        fprintf(stderr, "bad host\n");
        return 2;
    }

    char req[512];
    int reqn = snprintf(req, sizeof(req),
                        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n",
                        path, host);

    struct conn *cs = calloc((size_t)target, sizeof(*cs));
    if (!cs) return 1;
    int ep = epoll_create1(0);
    if (ep < 0) return 1;

    int opened = 0, http_ok = 0, failed = 0;
    int next = 0, inflight = 0;
    const int pace = 1024;
    char rbuf[1024];
    struct epoll_event evs[1024];
    signal(SIGPIPE, SIG_IGN);
    double t0 = now_ms();
    double open_deadline = t0 + 360000;

    /* Independent Swift1 observer is the G7 health metric. In-process
     * Connection:close HEAD sampling during hold polluted 100k p99. */
    struct sampler samp = {.run = 1, .go = 0, .port = port, .n = 0, .ok = 0};
    strncpy(samp.host, host, sizeof(samp.host) - 1);
    samp.ms = calloc(200, sizeof(double));
    pthread_t th;
    pthread_create(&th, NULL, health_thread, &samp);

    while (http_ok < target) {
        while (next < target && inflight < pace * 4) {
            int burst = 0;
            while (next < target && burst < pace && inflight < pace * 4) {
                const struct src *sp = nsrc ? &srcs[next % nsrc] : NULL;
                int fd = open_conn(&dst, sp);
                if (fd < 0) {
                    failed++;
                    next++;
                    continue;
                }
                cs[next].fd = fd;
                cs[next].st = ST_CONN;
                cs[next].src = (unsigned char)(nsrc ? next % nsrc : 0);
                struct epoll_event ev = {.events = EPOLLOUT | EPOLLIN | EPOLLERR | EPOLLHUP,
                                         .data.u32 = (uint32_t)next};
                epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
                next++;
                inflight++;
                burst++;
            }
        }
        /* Recycle failed slots so a SYN-storm drop does not cap http_ok
         * below target (G7 opened==target). */
        while (next >= target && http_ok < target && inflight < pace * 4) {
            int idx = -1;
            for (int j = 0; j < target; j++) {
                if (cs[j].st == ST_FAIL) {
                    idx = j;
                    break;
                }
            }
            if (idx < 0) break;
            if (cs[idx].fd > 0) {
                epoll_ctl(ep, EPOLL_CTL_DEL, cs[idx].fd, NULL);
                close(cs[idx].fd);
            }
            memset(&cs[idx], 0, sizeof(cs[idx]));
            cs[idx].fd = -1;
            const struct src *sp = nsrc ? &srcs[idx % nsrc] : NULL;
            int fd = open_conn(&dst, sp);
            if (fd < 0) {
                cs[idx].st = ST_FAIL;
                failed++;
                break;
            }
            cs[idx].fd = fd;
            cs[idx].st = ST_CONN;
            cs[idx].src = (unsigned char)(nsrc ? idx % nsrc : 0);
            struct epoll_event ev = {.events = EPOLLOUT | EPOLLIN | EPOLLERR | EPOLLHUP,
                                     .data.u32 = (uint32_t)idx};
            epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
            inflight++;
        }
        int n = epoll_wait(ep, evs, 1024, 200);
        if (n < 0 && errno == EINTR) continue;
        for (int i = 0; i < n; i++) {
            int idx = (int)evs[i].data.u32;
            struct conn *c = &cs[idx];
            if (c->st == ST_FAIL || c->st == ST_HOLD) continue;
            if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
                if (c->st != ST_HOLD) {
                    c->st = ST_FAIL;
                    failed++;
                    inflight--;
                    close(c->fd);
                    c->fd = -1;
                }
                continue;
            }
            if (c->st == ST_CONN && (evs[i].events & EPOLLOUT)) {
                int err = 0;
                socklen_t el = sizeof(err);
                getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el);
                if (err) {
                    c->st = ST_FAIL;
                    failed++;
                    inflight--;
                    close(c->fd);
                    c->fd = -1;
                    continue;
                }
                opened++;
                c->st = ST_SEND;
                c->off = 0;
            }
            if (c->st == ST_SEND) {
                int w = write(c->fd, req + c->off, reqn - c->off);
                if (w > 0) c->off += w;
                if (c->off >= reqn) {
                    c->st = ST_RECV;
                    c->got = 0;
                } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    c->st = ST_FAIL;
                    failed++;
                    inflight--;
                    close(c->fd);
                    c->fd = -1;
                }
            }
            if (c->st == ST_RECV && (evs[i].events & EPOLLIN)) {
                int r = read(c->fd, rbuf, sizeof(rbuf));
                if (r > 0) {
                    if (c->got == 0 && r >= 12 && !memcmp(rbuf, "HTTP/1.1 200", 12)) http_ok++;
                    c->got = 1;
                    c->st = ST_HOLD;
                    inflight--;
                } else if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                    c->st = ST_FAIL;
                    failed++;
                    inflight--;
                    close(c->fd);
                    c->fd = -1;
                }
            }
        }
        if (now_ms() > open_deadline) {
            for (int j = 0; j < next; j++) {
                if (cs[j].st == ST_CONN || cs[j].st == ST_SEND || cs[j].st == ST_RECV) {
                    cs[j].st = ST_FAIL;
                    failed++;
                    inflight--;
                    if (cs[j].fd > 0) {
                        close(cs[j].fd);
                        cs[j].fd = -1;
                    }
                }
            }
            break;
        }
        if (http_ok >= target) break;
    }

    samp.go = 1;
    double hold_t0 = now_ms();
    while (now_ms() - hold_t0 < hold_ms) {
        epoll_wait(ep, evs, 1024, 200);
        usleep(50000);
    }

    samp.run = 0;
    pthread_join(th, NULL);
    qsort(samp.ms, (size_t)samp.n, sizeof(double), cmp_double);
    double p99 = 0, p50 = 0;
    if (samp.n > 0) {
        p50 = samp.ms[samp.n / 2];
        p99 = samp.ms[(int)((samp.n - 1) * 0.99)];
    }

    printf("{\"case\":\"idle\",\"target\":%d,\"opened\":%d,\"http_ok\":%d,\"failed\":%d,"
           "\"hold_ms\":%d,\"health_p50_ms\":%.3f,\"health_p99_ms\":%.3f,"
           "\"health_samples\":%d,\"health_ok\":%d,\"elapsed_ms\":%.1f}\n",
           target, opened, http_ok, failed, hold_ms, p50, p99, samp.n, samp.ok, now_ms() - t0);
    fflush(stdout);

    for (int i = 0; i < target; i++) if (cs[i].fd > 0) close(cs[i].fd);
    free(cs);
    free(samp.ms);
    close(ep);
    return (http_ok == target) ? 0 : 3;
}

static int run_slowloris(int argc, char **argv) {
    if (argc < 6) {
        usage();
        return 2;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);
    int target = atoi(argv[3]);
    int interval_ms = atoi(argv[4]);
    int hold_ms = atoi(argv[5]);
    char srcbuf[256] = "";
    for (int i = 6; i < argc; i++) {
        if (!strcmp(argv[i], "--src") && i + 1 < argc) strncpy(srcbuf, argv[++i], sizeof(srcbuf) - 1);
    }
    struct src srcs[8];
    int nsrc = srcbuf[0] ? parse_srcs(srcbuf, srcs, 8) : 0;
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &dst.sin_addr);

    int *fds = calloc((size_t)target, sizeof(int));
    int opened = 0;
    for (int i = 0; i < target; i++) {
        const struct src *sp = nsrc ? &srcs[i % nsrc] : NULL;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) break;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
        if (sp) bind(fd, (struct sockaddr *)&sp->addr, sizeof(sp->addr));
        if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
            close(fd);
            break;
        }
        dprintf(fd, "GET /healthcheck HTTP/1.1\r\nHost: %s\r\nX-A: %d\r\n", host, i);
        fds[opened++] = fd;
    }
    double t0 = now_ms();
    struct sampler samp = {.run = 1, .go = 1, .port = port, .n = 200, .ok = 0};
    strncpy(samp.host, host, sizeof(samp.host) - 1);
    samp.ms = calloc(200, sizeof(double));
    pthread_t th;
    pthread_create(&th, NULL, health_thread, &samp);
    while (now_ms() - t0 < hold_ms) {
        for (int i = 0; i < opened; i++) dprintf(fds[i], "X-B: %d\r\n", (int)now_ms());
        usleep((useconds_t)interval_ms * 1000);
    }
    samp.run = 0;
    pthread_join(th, NULL);
    qsort(samp.ms, (size_t)samp.n, sizeof(double), cmp_double);
    double p99 = samp.n ? samp.ms[(int)((samp.n - 1) * 0.99)] : 0;
    printf("{\"case\":\"slowloris\",\"target\":%d,\"opened\":%d,\"failed\":%d,"
           "\"health_p99_ms\":%.3f,\"health_samples\":%d,\"health_ok\":%d}\n",
           target, opened, target - opened, p99, samp.n, samp.ok);
    for (int i = 0; i < opened; i++) close(fds[i]);
    free(fds);
    free(samp.ms);
    return opened == target ? 0 : 3;
}

static int run_slowput(int argc, char **argv) {
    if (argc < 6) {
        usage();
        return 2;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);
    int target = atoi(argv[3]);
    int rate = atoi(argv[4]);
    int body = atoi(argv[5]);
    char srcbuf[256] = "";
    const char *path = "/v1/AUTH_test/g7slow/o";
    const char *token = "";
    for (int i = 6; i < argc; i++) {
        if (!strcmp(argv[i], "--src") && i + 1 < argc) strncpy(srcbuf, argv[++i], sizeof(srcbuf) - 1);
        else if (!strcmp(argv[i], "--path") && i + 1 < argc) path = argv[++i];
        else if (!strcmp(argv[i], "--token") && i + 1 < argc) token = argv[++i];
    }
    struct src srcs[8];
    int nsrc = srcbuf[0] ? parse_srcs(srcbuf, srcs, 8) : 0;
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &dst.sin_addr);
    int *fds = calloc((size_t)target, sizeof(int));
    int opened = 0;
    for (int i = 0; i < target; i++) {
        const struct src *sp = nsrc ? &srcs[i % nsrc] : NULL;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) break;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
        if (sp) bind(fd, (struct sockaddr *)&sp->addr, sizeof(sp->addr));
        if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
            close(fd);
            break;
        }
        dprintf(fd,
                "PUT %s-%d HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n"
                "X-Auth-Token: %s\r\nConnection: keep-alive\r\n\r\n",
                path, i, host, body, token);
        fds[opened++] = fd;
    }
    /* Preserve the frozen 1 KiB/s drip with 64-byte slices.  The overload
     * case uses a larger slice so 4k x 1 MiB does not become 65m syscalls. */
    int chunk = rate >= 65536 ? 16384 : 64;
    if (chunk > body) chunk = body;
    int delay_us = rate > 0 ? (int)(1000000.0 * chunk / rate) : 1000;
    if (delay_us < 200) delay_us = 200;
    int sent = 0;
    char *payload = malloc((size_t)chunk);
    unsigned char *send_error = calloc((size_t)target, 1);
    if (!payload || !send_error) return 1;
    memset(payload, 'X', (size_t)chunk);
    struct sampler samp = {.run = 1, .go = 1, .port = port, .n = 200, .ok = 0};
    strncpy(samp.host, host, sizeof(samp.host) - 1);
    samp.ms = calloc(200, sizeof(double));
    pthread_t th;
    pthread_create(&th, NULL, health_thread, &samp);
    while (sent < body) {
        int nthis = chunk;
        if (sent + nthis > body) nthis = body - sent;
        for (int i = 0; i < opened; i++) {
            if (send_error[i]) continue;
            ssize_t written = write(fds[i], payload, (size_t)nthis);
            if (written != nthis) send_error[i] = 1;
        }
        sent += nthis;
        usleep((useconds_t)delay_us);
    }
    samp.run = 0;
    pthread_join(th, NULL);
    qsort(samp.ms, (size_t)samp.n, sizeof(double), cmp_double);
    double p99 = samp.n ? samp.ms[(int)((samp.n - 1) * 0.99)] : 0;
    int responses = 0, http_2xx = 0, http_503 = 0;
    for (int i = 0; i < opened; i++) {
        struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
        setsockopt(fds[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        char response[1024];
        ssize_t nread = read(fds[i], response, sizeof(response) - 1);
        if (nread <= 0) continue;
        response[nread] = 0;
        int status = 0;
        if (sscanf(response, "HTTP/%*s %d", &status) != 1) continue;
        responses++;
        if (status >= 200 && status < 300) http_2xx++;
        if (status == 503) http_503++;
    }
    int failed = target - responses;
    printf("{\"case\":\"slow_put\",\"target\":%d,\"opened\":%d,\"responses\":%d,"
           "\"http_2xx\":%d,\"http_503\":%d,\"failed\":%d,\"body_bytes\":%d,"
           "\"health_p99_ms\":%.3f,\"health_samples\":%d,\"health_ok\":%d}\n",
           target, opened, responses, http_2xx, http_503, failed, body, p99, samp.n, samp.ok);
    for (int i = 0; i < opened; i++) close(fds[i]);
    free(fds);
    free(payload);
    free(send_error);
    free(samp.ms);
    return opened == target && responses == target ? 0 : 3;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = 500000;
    setrlimit(RLIMIT_NOFILE, &rl);
    if (argc < 2) {
        usage();
        return 2;
    }
    if (!strcmp(argv[1], "accept")) return run_accept(argv[2], atoi(argv[3]));
    if (!strcmp(argv[1], "idle")) return run_idle(argc - 1, argv + 1);
    if (!strcmp(argv[1], "slowloris")) return run_slowloris(argc - 1, argv + 1);
    if (!strcmp(argv[1], "slowput")) return run_slowput(argc - 1, argv + 1);
    usage();
    return 2;
}
