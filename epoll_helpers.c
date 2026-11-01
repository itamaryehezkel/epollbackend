/* ====================================================================
 *  epoll_helpers.c
 *
 *  The TCP engine: listeners, worker threads, the per-connection state
 *  machine, non-blocking TLS/TCP I/O and HTTP framing. Routes live in
 *  handlers.c -- nothing in this file needs touching to add one.
 *
 *  NOT a separate translation unit -- main.c #includes it textually. It
 *  relies on the types, globals and
 *  prototypes declared above main.c's #include of this file, and must
 *  NOT be added to the gcc line in ./compile.
 *
 *  The engine, plus Section 7: the routes do not
 *  run on the socket's thread any more. A worker parses a request and
 *  hands the connection to a pool of handler threads (CS_BUSY); the
 *  handler fills c->out and rings the worker, which writes it out. The
 *  workers therefore never block, however long an upstream call takes, and
 *  each handler thread keeps one MySQL connection open across requests
 *  (connect_db() / db_release() at the bottom of this file).
 *
 *  ---- what changed (the TCP path, handlers untouched) ----------------
 *
 *  Still the kernel's TCP, but the server now drives it with far fewer
 *  syscalls, no locks and no cross-CPU traffic:
 *
 *   - No acceptor thread / eventfd handoff / mutex. ONE listener per port,
 *     shared by every worker: each worker registers it in its own epoll
 *     set with EPOLLEXCLUSIVE, so the kernel wakes exactly one worker per
 *     incoming connection -- and only a worker that is actually sitting
 *     in epoll_wait() can be the one. A worker busy inside a handler
 *     (MySQL, a 30 s upstream call) is simply skipped, which is what spreads
 *     the load: idle workers pull connections, busy ones don't get any.
 *
 *     (The previous design -- one SO_REUSEPORT listener per worker with
 *     a cBPF program choosing the worker by the CPU that processed the
 *     SYN -- put every connection on one worker on any machine where the
 *     NIC's packets are all processed on a single CPU, i.e. most VMs.
 *     It also never rebalanced: a worker stuck in a handler kept
 *     receiving its share while the others idled.)
 *   - Optional CPU pinning (-a 1, off by default): worker i runs on CPU
 *     i % ncpu. No SYN steering any more.
 *   - accept4(SOCK_NONBLOCK): no fcntl pair per connection. TCP_NODELAY is
 *     set once on the listener and inherited by every accepted socket.
 *   - TCP_DEFER_ACCEPT: the worker is only woken once the ClientHello /
 *     request line has arrived, and the handshake starts immediately.
 *   - Edge-triggered epoll, registered ONCE per connection for
 *     IN|OUT|RDHUP. The old conn_arm() did an epoll_ctl(MOD) on every
 *     WANT_READ <-> WANT_WRITE flip; now there are zero epoll_ctl calls
 *     after accept. rd_ready / wr_ready remember what the socket can do,
 *     so no read or write is attempted that would only return EAGAIN.
 *   - close() drops the fd from epoll by itself -- no EPOLL_CTL_DEL.
 *   - O(1) timer lists instead of walking every live connection once a
 *     second.
 *   - conn_t + its buffers are pooled per worker instead of
 *     calloc/malloc/free per connection.
 *   - Keep-alive + pipelining when a response allows it (Content-Length
 *     present, no "Connection: close"). handle_request() answers with
 *     "Connection: close" today, so it keeps closing exactly as before;
 *     drop that header from a route and it gets connection reuse for free.
 *   - Request log lines are batched per worker and written once per epoll
 *     batch instead of one unbuffered write(2) per line under stdio's
 *     global lock.
 *   - Clean close: close_notify, FIN, then drain until the peer's FIN, so
 *     unread input never turns our close into a RST that eats the reply.
 * ==================================================================== */
#ifndef EPOLL_HELPERS_C_INCLUDED
#define EPOLL_HELPERS_C_INCLUDED

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1u << 28)      /* Linux >= 4.5; older headers lack it */
#endif
#ifndef SO_BUSY_POLL
#define SO_BUSY_POLL 46
#endif
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif

/* epoll busy-poll parameters (Linux >= 6.9); defined here for older headers */
#ifndef EPIOCSPARAMS
struct epoll_params {
    uint32_t busy_poll_usecs;
    uint16_t busy_poll_budget;
    uint8_t  prefer_busy_poll;
    uint8_t  __pad;
};
#define EPIOCSPARAMS _IOW(0x8A, 0x01, struct epoll_params)
#endif

static inline uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);     /* vDSO, no syscall */
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* thread-locals for the coroutine runtime (Section 7) */
static __thread coro_t   *co_cur    = NULL;   /* running coroutine, NULL = worker loop itself */
static __thread worker_t *co_worker = NULL;   /* the worker this thread is, NULL on helpers   */
static void co_continue(coro_t *co);
#define STOP_GRACE_MS 5000                    /* wait this long for routes in flight at stop */

/* ==================================================================== *
 *  Section 1 -- listeners
 * ==================================================================== */

/* Kept for anything else that wants it; the engine itself no longer
   needs it (socket() and accept4() take SOCK_NONBLOCK directly). */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* One listening socket. Called ONCE per port; every worker then adds
   the same fd to its own epoll set (EPOLLEXCLUSIVE, see worker_main()).
   No SO_REUSEPORT: there is only one socket per port, and a second
   server instance on the same port should fail to bind, not silently
   steal half the connections. Options set here are copied onto every
   socket accept4() returns. */
static int make_listener(const char *addr, int port) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (s < 0) { perror("Socket creation failed"); return -1; }

    int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(s);
        return -1;
    }
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int defer = DEFER_ACCEPT_SECS;
    setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer, sizeof(defer));

    int tfo = FASTOPEN_QLEN;
    setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN, &tfo, sizeof(tfo));

    /* -B: spin on the NIC queue for up to N microseconds instead of
       sleeping until the interrupt -- lower latency, costs CPU. Inherited
       by every accepted socket. Off by default. */
    if (busy_poll_us > 0) {
        setsockopt(s, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_us, sizeof(busy_poll_us));
        setsockopt(s, SOL_SOCKET, SO_PREFER_BUSY_POLL, &one, sizeof(one));
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad bind address %s\n", addr);
        close(s);
        return -1;
    }
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "Bind %s:%d failed: %s\n", addr, port, strerror(errno));
        close(s);
        return -1;
    }
    if (listen(s, BACKLOG) < 0) {
        perror("Listen failed");
        close(s);
        return -1;
    }
    return s;
}

/* ==================================================================== *
 *  Section 2 -- connections: pool, timers, close
 * ==================================================================== */

static void conn_timer_unlink(conn_t *c) {
    if (c->tlist < 0) return;
    tlist_t *l = &c->w->tl[c->tlist];
    if (c->prev) c->prev->next = c->next; else l->head = c->next;
    if (c->next) c->next->prev = c->prev; else l->tail = c->prev;
    c->prev = c->next = NULL;
    c->tlist = -1;
}

/* Every list has one fixed timeout, so appending at the tail keeps each
   list sorted by deadline -- the sweep only ever looks at the head. */
static void conn_timer(conn_t *c, int list) {
    worker_t *w = c->w;
    uint64_t deadline = w->now_ms + w->tl[list].timeout_ms;
    if (c->tlist == list && w->tl[list].tail == c) { c->deadline = deadline; return; }
    conn_timer_unlink(c);
    tlist_t *l = &w->tl[list];
    c->tlist = list;
    c->deadline = deadline;
    c->next = NULL;
    c->prev = l->tail;
    if (l->tail) l->tail->next = c; else l->head = c;
    l->tail = c;
}

/* Same name and meaning as before: "this connection just made progress". */
static void conn_touch(conn_t *c) {
    c->last_active = time(NULL);
    if (c->tlist >= 0) conn_timer(c, c->tlist);
}

static conn_t *conn_new(worker_t *w, int fd, struct sockaddr_in *addr,
                        SSL_CTX *ctx, int is_tls) {
    conn_t *c = w->free_list;
    if (c) {
        w->free_list = c->next_pending;
        w->nfree--;
    } else {
        /* buffers are allocated lazily by in_reserve()/out_append() */
        c = calloc(1, sizeof(conn_t));
        if (!c) { perror("calloc conn"); return NULL; }
    }

    c->kind        = EP_CONN;
    c->fd          = fd;
    c->is_tls      = is_tls;
    c->ctx         = ctx;
    c->ssl         = NULL;
    c->address     = *addr;
    c->state       = is_tls ? CS_HANDSHAKE : CS_READ;
    c->want        = IO_OK;
    c->rd_ready    = 1;          /* TCP_DEFER_ACCEPT: data is already here */
    c->wr_ready    = 1;
    c->keepalive   = 0;
    c->close_after = 0;
    c->http10      = 0;
    c->rdhup       = 0;
    c->requests    = 0;
    c->shutdown_tries = 0;
    c->in_epoll    = 0;
    c->armed       = 0;
    c->last_active = time(NULL);
    c->in_len      = 0;
    if (c->in) c->in[0] = '\0';
    c->scan_from   = 0;
    c->headers_end = -1;
    c->need        = -1;
    c->out_len     = 0;
    c->out_sent    = 0;
    c->tlist       = -1;
    c->prev = c->next = NULL;
    c->next_pending = NULL;
    c->w           = w;
    inet_ntop(AF_INET, &c->address.sin_addr, c->ip, INET_ADDRSTRLEN);

    if (is_tls) {
        c->ssl = SSL_new(ctx);
        if (!c->ssl || SSL_set_fd(c->ssl, fd) != 1) {
            ERR_print_errors_fp(stderr);
            if (c->ssl) SSL_free(c->ssl);
            c->ssl = NULL;
            c->next_pending = w->free_list;      /* straight back to the pool */
            w->free_list = c;
            w->nfree++;
            return NULL;
        }
        SSL_set_accept_state(c->ssl);
    }
    return c;
}

/* Give both buffers back. An idle keep-alive connection then costs only
   its conn_t and the (buffer-less, see SSL_MODE_RELEASE_BUFFERS) SSL
   object -- a few KB instead of ~45 KB -- which is what lets one worker
   hold tens of thousands of open connections. */
static void conn_drop_buffers(conn_t *c) {
    free(c->in);  c->in  = NULL; c->in_cap  = 0;
    free(c->out); c->out = NULL; c->out_cap = 0;
    c->in_len = 0;
    c->out_len = c->out_sent = 0;
}

/* Close now; the conn_t itself is recycled at the end of the epoll batch
   so a later event in the same batch can never land on a reused object. */
static void conn_destroy(conn_t *c) {
    if (!c || c->state == CS_DEAD) return;
    worker_t *w = c->w;

    conn_timer_unlink(c);
    if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }  /* also drops the BIO */
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }     /* also leaves epoll  */

    c->state = CS_DEAD;
    c->next_pending = w->grave;
    w->grave = c;
    w->nlive--;
    atomic_fetch_sub_explicit(&g_live, 1, memory_order_relaxed);
}

static void worker_reap(worker_t *w) {
    while (w->grave) {
        conn_t *c = w->grave;
        w->grave = c->next_pending;
        if (w->nfree >= POOL_KEEP_FREE) {
            free(c->in); free(c->out); free(c);
            continue;
        }
        /* free + malloc, not realloc-to-shrink: shrinking a large (mmap'd)
           block and growing it again next request makes the kernel map and
           zero fresh pages every time; a plain free() lets malloc reuse
           the memory instead */
        if (c->in_cap > POOL_BUF_MAX)  conn_drop_buffers(c);
        if (c->out_cap > POOL_BUF_MAX) conn_drop_buffers(c);
        c->next_pending = w->free_list;
        w->free_list = c;
        w->nfree++;
    }
}

/* Close connections whose deadline passed. Touches only expired ones. */
static void worker_sweep_idle(worker_t *w) {
    for (int i = 0; i < TL_COUNT; i++)
        while (w->tl[i].head && w->tl[i].head->deadline <= w->now_ms)
            conn_destroy(w->tl[i].head);
}

/* ==================================================================== *
 *  Section 3 -- non-blocking I/O
 * ==================================================================== */

static io_state tls_err(conn_t *c, int r, int writing) {
    switch (SSL_get_error(c->ssl, r)) {
      case SSL_ERROR_WANT_READ:   return IO_WANT_READ;
      case SSL_ERROR_WANT_WRITE:  return IO_WANT_WRITE;
      case SSL_ERROR_ZERO_RETURN: return IO_EOF;
      case SSL_ERROR_SYSCALL:
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return writing ? IO_WANT_WRITE : IO_WANT_READ;
        return (errno == 0) ? IO_EOF : IO_ERR;
      case SSL_ERROR_SSL:
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
        if (ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
            return IO_EOF;              /* OpenSSL 3.x unclean close */
#endif
        return IO_ERR;
      default:
        return IO_ERR;
    }
}

/* One non-blocking read. Same contract as before. */
static io_state conn_recv(conn_t *c, void *buf, size_t len, size_t *got) {
    *got = 0;
    if (len == 0) return IO_OK;

    if (!c->is_tls) {
        for (;;) {
            ssize_t n = recv(c->fd, buf, len, 0);
            if (n > 0) {
                *got = (size_t)n;
                /* short read: the receive queue is empty; the next data
                   to arrive raises a fresh edge */
                if ((size_t)n < len) c->rd_ready = 0;
                return IO_OK;
            }
            if (n == 0) return IO_EOF;
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return IO_WANT_READ;
            return IO_ERR;
        }
    }

    size_t n = 0;
    ERR_clear_error();
    if (SSL_read_ex(c->ssl, buf, len, &n) == 1) { *got = n; return IO_OK; }
    return tls_err(c, 0, 0);
}

/* One non-blocking write. Same contract as before. */
static io_state conn_send(conn_t *c, const void *buf, size_t len, size_t *sent) {
    *sent = 0;
    if (len == 0) return IO_OK;

    if (!c->is_tls) {
        for (;;) {
            ssize_t n = send(c->fd, buf, len, MSG_NOSIGNAL);
            if (n >= 0) {
                *sent = (size_t)n;
                if ((size_t)n < len) c->wr_ready = 0;
                return IO_OK;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return IO_WANT_WRITE;
            return IO_ERR;
        }
    }

    size_t n = 0;
    ERR_clear_error();
    if (SSL_write_ex(c->ssl, buf, len, &n) == 1) { *sent = n; return IO_OK; }
    return tls_err(c, 0, 1);
}

/* Remember what the socket is waiting for; the next edge clears it. */
static drive_r conn_wait(conn_t *c, io_state st) {
    if (st == IO_WANT_READ) { c->rd_ready = 0; c->want = IO_WANT_READ;  }
    else                    { c->wr_ready = 0; c->want = IO_WANT_WRITE; }
    return DR_WAIT;
}

/* Make sure at least `extra` bytes (plus the NUL) fit in c->in. */
static int in_reserve(conn_t *c, size_t extra) {
    if (c->in_len + extra + 1 <= c->in_cap) return 0;

    size_t cap = c->in_cap ? c->in_cap : BUFFER_SIZE;
    while (cap < c->in_len + extra + 1) {
        if (cap > MAX_REQUEST_SIZE) return -1;
        cap *= 2;
    }
    if (cap > MAX_REQUEST_SIZE + BUFFER_SIZE) return -1;

    char *tmp = realloc(c->in, cap);
    if (!tmp) { perror("realloc request buffer"); return -1; }
    c->in     = tmp;
    c->in_cap = cap;
    return 0;
}

/* Append to the response buffer -- unchanged contract (still keeps
   c->out NUL-terminated). */
static int out_append(conn_t *c, const void *data, size_t len) {
    if (!data || len == 0) return 0;

    if (c->out_len + len + 1 > c->out_cap) {
        size_t cap = c->out_cap ? c->out_cap : BUFFER_SIZE;
        while (cap < c->out_len + len + 1) cap *= 2;
        char *tmp = realloc(c->out, cap);
        if (!tmp) { perror("realloc response buffer"); return -1; }
        c->out     = tmp;
        c->out_cap = cap;
    }

    memcpy(c->out + c->out_len, data, len);
    c->out_len += len;
    c->out[c->out_len] = '\0';
    return 0;
}

/* ==================================================================== *
 *  Section 4 -- HTTP framing (where a request ends, may we reuse the
 *               connection). parse_request() still does the real parse.
 * ==================================================================== */

static int name_is(const char *p, size_t n, const char *lower) {
    size_t l = strlen(lower);
    return n == l && strncasecmp(p, lower, l) == 0;
}

static int has_token(const char *v, size_t n, const char *tok) {
    size_t tl = strlen(tok), i = 0;
    while (i < n) {
        while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
        size_t s = i;
        while (i < n && v[i] != ',') i++;
        size_t e = i;
        while (e > s && (v[e-1] == ' ' || v[e-1] == '\t')) e--;
        if (e - s == tl && strncasecmp(v + s, tok, tl) == 0) return 1;
    }
    return 0;
}

typedef struct {
    long cl;            /* Content-Length, -1 = none               */
    int  bad;           /* HTTP status to fail with, 0 = fine      */
    int  te, conn_close, conn_ka, have_len;
} frame_t;

/* Walk "Name: value" lines in [p, end) without modifying them. */
static void scan_headers(const char *p, const char *end, frame_t *f, int is_request) {
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        const char *le = (nl > p && nl[-1] == '\r') ? nl - 1 : nl;
        if (le == p) break;
        const char *colon = memchr(p, ':', (size_t)(le - p));
        if (colon) {
            const char *v = colon + 1;
            while (v < le && (*v == ' ' || *v == '\t')) v++;
            const char *ve = le;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
            size_t nlen = (size_t)(colon - p), vl = (size_t)(ve - v);

            if (name_is(p, nlen, "content-length")) {
                f->have_len = 1;
                if (is_request) {
                    long x = 0;
                    if (vl == 0 || vl > 10) f->bad = vl ? 413 : 400;
                    for (size_t i = 0; i < vl && !f->bad; i++) {
                        if (v[i] < '0' || v[i] > '9') f->bad = 400;
                        else x = x * 10 + (v[i] - '0');
                    }
                    if (!f->bad && f->cl >= 0 && f->cl != x) f->bad = 400;  /* smuggling */
                    if (!f->bad) f->cl = x;
                }
            } else if (name_is(p, nlen, "transfer-encoding")) {
                f->te = 1;
                f->have_len = 1;
            } else if (name_is(p, nlen, "connection")) {
                if (has_token(v, vl, "close"))      f->conn_close = 1;
                if (has_token(v, vl, "keep-alive")) f->conn_ka = 1;
            }
        }
        p = nl + 1;
    }
}

/* 1 = whole request in c->in[0 .. need), 0 = need more, <0 = -(status) */
static int request_complete(conn_t *c) {
    if (c->headers_end < 0) {
        if (c->in_len < 4) return 0;
        char *p = memmem(c->in + c->scan_from, c->in_len - c->scan_from, "\r\n\r\n", 4);
        if (!p) {
            if (c->in_len > MAX_HEADER_BLOCK) return -431;      /* header flood */
            c->scan_from = c->in_len - 3;
            return 0;
        }
        size_t he = (size_t)(p - c->in) + 4;
        if (he > MAX_HEADER_BLOCK) return -431;

        const char *rl_nl = memchr(c->in, '\n', he);
        const char *rl_e  = (rl_nl > c->in && rl_nl[-1] == '\r') ? rl_nl - 1 : rl_nl;
        if (rl_e - c->in < 14) return -400;
        if      (!memcmp(rl_e - 8, "HTTP/1.1", 8)) c->http10 = 0;
        else if (!memcmp(rl_e - 8, "HTTP/1.0", 8)) c->http10 = 1;
        else return -505;

        frame_t f = { .cl = -1 };
        scan_headers(rl_nl + 1, c->in + he, &f, 1);
        if (f.bad) return -f.bad;
        if (f.te)  return -501;                 /* chunked uploads unsupported */

        long body = f.cl < 0 ? 0 : f.cl;
        if (body > (long)MAX_REQUEST_SIZE - (long)he) return -413;

        c->headers_end = (long)he;
        c->need        = (long)he + body;
        c->keepalive   = c->http10 ? f.conn_ka : !f.conn_close;
    }
    return ((long)c->in_len >= c->need) ? 1 : 0;
}

/* Reuse the connection only if the handler's response is self-delimiting
   and doesn't ask to close. */
static int response_wants_close(conn_t *c) {
    char *he = memmem(c->out, c->out_len, "\r\n\r\n", 4);
    if (!he || c->out_len < 12) return 1;
    const char *nl = memchr(c->out, '\n', (size_t)(he - c->out) + 2);
    frame_t f = { .cl = -1 };
    scan_headers(nl + 1, he + 4, &f, 0);
    if (f.conn_close) return 1;
    if (c->http10 && !f.conn_ka) return 1;
    if (!f.have_len) {
        int code = atoi(c->out + 9);
        if (code != 204 && code != 304) return 1;
    }
    return 0;
}

/* What a handler should put in its "Connection:" header. The engine
   then keeps the connection open only if the response says keep-alive
   and carries a Content-Length (see response_wants_close()). */
static const char *conn_keepalive_hdr(conn_t *c) {
    int ka = c->keepalive && keepalive_secs > 0 && !c->rdhup &&
             c->requests + 1 < MAX_KEEPALIVE_REQS;
    return ka ? "keep-alive" : "close";
}

static void send_error_close(conn_t *c, int status) {
    const char *txt =
        status == 400 ? "Bad Request" :
        status == 413 ? "Content Too Large" :
        status == 431 ? "Request Header Fields Too Large" :
        status == 501 ? "Not Implemented" :
        status == 503 ? "Service Unavailable" :
        status == 505 ? "HTTP Version Not Supported" : "Internal Server Error";
    char buf[160];
    int n = snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, txt);
    c->out_len = c->out_sent = 0;
    out_append(c, buf, (size_t)n);
    c->close_after = 1;
}

/* Per-worker log buffer: one write(2) per epoll batch, not per request. */
static void worker_log_flush(worker_t *w) {
    size_t off = 0;
    while (off < w->log_len) {
        ssize_t n = write(STDOUT_FILENO, w->log + off, w->log_len - off);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; }
        off += (size_t)n;
    }
    w->log_len = 0;
}

static void log_request(conn_t *c, Request *req) {
    if (!log_requests) return;
    worker_t *w = c->w;
    if (w->log_len > LOG_BUF_SIZE - 1024) worker_log_flush(w);
    int n = snprintf(w->log + w->log_len, LOG_BUF_SIZE - w->log_len,
        "%s%s%s: %s%s%s uri=%s%s%s version=%s%s%s host=%s%s%s [%s%s%s]\n",
        ANSI_MAGENTA, req->ip, ANSI_RESET,
        ANSI_GREEN, method_to_str(req->method), ANSI_RESET,
        ANSI_CYAN, req->uri ? req->uri : "(null)", ANSI_RESET,
        ANSI_YELLOW, req->version ? req->version : "(null)", ANSI_RESET,
        ANSI_BOLD_RED, get_header_default(req, "Host", "(none)"), ANSI_RESET,
        ANSI_DIM_GRAY, req->is_tls ? "https" : "http", ANSI_RESET);
    if (n > 0) {
        size_t room = LOG_BUF_SIZE - w->log_len;
        w->log_len += ((size_t)n < room) ? (size_t)n : room - 1;
    }
}

/* ==================================================================== *
 *  Section 5 -- the state machine
 *
 *    CS_HANDSHAKE -> CS_READ -> CS_HANDLE -> CS_WRITE -+-> CS_READ (keep-alive)
 *                                                      +-> CS_SHUTDOWN -> CS_LINGER
 * ==================================================================== */

static drive_r do_handshake(conn_t *c) {
    if (!c->is_tls) { c->state = CS_READ; return DR_AGAIN; }

    ERR_clear_error();
    int r = SSL_do_handshake(c->ssl);
    if (r == 1) {
        c->state = CS_READ;
        conn_timer(c, TL_IDLE);
        return DR_AGAIN;
    }
    io_state st = tls_err(c, r, 0);
    if (st == IO_WANT_READ || st == IO_WANT_WRITE) return conn_wait(c, st);

    /* handshake failed -- drop it quietly, as before */
    ERR_clear_error();
    conn_destroy(c);
    return DR_DEAD;
}

static drive_r do_read(conn_t *c) {
    for (;;) {
        int done = request_complete(c);          /* pipelined bytes first */
        if (done > 0) { c->state = CS_HANDLE; return DR_AGAIN; }
        if (done < 0) {
            send_error_close(c, -done);
            c->state = CS_WRITE;
            conn_timer(c, TL_IO);
            return DR_AGAIN;
        }

        /* Idle TLS connection (between requests): ask the kernel whether
           anything arrived before calling SSL_read(). SSL_read() allocates
           OpenSSL's ~17 KB record buffer and then sits on it until data
           comes -- FIONREAD costs the same one syscall as the EAGAIN it
           replaces and keeps an idle connection buffer-free. Bytes that
           arrive after this check raise a new edge, so nothing is missed. */
        if (c->rd_ready && c->is_tls && c->in_len == 0 && !SSL_has_pending(c->ssl)) {
            int avail = 0;
            if (ioctl(c->fd, FIONREAD, &avail) == 0 && avail == 0 && !c->rdhup)
                c->rd_ready = 0;
        }

        if (!c->rd_ready) {
            if (c->rdhup) { conn_destroy(c); return DR_DEAD; }  /* peer gone */
            c->want = IO_WANT_READ;
            return DR_WAIT;
        }

        size_t want = BUFFER_SIZE;
        if (c->need > 0 && (size_t)c->need > c->in_len && (size_t)c->need - c->in_len > want)
            want = (size_t)c->need - c->in_len;
        if (in_reserve(c, want) < 0) {
            send_error_close(c, 413);
            c->state = CS_WRITE;
            return DR_AGAIN;
        }

        size_t got = 0, before = c->in_len;
        io_state st = conn_recv(c, c->in + c->in_len, c->in_cap - c->in_len - 1, &got);

        if (st == IO_OK) {
            c->in_len += got;
            c->in[c->in_len] = '\0';
            c->last_active = time(NULL);
            /* a new request starts its deadline on its first byte; body
               bytes keep refreshing it, a header drip does not */
            if (before == 0 || c->headers_end >= 0) conn_timer(c, TL_IO);
            continue;
        }
        if (st == IO_WANT_READ || st == IO_WANT_WRITE) return conn_wait(c, st);

        if (st == IO_EOF && c->headers_end > 0) {
            /* peer closed mid-body: serve what we have, as before */
            c->need = (long)c->in_len;
            c->keepalive = 0;
            c->state = CS_HANDLE;
            return DR_AGAIN;
        }
        conn_destroy(c);
        return DR_DEAD;
    }
}

/* A complete request is in c->in[0 .. need). Three steps:

     do_handle()      isolate the request, parse it, log it, then start
                      the route as a coroutine (CS_BUSY, co_spawn)
     handler_run()    handle_request() / handle_http_redirect(): the
                      routes, MySQL, upstream calls -- fills c->out. Runs inside
                      the coroutine; whenever it has to wait it yields
                      and this worker goes on serving other connections
     handle_finish()  free the parse, restore pipelined bytes, decide
                      keep-alive, go to CS_WRITE

   A route that never waits (redirect, static file) finishes inside
   co_spawn() and do_handle() returns like a plain function call. While
   CS_BUSY the worker leaves c->in / c->out alone and only records epoll
   flags (rd_ready, rdhup) for handle_finish() to look at. */
static drive_r do_handle(conn_t *c) {
    c->hreq_len  = (size_t)c->need;
    c->hfull_len = c->in_len;

    /* hide pipelined bytes from parse_request(), which treats everything
       after the header block as the body */
    c->hsaved = c->in[c->hreq_len];
    c->in[c->hreq_len] = '\0';
    c->in_len = c->hreq_len;
    c->out_len = c->out_sent = 0;

    c->req = parse_request(c);
    if (!c->req.parsed) {
        free_headers(&c->req);       /* a partial table may have been built */
        conn_destroy(c);
        return DR_DEAD;
    }

    log_request(c, &c->req);

    /* The route's time is not the client's: no timer while busy (the
       old code re-read the clock after a 34 s upstream call for the same
       reason). handle_finish() re-arms it. */
    conn_timer_unlink(c);
    c->state = CS_BUSY;
    return co_spawn(c);              /* DR_AGAIN if it finished at once */
}

/* The one place a route is entered. Always inside a coroutine. */
static void handler_run(conn_t *c) {
    if (c->is_tls) handle_request(c, &c->req);          /* the real routes */
    else           handle_http_redirect(c, &c->req);    /* 302 to https    */
}

/* Routes write "Connection: keep-alive"; when the engine has decided to
   close instead (client asked for it, HTTP/1.0, limit reached, no
   Content-Length, error) the header is corrected in place so the
   client is told the truth. Same length, padded with spaces -- trailing
   whitespace in a header value is legal and ignored. */
static void response_say_close(conn_t *c) {
    char *he = memmem(c->out, c->out_len, "\r\n\r\n", 4);
    size_t hlen = he ? (size_t)(he - c->out) + 2 : c->out_len;
    char *p = c->out;
    while ((p = memmem(p, hlen - (size_t)(p - c->out), "\r\nConnection:", 13)) != NULL) {
        char *v = p + 13;
        while (*v == ' ' || *v == '\t') v++;
        if (!strncasecmp(v, "keep-alive", 10)) { memcpy(v, "close     ", 10); return; }
        p = v;
    }
}

static drive_r handle_finish(conn_t *c) {
    free_headers(&c->req);

    c->w->now_ms = mono_ms();
    c->last_active = time(NULL);

    /* keep whatever was pipelined behind this request */
    c->in[c->hreq_len] = c->hsaved;
    size_t rest = c->hfull_len - c->hreq_len;
    if (rest) memmove(c->in, c->in + c->hreq_len, rest);
    c->in_len = rest;
    c->in[rest] = '\0';
    c->headers_end = -1;
    c->need = -1;
    c->scan_from = 0;
    c->requests++;
    c->w->handled++;

    if (c->out_len == 0)
        send_error_close(c, 500);
    else if (!c->keepalive || keepalive_secs == 0 || c->rdhup ||
             c->requests >= MAX_KEEPALIVE_REQS || response_wants_close(c)) {
        c->close_after = 1;
        response_say_close(c);
    }

    c->state = CS_WRITE;
    conn_timer(c, TL_IO);
    return DR_AGAIN;
}

static drive_r do_write(conn_t *c) {
    int progressed = 0;
    while (c->out_sent < c->out_len) {
        if (!c->wr_ready) { c->want = IO_WANT_WRITE; goto wait; }
        size_t sent = 0;
        io_state st = conn_send(c, c->out + c->out_sent, c->out_len - c->out_sent, &sent);
        if (st == IO_OK) { c->out_sent += sent; progressed = 1; continue; }
        if (st == IO_WANT_WRITE || st == IO_WANT_READ) { conn_wait(c, st); goto wait; }

        /* IO_EOF or IO_ERR: peer is gone, nothing left to say */
        ERR_clear_error();
        conn_destroy(c);
        return DR_DEAD;
    }

    c->out_len = c->out_sent = 0;
    c->last_active = time(NULL);

    if (c->close_after) { c->state = CS_SHUTDOWN; return DR_AGAIN; }
    c->state = CS_READ;
    if (c->in_len == 0) conn_drop_buffers(c);       /* idle: hold no buffers */
    conn_timer(c, c->in_len ? TL_IO : TL_IDLE);
    return DR_AGAIN;

wait:
    if (progressed) { c->last_active = time(NULL); conn_timer(c, TL_IO); }
    return DR_WAIT;
}

/* close_notify (one-way -- we don't wait for theirs), then FIN, then
   drain input until the peer's FIN so the close is never a RST. */
static drive_r do_shutdown(conn_t *c) {
    if (c->is_tls && c->ssl) {
        ERR_clear_error();
        SSL_shutdown(c->ssl);
        c->shutdown_tries++;
    }
    shutdown(c->fd, SHUT_WR);
    c->state = CS_LINGER;
    c->rd_ready = 1;
    conn_timer(c, TL_LINGER);
    return DR_AGAIN;
}

static drive_r do_linger(conn_t *c) {
    char sink[4096];
    for (;;) {
        if (!c->rd_ready) { c->want = IO_WANT_READ; return DR_WAIT; }
        ssize_t n = recv(c->fd, sink, sizeof(sink), 0);
        if (n > 0) continue;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            c->rd_ready = 0;
            c->want = IO_WANT_READ;
            return DR_WAIT;
        }
        conn_destroy(c);                        /* FIN or error */
        return DR_DEAD;
    }
}

/* Run the state machine until it finishes or needs to wait. Never makes
   a syscall that the readiness flags say would return EAGAIN. */
static void conn_drive(conn_t *c) {
    for (;;) {
        if (c->state == CS_BUSY) return;   /* a handler thread has it */
        if (c->want == IO_WANT_READ  && !c->rd_ready) return;
        if (c->want == IO_WANT_WRITE && !c->wr_ready) return;
        c->want = IO_OK;

        drive_r r;
        switch (c->state) {
            case CS_HANDSHAKE: r = do_handshake(c); break;
            case CS_READ:      r = do_read(c);      break;
            case CS_HANDLE:    r = do_handle(c);    break;
            case CS_WRITE:     r = do_write(c);     break;
            case CS_SHUTDOWN:  r = do_shutdown(c);  break;
            case CS_LINGER:    r = do_linger(c);    break;
            default:           return;
        }
        if (r != DR_AGAIN) return;
    }
}

/* ==================================================================== *
 *  Section 6 -- workers
 * ==================================================================== */

/* Out of file descriptors: the pending connection would sit in the
   (level-triggered) listen queue and wake us in a busy loop. Spend the
   spare fd kept for exactly this, accept it, close it, take the spare back. */
static void worker_shed_one(worker_t *w, int lfd) {
    if (w->spare_fd >= 0) { close(w->spare_fd); w->spare_fd = -1; }
    int fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
    if (fd >= 0) close(fd);
    w->spare_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    w->shed++;
}

/* Called when EPOLLEXCLUSIVE picked this worker for a listener wakeup.
   Takes at most ACCEPT_BATCH connections and returns to epoll_wait();
   the listener is level-triggered, so anything still queued wakes a
   worker again at once. The batch is kept small so a burst is spread
   over the workers rather than one worker doing all its handshakes. */
static void worker_accept(worker_t *w, int lfd, int is_tls) {
    for (int k = 0; k < ACCEPT_BATCH; k++) {
        /* at the server-wide cap (fds / memory / -m): refuse politely
           instead of running the process out of memory or descriptors.
           Global, not per worker, so the whole budget is usable no
           matter how the connections happened to land. */
        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        int cfd = accept4(lfd, (struct sockaddr *)&addr, &alen, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno == EMFILE || errno == ENFILE) {
                if (w->now_ms - w->last_emfile_log > 1000) {
                    fprintf(stderr, "worker %d: out of file descriptors at %ld connections"
                                    " -- raise `ulimit -n` or lower -m\n", w->id,
                            atomic_load_explicit(&g_live, memory_order_relaxed));
                    w->last_emfile_log = w->now_ms;
                }
                worker_shed_one(w, lfd);
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("accept failed");
            return;
        }

        /* Claim a slot with ONE atomic add and check what it returned:
           two workers accepting at the same instant can never both get
           past the cap, and nobody holds a slot it did not use. The
           slot is released by conn_destroy() -- or right here if the
           connection never becomes live. */
        if (atomic_fetch_add_explicit(&g_live, 1, memory_order_relaxed) >= g_max_live
            && g_max_live) {
            atomic_fetch_sub_explicit(&g_live, 1, memory_order_relaxed);
            close(cfd);                  /* polite refusal: FIN, not a hang */
            w->shed++;
            continue;
        }

        conn_t *c = conn_new(w, cfd, &addr, w->ctx, is_tls);
        if (!c) {
            atomic_fetch_sub_explicit(&g_live, 1, memory_order_relaxed);
            close(cfd);
            continue;
        }

        struct epoll_event ev;
        ev.events   = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
        ev.data.ptr = c;
        w->nlive++;                  /* conn_destroy() decrements both counters */
        if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, cfd, &ev) < 0) {
            perror("epoll_ctl add");
            conn_destroy(c);
            continue;
        }
        c->in_epoll = 1;
        c->armed    = ev.events;
        w->accepted++;
        if (w->nlive > w->peak) w->peak = w->nlive;
        conn_timer(c, is_tls ? TL_HANDSHAKE : TL_IO);

        conn_drive(c);               /* first flight is already queued */
    }
}

static void *worker_main(void *arg) {
    worker_t *w = (worker_t *)arg;
    struct epoll_event events[MAX_EVENTS];

    /* every thread that talks to libmysqlclient must announce itself */
    mysql_thread_init();

    if (w->cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(w->cpu, &set);
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }

    w->spare_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);   /* see worker_shed_one() */
    w->tl[TL_HANDSHAKE].timeout_ms = TMO_HANDSHAKE_MS;
    w->tl[TL_IDLE].timeout_ms      = (uint64_t)(keepalive_secs ? keepalive_secs : IDLE_TIMEOUT_SECS) * 1000u;
    w->tl[TL_IO].timeout_ms        = (uint64_t)IDLE_TIMEOUT_SECS * 1000u;
    w->tl[TL_LINGER].timeout_ms    = TMO_LINGER_MS;

    if (busy_poll_us > 0) {                       /* epoll busy-poll, Linux >= 6.9 */
        struct epoll_params bp = { .busy_poll_usecs = (uint32_t)busy_poll_us,
                                   .busy_poll_budget = 64, .prefer_busy_poll = 1 };
        ioctl(w->epfd, EPIOCSPARAMS, &bp);        /* best effort */
    }

    /* The two listeners are shared by all workers. Level-triggered +
       EPOLLEXCLUSIVE: a new connection wakes ONE of the workers waiting
       in epoll_wait(), never all of them (no thundering herd) and never
       one that is busy in a handler. If the kernel is older than 4.5 and
       refuses the flag, fall back to a plain shared wakeup: every idle
       worker races for accept4(), the losers get EAGAIN -- still
       balanced, just noisier. */
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLEXCLUSIVE;
    ev.data.ptr = &w->tag_tls;
    if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->lfd_tls, &ev) < 0 && errno == EINVAL) {
        ev.events = EPOLLIN;
        if (w->id == 0) fprintf(stderr, "EPOLLEXCLUSIVE unsupported -- shared wakeups\n");
        epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->lfd_tls, &ev);
    }
    ev.data.ptr = &w->tag_plain;
    epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->lfd_plain, &ev);

    ev.events = EPOLLIN;                          /* private wake doorbell */
    ev.data.ptr = &w->tag_wake;
    epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->evfd, &ev);

    w->now_ms = mono_ms();
    uint64_t next_sweep = w->now_ms + SWEEP_INTERVAL_MS;
    uint64_t stop_deadline = 0;
    int running = 1, stopping = 0;
    co_worker = w;                    /* thread-local: which worker this thread is */

    while (running) {
        int n = epoll_wait(w->epfd, events, MAX_EVENTS, SWEEP_INTERVAL_MS);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        w->now_ms = mono_ms();

        for (int i = 0; i < n; i++) {
            int kind = *(int *)events[i].data.ptr;
            if (kind == EP_CONN) {
                conn_t *c = events[i].data.ptr;
                if (c->state == CS_DEAD) continue;      /* closed earlier this batch */
                uint32_t e = events[i].events;
                if (e & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) c->rd_ready = 1;
                if (e & (EPOLLOUT | EPOLLHUP | EPOLLERR))              c->wr_ready = 1;
                if (e & (EPOLLRDHUP | EPOLLHUP))                      c->rdhup = 1;
                conn_drive(c);
            } else if (kind == EP_LISTEN_TLS) {
                worker_accept(w, w->lfd_tls, 1);
            } else if (kind == EP_LISTEN_PLAIN) {
                worker_accept(w, w->lfd_plain, 0);
            } else if (kind == EP_CORO) {
                /* an upstream socket a route is waiting on became ready */
                coro_t *co = events[i].data.ptr;
                if (co->done) continue;                 /* finished earlier this batch */
                co->ready = events[i].events;
                co_continue(co);
            } else if (kind == EP_WAKE) {
                worker_drain_done(w);       /* coroutines woken by other threads */
                if (!stopping && atomic_load_explicit(&w->stop, memory_order_acquire)) {
                    /* Stop accepting, fail every wait that is still
                       pending, then keep looping until the routes in
                       flight have run to their end (they fail fast now)
                       -- but not forever. */
                    stopping = 1;
                    epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->lfd_tls, NULL);
                    epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->lfd_plain, NULL);
                    co_cancel_all(w);
                    stop_deadline = w->now_ms + STOP_GRACE_MS;
                }
            }
        }

        if (w->now_ms >= next_sweep) {
            worker_sweep_idle(w);
            co_sweep(w);                    /* route waits that timed out */
            next_sweep = w->now_ms + SWEEP_INTERVAL_MS;
        }
        worker_reap(w);
        co_reap(w);
        if (w->log_len) worker_log_flush(w);

        if (stopping && (w->co_inflight == 0 || w->now_ms >= stop_deadline))
            running = 0;
    }

    /* shutting down: close everything this worker owns. The listeners
       are shared -- main() closes them once every worker has joined. */
    if (w->co_inflight)
        fprintf(stderr, "worker %d: %d route(s) still in flight at exit\n", w->id, w->co_inflight);
    for (int i = 0; i < TL_COUNT; i++)
        while (w->tl[i].head) conn_destroy(w->tl[i].head);
    worker_reap(w);
    co_reap(w);
    while (w->free_list) {
        conn_t *c = w->free_list;
        w->free_list = c->next_pending;
        free(c->in); free(c->out); free(c);
    }
    while (w->co_free) {
        coro_t *co = w->co_free;
        w->co_free = co->next;
        munmap((char *)co->stack - CO_GUARD_SIZE, CO_GUARD_SIZE + co->stack_size);
        free(co);
    }
    if (w->log_len) worker_log_flush(w);
    if (w->spare_fd >= 0) close(w->spare_fd);
    mysql_thread_end();
    return NULL;
}

/* ==================================================================== *
 *  Section 7 -- coroutines: how a route waits without blocking its worker
 *
 *  Why: a route waits -- on MySQL, on DNS, and on upstream calls that can
 *  take tens of seconds. The thread that owns
 *  the sockets must not wait with it, or every other connection on that
 *  thread freezes for the duration. So each route runs as a coroutine:
 *  a function with its own stack that the worker can leave in the
 *  middle and come back to. When the route has to wait it *yields* --
 *  the worker returns to epoll_wait() and serves its other connections;
 *  when what it waited for happens (the socket is ready, the helper
 *  thread is done, the deadline passed) the worker *resumes* it exactly
 *  where it stopped. The route's code stays plain sequential C.
 *
 *  Two things can be waited for:
 *    co_wait_fd()   a non-blocking socket, registered ONESHOT in the
 *                   worker's own epoll with the coroutine as data.ptr
 *                   (EP_CORO). https_request()/http_request() use it.
 *    co_offload()   a function run on a helper thread (MySQL queries,
 *                   DNS); the helper pushes the coroutine onto its
 *                   worker's done stack and rings the eventfd.
 *  Both honour a deadline (the worker sweeps co_thead every
 *  SWEEP_INTERVAL_MS) and a cancel flag (shutdown).
 *
 *  Rules that keep this simple:
 *    - a coroutine never moves between threads: it runs, yields and
 *      resumes on the worker that owns its connection. Thread-locals,
 *      OpenSSL error queues and MySQL handles therefore behave.
 *    - the worker never touches c->in / c->out / c->req while the
 *      coroutine exists (CS_BUSY); it only sets epoll flag bits.
 *    - a route must not block the thread: use the co_ calls, and
 *      co_mutex_t instead of a pthread mutex across them.
 *    - stacks are CO_STACK_SIZE of virtual memory with a guard page;
 *      only touched pages are resident. Keep big buffers on the heap.
 * ==================================================================== */

/* ---- lifecycle --------------------------------------------------------- */

static coro_t *co_alloc(worker_t *w) {
    coro_t *co = w->co_free;
    if (co) {
        w->co_free = co->next;
        w->co_nfree--;
    } else {
        co = calloc(1, sizeof(coro_t));
        if (!co) { perror("calloc coroutine"); return NULL; }
        size_t total = CO_GUARD_SIZE + CO_STACK_SIZE;
        void *m = mmap(NULL, total, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_STACK, -1, 0);
        if (m == MAP_FAILED) { perror("mmap coroutine stack"); free(co); return NULL; }
        mprotect(m, CO_GUARD_SIZE, PROT_NONE);       /* overflow -> SIGSEGV */
        co->stack      = (char *)m + CO_GUARD_SIZE;
        co->stack_size = CO_STACK_SIZE;
    }
    co->kind = EP_CORO;
    co->w = w;
    co->c = NULL;
    co->done = 0;
    co->cancelled = 0;
    co->wait_fd = -1;
    co->fd_in_epoll = 0;
    co->ready = 0;
    co->deadline = 0;
    co->tprev = co->tnext = NULL;
    co->fn = NULL;
    co->arg = NULL;
    co->next = NULL;
    return co;
}

/* The coroutine's body. Returning lands in uc_link = the worker loop. */
static void co_entry(void) {
    coro_t *co = co_cur;
    handler_run(co->c);
    co->done = 1;
}

/* Switch into a coroutine; comes back when it yields or returns. */
static void co_resume(coro_t *co) {
    worker_t *w = co->w;
    co_cur = co;
    swapcontext(&w->main_ctx, &co->ctx);
    co_cur = NULL;
}

/* Called from inside a coroutine: hand the thread back to the worker. */
static void co_yield(void) {
    coro_t *co = co_cur;
    swapcontext(&co->ctx, &co->w->main_ctx);
}

/* --- timer list: coroutines waiting with a deadline --- */
static void co_timer_unlink(coro_t *co) {
    if (!co->deadline) return;
    worker_t *w = co->w;
    if (co->tprev) co->tprev->tnext = co->tnext; else w->co_thead = co->tnext;
    if (co->tnext) co->tnext->tprev = co->tprev; else w->co_ttail = co->tprev;
    co->tprev = co->tnext = NULL;
    co->deadline = 0;
}

static void co_timer_arm(coro_t *co, int timeout_ms) {
    co_timer_unlink(co);
    if (timeout_ms < 0) return;
    worker_t *w = co->w;
    co->deadline = mono_ms() + (uint64_t)timeout_ms;
    if (co->deadline == 0) co->deadline = 1;
    co->tnext = NULL;
    co->tprev = w->co_ttail;
    if (w->co_ttail) w->co_ttail->tnext = co; else w->co_thead = co;
    w->co_ttail = co;
}

/* The coroutine returned: recycle it and finish the connection's
   request. Runs on the worker loop. */
static drive_r co_retire(coro_t *co) {
    worker_t *w = co->w;
    conn_t *c = co->c;
    co_timer_unlink(co);
    if (co->fd_in_epoll) {               /* a route forgot co_close() */
        epoll_ctl(w->epfd, EPOLL_CTL_DEL, co->wait_fd, NULL);
        co->fd_in_epoll = 0;
    }
    w->co_inflight--;
    c->co = NULL;
    co->next = w->co_grave;              /* recycled at the end of the batch, so a */
    w->co_grave = co;                    /* stale event this batch cannot hit a reused one */
    return handle_finish(c);
}

/* Start the route for c. Returns DR_AGAIN if it ran to the end without
   waiting (the common case for redirects and static files), DR_WAIT if
   it is now parked and the worker should go on with other work. */
static drive_r co_spawn(conn_t *c) {
    worker_t *w = c->w;
    coro_t *volatile co = co_alloc(w);     /* volatile: getcontext() is a returns-twice call */
    if (!co) {
        send_error_close(c, 503);
        return handle_finish(c);
    }
    co->c = c;
    co->cancelled = atomic_load_explicit(&w->stop, memory_order_relaxed);
    c->co = co;

    getcontext(&co->ctx);
    co->ctx.uc_stack.ss_sp   = co->stack;
    co->ctx.uc_stack.ss_size = co->stack_size;
    co->ctx.uc_link          = &w->main_ctx;
    makecontext(&co->ctx, co_entry, 0);

    w->co_inflight++;
    co_resume(co);
    if (co->done) return co_retire(co);
    return DR_WAIT;
}

/* Resume a parked coroutine from the worker loop and, if it finished,
   write its answer out. */
static void co_continue(coro_t *co) {
    conn_t *c = co->c;
    co_resume(co);
    if (co->done) {
        co_retire(co);
        conn_drive(c);
    }
}

/* Move finished coroutines back to the pool (end of each epoll batch). */
static void co_reap(worker_t *w) {
    while (w->co_grave) {
        coro_t *co = w->co_grave;
        w->co_grave = co->next;
        if (w->co_nfree >= CO_POOL_KEEP) {
            munmap((char *)co->stack - CO_GUARD_SIZE, CO_GUARD_SIZE + co->stack_size);
            free(co);
            continue;
        }
        co->next = w->co_free;
        w->co_free = co;
        w->co_nfree++;
    }
}

/* Deadlines that passed: resume each with ready == 0. Collected first,
   because a resumed coroutine may arm a new timer. The temporary list
   is threaded through tnext, which is free once the entry is unlinked
   from the timer list -- NOT through `next`, which the coroutine may be
   using at the same time as its link in a wait queue (the DB pool's, a
   co_mutex's); clobbering it there corrupts that queue. */
static void co_sweep(worker_t *w) {
    uint64_t now = w->now_ms;
    coro_t *expired = NULL, *co = w->co_thead;
    while (co) {
        coro_t *n = co->tnext;
        if (co->deadline <= now) {
            co_timer_unlink(co);
            co->tnext = expired;
            expired = co;
        }
        co = n;
    }
    while (expired) {
        co = expired;
        expired = co->tnext;
        co->tnext = NULL;
        co->ready = 0;
        w->co_timeouts++;
        co_continue(co);
    }
}

/* Shutdown: every pending wait fails at once, so routes finish fast.
   Same tnext rule as co_sweep(). */
static void co_cancel_all(worker_t *w) {
    coro_t *list = NULL, *co = w->co_thead;
    while (co) {
        coro_t *n = co->tnext;
        co_timer_unlink(co);
        co->tnext = list;
        list = co;
        co = n;
    }
    while (list) {
        co = list;
        list = co->tnext;
        co->tnext = NULL;
        co->cancelled = 1;
        co->ready = 0;
        co_continue(co);
    }
}

/* ---- what a route may call ---------------------------------------------- */

/* Wait until a non-blocking socket is ready. Returns the epoll events
   (> 0), CO_TIMEOUT (0) when the deadline passes, -1 on error or when
   the server is stopping. Outside a coroutine it blocks in poll(). */
static int co_wait_fd(int fd, uint32_t events, int timeout_ms) {
    coro_t *co = co_cur;
    if (!co) {
        struct pollfd p = { .fd = fd, .events = 0, .revents = 0 };
        if (events & EPOLLIN)  p.events |= POLLIN;
        if (events & EPOLLOUT) p.events |= POLLOUT;
        int r = poll(&p, 1, timeout_ms);
        if (r < 0) return -1;
        if (r == 0) return CO_TIMEOUT;
        uint32_t ev = 0;
        if (p.revents & POLLIN)  ev |= EPOLLIN;
        if (p.revents & POLLOUT) ev |= EPOLLOUT;
        if (p.revents & (POLLERR | POLLHUP)) ev |= EPOLLERR;
        return (int)(ev ? ev : EPOLLERR);
    }
    if (co->cancelled) return -1;
    if (timeout_ms < 0) timeout_ms = HTTP_TIMEOUT_DEFAULT * 1000;   /* never wait unbounded */

    worker_t *w = co->w;
    struct epoll_event ev;
    ev.events   = events | EPOLLONESHOT | EPOLLRDHUP;
    ev.data.ptr = co;
    int op = EPOLL_CTL_ADD;
    if (co->fd_in_epoll) {
        if (co->wait_fd == fd) op = EPOLL_CTL_MOD;
        else { epoll_ctl(w->epfd, EPOLL_CTL_DEL, co->wait_fd, NULL); co->fd_in_epoll = 0; }
    }
    if (epoll_ctl(w->epfd, op, fd, &ev) < 0) {
        if (errno != EEXIST || epoll_ctl(w->epfd, EPOLL_CTL_MOD, fd, &ev) < 0)
            return -1;
    }
    co->wait_fd = fd;
    co->fd_in_epoll = 1;
    co->ready = 0;
    co_timer_arm(co, timeout_ms);

    co_yield();                               /* ... the worker serves others ... */

    co_timer_unlink(co);
    if (co->cancelled) return -1;
    if (co->ready == 0) return CO_TIMEOUT;
    return (int)co->ready;
}

/* Close a socket that was passed to co_wait_fd(). close() alone would
   leave the runtime thinking the fd number -- which the kernel may
   hand out again for a new client connection -- is still its own. */
static void co_close(int fd) {
    coro_t *co = co_cur;
    if (co && co->fd_in_epoll && co->wait_fd == fd) {
        co->fd_in_epoll = 0;                  /* close() drops it from epoll */
        co->wait_fd = -1;
    }
    close(fd);
}

static void co_sleep_ms(int ms) {
    coro_t *co = co_cur;
    if (!co) { usleep((useconds_t)ms * 1000u); return; }
    if (co->cancelled) return;
    co->ready = 0;
    co_timer_arm(co, ms);
    co_yield();
    co_timer_unlink(co);
}

/* Wake a parked coroutine from ANY thread: push it on its worker's done
   stack and ring that worker. The worker resumes it on its own thread. */
static void co_wake(coro_t *co) {
    worker_t *w = co->w;
    coro_t *old = atomic_load_explicit(&w->done_head, memory_order_relaxed);
    do { co->next = old; }
    while (!atomic_compare_exchange_weak_explicit(&w->done_head, &old, co,
                                                  memory_order_release,
                                                  memory_order_relaxed));
    uint64_t one = 1;
    if (write(w->evfd, &one, sizeof(one)) < 0) { /* EAGAIN: already rung */ }
}

/* Worker side: take everything other threads handed back, resume each. */
static void worker_drain_done(worker_t *w) {
    uint64_t v;
    while (read(w->evfd, &v, sizeof(v)) < 0 && errno == EINTR) { }

    coro_t *co = atomic_exchange_explicit(&w->done_head, NULL, memory_order_acquire);
    coro_t *fifo = NULL;                       /* the stack is LIFO; restore order */
    while (co) { coro_t *n = co->next; co->next = fifo; fifo = co; co = n; }

    while (fifo) {
        co = fifo;
        fifo = co->next;
        co->next = NULL;
        if (co->done) continue;
        co_continue(co);
    }
}

/* ---- helper threads: run a blocking call FOR a coroutine ------------- */

static struct {
    pthread_t      *tids;
    int             n;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    coro_t         *head, *tail;
    int             queued, peak_queued, stop;
    unsigned long   run;
} helpers;

static void *helper_main(void *arg) {
    (void)arg;
    mysql_thread_init();                     /* MySQL calls run here */
    /* Below the workers' priority (Linux: setpriority on a TID affects
       that thread only). A helper is parked while MySQL works and only
       burns CPU copying result rows; when the cores are saturated that
       copying must not pre-empt a worker's TLS and route work. Nice
       values are soft -- the helper still runs, just after the workers. */
    setpriority(PRIO_PROCESS, (id_t)syscall(SYS_gettid), HELPER_NICE);
    for (;;) {
        pthread_mutex_lock(&helpers.mu);
        while (!helpers.head && !helpers.stop) pthread_cond_wait(&helpers.cv, &helpers.mu);
        coro_t *co = helpers.head;
        if (!co) { pthread_mutex_unlock(&helpers.mu); break; }
        helpers.head = co->next;
        if (!helpers.head) helpers.tail = NULL;
        helpers.queued--;
        helpers.run++;
        pthread_mutex_unlock(&helpers.mu);

        co->next = NULL;
        co->fn(co->arg);
        co_wake(co);                          /* back to its worker */
    }
    mysql_thread_end();
    return NULL;
}

static int helpers_start(int nthreads) {
    memset(&helpers, 0, sizeof(helpers));
    pthread_mutex_init(&helpers.mu, NULL);
    pthread_cond_init(&helpers.cv, NULL);
    helpers.tids = calloc((size_t)nthreads, sizeof(pthread_t));
    if (!helpers.tids) { perror("calloc helpers"); return -1; }
    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&helpers.tids[i], NULL, helper_main, NULL) != 0) {
            perror("helper thread creation failed");
            helpers.n = i;
            return -1;
        }
        helpers.n = i + 1;
    }
    return 0;
}

/* After the workers have exited: nothing can be queued any more. */
static void helpers_stop(void) {
    pthread_mutex_lock(&helpers.mu);
    helpers.stop = 1;
    pthread_cond_broadcast(&helpers.cv);
    pthread_mutex_unlock(&helpers.mu);
    for (int i = 0; i < helpers.n; i++) pthread_join(helpers.tids[i], NULL);
    free(helpers.tids);
    helpers.tids = NULL;
}

static void helpers_stats(unsigned long *run, int *peak_queued) {
    *run = helpers.run;
    *peak_queued = helpers.peak_queued;
}

/* Run fn(arg) on a helper thread; this coroutine continues when it has
   returned. Outside a coroutine, or once the helpers are gone, fn runs
   right here. */
static void co_offload(void (*fn)(void *), void *arg) {
    coro_t *co = co_cur;
    if (!co || helpers.n == 0) { fn(arg); return; }

    co->fn = fn;
    co->arg = arg;
    pthread_mutex_lock(&helpers.mu);
    if (helpers.stop) {
        pthread_mutex_unlock(&helpers.mu);
        fn(arg);
        co->fn = NULL;
        return;
    }
    co->next = NULL;
    if (helpers.tail) helpers.tail->next = co; else helpers.head = co;
    helpers.tail = co;
    if (++helpers.queued > helpers.peak_queued) helpers.peak_queued = helpers.queued;
    pthread_cond_signal(&helpers.cv);
    pthread_mutex_unlock(&helpers.mu);

    co_yield();
    co->fn = NULL;
}

/* ---- co_mutex: a lock a route may hold across a yield ------------------
   A pthread mutex is owned by a THREAD; two routes on the same worker
   taking it would deadlock that thread. This one is owned by the
   coroutine: waiters park, unlock() hands the lock to the first waiter
   and wakes it. Outside a coroutine it behaves like a normal mutex. */
static void co_mutex_lock(co_mutex_t *m) {
    pthread_mutex_lock(&m->mu);
    if (!m->locked) {
        m->locked = 1;
        pthread_mutex_unlock(&m->mu);
        return;
    }
    coro_t *co = co_cur;
    if (!co) {                                /* a plain thread: block on the condvar */
        while (m->locked) pthread_cond_wait(&m->cv, &m->mu);
        m->locked = 1;
        pthread_mutex_unlock(&m->mu);
        return;
    }
    co->next = NULL;
    if (m->tail) m->tail->next = co; else m->head = co;
    m->tail = co;
    pthread_mutex_unlock(&m->mu);
    co_yield();                               /* unlock() hands us the lock */
}

static void co_mutex_unlock(co_mutex_t *m) {
    pthread_mutex_lock(&m->mu);
    coro_t *co = m->head;
    if (co) {
        m->head = co->next;
        if (!m->head) m->tail = NULL;
        pthread_mutex_unlock(&m->mu);         /* still locked: now owned by co */
        co_wake(co);
        return;
    }
    m->locked = 0;
    pthread_cond_signal(&m->cv);
    pthread_mutex_unlock(&m->mu);
}

/* ---- MySQL: the connection pool and the yielding calls ----------------
   A route takes a connection with connect_db() and returns it with
   db_release(). Each query runs on a helper thread (co_offload) while
   the route yields; the handle is only ever used by one thread at a
   time, which is all libmysqlclient asks. On acquire the session is
   reset (COM_RESET_CONNECTION; ping on servers without it) so a route
   can never see another route's leftovers. */

static struct {
    pthread_mutex_t mu;
    MYSQL         **idle;
    int             nidle, idle_cap;
    int             open, max;
    coro_t         *whead, *wtail;           /* routes waiting for a free one */
    int             nwait;
    unsigned long   waits;
    int             can_reset;
    int             stop;
} dbp;

static int db_pool_init(int max) {
    memset(&dbp, 0, sizeof(dbp));
    pthread_mutex_init(&dbp.mu, NULL);
    dbp.max = max;
    dbp.can_reset = 1;
    dbp.idle = calloc((size_t)max, sizeof(MYSQL *));
    return dbp.idle ? 0 : -1;
}

struct db_task { MYSQL *m; int rc; };
static void db_task_open (void *a) { struct db_task *t = a; t->m = db_open_raw(); }

/* A slot was given up without a connection to hand over (an open or a
   reset failed): let one waiting route try for itself instead of
   sleeping out its DB_WAIT_MS. Caller holds dbp.mu. */
#define DB_RETRY ((MYSQL *)1)
static coro_t *db_pop_waiter_locked(MYSQL *give) {
    coro_t *co = dbp.whead;
    if (!co) return NULL;
    dbp.whead = co->next;
    if (!dbp.whead) dbp.wtail = NULL;
    dbp.nwait--;
    co->next = NULL;
    co->arg = give;                       /* under the lock: see connect_db() */
    return co;
}
static void db_slot_freed(void) {         /* dbp.open was decremented */
    pthread_mutex_lock(&dbp.mu);
    coro_t *co = db_pop_waiter_locked(DB_RETRY);
    pthread_mutex_unlock(&dbp.mu);
    if (co) co_wake(co);
}
static void db_task_close(void *a) { struct db_task *t = a; mysql_close(t->m); }
static void db_task_reset(void *a) {
    struct db_task *t = a;
    if (dbp.can_reset) {
        if (mysql_reset_connection(t->m) == 0) { t->rc = 0; return; }
        if (mysql_ping(t->m) == 0) { dbp.can_reset = 0; t->rc = 0; return; }
        t->rc = -1;
        return;
    }
    t->rc = mysql_ping(t->m) == 0 ? 0 : -1;
}

MYSQL *connect_db(void) {
    if (dbp.max <= 0) return NULL;            /* USE_DATABASE 0: no pool exists */
    for (;;) {
        pthread_mutex_lock(&dbp.mu);
        if (dbp.stop) { pthread_mutex_unlock(&dbp.mu); return NULL; }

        if (dbp.nidle > 0) {
            MYSQL *m = dbp.idle[--dbp.nidle];
            pthread_mutex_unlock(&dbp.mu);
            struct db_task t = { m, 0 };
            co_offload(db_task_reset, &t);
            if (t.rc == 0) return m;
            co_offload(db_task_close, &t);    /* server went away: drop it, try again */
            pthread_mutex_lock(&dbp.mu);
            dbp.open--;
            pthread_mutex_unlock(&dbp.mu);
            db_slot_freed();
            continue;
        }

        if (dbp.open < dbp.max) {
            dbp.open++;
            pthread_mutex_unlock(&dbp.mu);
            struct db_task t = { NULL, 0 };
            co_offload(db_task_open, &t);
            if (t.m) return t.m;
            pthread_mutex_lock(&dbp.mu);
            dbp.open--;
            pthread_mutex_unlock(&dbp.mu);
            db_slot_freed();
            return NULL;                      /* unreachable: the route answers 500 */
        }

        /* every connection is in use: park until db_release() hands one over */
        coro_t *co = co_cur;
        if (!co || co->cancelled) { pthread_mutex_unlock(&dbp.mu); return NULL; }
        co->arg = NULL;
        co->next = NULL;
        if (dbp.wtail) dbp.wtail->next = co; else dbp.whead = co;
        dbp.wtail = co;
        dbp.nwait++;
        dbp.waits++;
        pthread_mutex_unlock(&dbp.mu);

        co_timer_arm(co, DB_WAIT_MS);
        co_yield();
        co_timer_unlink(co);

        MYSQL *m = co->arg;                   /* set under dbp.mu: a connection, DB_RETRY, or NULL */
        if (!m) {
            /* timed out or cancelled. Either we are still on the wait
               list (remove ourselves, give up) or db_release() took us
               off it a moment ago and its wake is on the way: absorb
               that wake with one more yield and take the connection. */
            pthread_mutex_lock(&dbp.mu);
            coro_t **pp = &dbp.whead, *prev = NULL;
            while (*pp && *pp != co) { prev = *pp; pp = &(*pp)->next; }
            int still_waiting = (*pp == co);
            if (still_waiting) {
                *pp = co->next;
                if (dbp.wtail == co) dbp.wtail = prev;
                dbp.nwait--;
            }
            pthread_mutex_unlock(&dbp.mu);
            co->next = NULL;
            if (still_waiting) return NULL;
            co_yield();                       /* the hand-over wake */
            m = co->arg;
        }
        co->arg = NULL;
        if (m == DB_RETRY) {                  /* a slot opened up: go round again */
            if (co->cancelled) return NULL;
            continue;
        }
        if (co->cancelled) { db_release(m); return NULL; }
        struct db_task t = { m, 0 };
        co_offload(db_task_reset, &t);
        if (t.rc == 0) return m;
        co_offload(db_task_close, &t);
        pthread_mutex_lock(&dbp.mu);
        dbp.open--;
        pthread_mutex_unlock(&dbp.mu);
    }
}

void db_release(MYSQL *m) {
    if (!m) return;
    pthread_mutex_lock(&dbp.mu);
    coro_t *co = db_pop_waiter_locked(m);     /* hand it straight to a waiting route */
    if (co) {
        pthread_mutex_unlock(&dbp.mu);
        co_wake(co);
        return;
    }
    if (dbp.nidle < dbp.max) dbp.idle[dbp.nidle++] = m;
    else { dbp.open--; pthread_mutex_unlock(&dbp.mu); mysql_close(m); return; }
    pthread_mutex_unlock(&dbp.mu);
}

static void db_pool_shutdown(void) {
    pthread_mutex_lock(&dbp.mu);
    dbp.stop = 1;
    while (dbp.nidle > 0) mysql_close(dbp.idle[--dbp.nidle]);
    pthread_mutex_unlock(&dbp.mu);
}

static void db_pool_stats(int *open, int *idle, unsigned long *waits) {
    *open = dbp.open; *idle = dbp.nidle; *waits = dbp.waits;
}

/* The calls that talk to the server, run on a helper while the route
   yields. Everything else in the MySQL API (fetch_row, free_result,
   num_rows, error, escape_string, insert_id ...) works on data already
   in memory and is used unchanged. */
struct q_task { MYSQL *m; const char *q; unsigned long len; int rc; MYSQL_RES *res; };
static void q_task_query      (void *a) { struct q_task *t = a; t->rc  = mysql_query(t->m, t->q); }
static void q_task_real_query (void *a) { struct q_task *t = a; t->rc  = mysql_real_query(t->m, t->q, t->len); }
static void q_task_store      (void *a) { struct q_task *t = a; t->res = mysql_store_result(t->m); }

int co_mysql_query(MYSQL *m, const char *q) {
    struct q_task t = { m, q, 0, 0, NULL };
    co_offload(q_task_query, &t);
    return t.rc;
}
int co_mysql_real_query(MYSQL *m, const char *q, unsigned long len) {
    struct q_task t = { m, q, len, 0, NULL };
    co_offload(q_task_real_query, &t);
    return t.rc;
}
MYSQL_RES *co_mysql_store_result(MYSQL *m) {
    struct q_task t = { m, NULL, 0, 0, NULL };
    co_offload(q_task_store, &t);
    return t.res;
}

#endif /* EPOLL_HELPERS_C_INCLUDED */
