/* ====================================================================
 *  EPOLL_VANILLA/main.c -- a generic HTTPS/HTTP server to build on
 *
 *  What it is: an epoll + OpenSSL web server in C that serves static
 *  sites by virtual host, with one place to add your own routes
 *  (handle_request() in handlers.c). Everything about scale is already
 *  solved so a route author never has to think about it:
 *
 *      epoll workers     one per hardware thread; accept, TLS, HTTP
 *                        framing, I/O, timers. They never block.
 *      route coroutines  every request runs handle_request() as a
 *                        coroutine on its worker. When the route has to
 *                        wait (an upstream HTTP call, a database query,
 *                        a DNS lookup) it yields and the worker serves
 *                        its other connections; the route resumes where
 *                        it stopped when the wait is over. Routes are
 *                        plain sequential C.
 *      helper threads    run the few library calls that cannot yield
 *                        (MySQL queries, getaddrinfo) on a route's
 *                        behalf, a few ms each.
 *      MySQL pool        optional (USE_DATABASE below): connect_db() /
 *                        db_release(), co_mysql_query() & co.
 *
 *  The connection path: one listener pair (:443 TLS, :80 redirect)
 *  shared by every worker through EPOLLEXCLUSIVE, edge-triggered epoll
 *  registered once per connection, O(1) timer lists, pooled connection
 *  objects, HTTP/1.1 keep-alive + pipelining, batched request logging,
 *  a connection cap derived from free RAM and the fd limit, kernel
 *  settings checked and applied at startup (os_tune.c). TLS: 1.2+,
 *  AEAD suites, X25519, ALPN http/1.1, tickets, release-buffers, kTLS
 *  when the kernel has it, RSA and ECDSA chains side by side.
 *
 *  Layout -- includes, macros, globals, typedefs, ONE forward-declaration
 *  block covering every function in all files, main(), then the
 *  definitions. The definitions are split across textually-included
 *  files (NOT separate translation units -- do not add them to the gcc
 *  line in ./compile):
 *
 *      main.c            types, globals, the forward block, main(),
 *                        startup path discovery, argument parsing, the
 *                        general helpers (get_file, mime, https_request,
 *                        http_request, SSL context, signals, ...)
 *      os_tune.c         kernel settings: check + live apply at startup
 *      epoll_helpers.c   the engine: listeners, the per-connection state
 *                        machine, non-blocking I/O, the workers, the
 *                        coroutine runtime, helpers, the MySQL pool
 *      handlers.c        parse_request(), the Request header-table API,
 *                        handle_request() (YOUR ROUTES) and the :80
 *                        redirect
 *      cJSON.c/h         JSON (compiled separately, on the gcc line)
 *
 *  Paths are discovered at startup, not compiled in. resolve_paths()
 *  reads /proc/self/exe, so wherever the tree is checked out:
 *
 *      home       .../EPOLL_VANILLA/      the binary's own folder
 *      workspace  .../                    one up -- the site root: a
 *                                         folder per virtual host, e.g.
 *                                         example.com/index.html
 *      cert_dir   certs/                  fullchain.pem + privkey.pem,
 *                                         plus any fullchain.pem.<tag>
 *                                         + privkey.pem.<tag>
 *
 *  certs/ is looked for next to the binary first, then in the nearest
 *  parent folder that has it (up to 3 levels). -r / -c override both.
 *
 *  To make this server yours: set BIND_ADDR / DOMAIN below, drop your
 *  site folder(s) in the site root and your certificate in certs/, and
 *  add routes to handle_request() -- see HANDLER_README.c.
 * ==================================================================== */

/* ---- THE ONE SWITCH ----------------------------------------------------
   1 = use MySQL: a connection pool is opened at startup (credentials in
       DB_* below), routes get connections with connect_db()/db_release()
       and query with co_mysql_query()/co_mysql_store_result().
   0 = no database: nothing is connected, connect_db() returns NULL, the
       pool and the -D flag are ignored. The MySQL client library is
       still linked (./compile), so flipping to 1 needs no other change. */
#define USE_DATABASE 0

#define _GNU_SOURCE         /* accept4, memmem, pthread_setaffinity_np */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <mysql.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/resource.h>   /* RLIMIT_NOFILE, setpriority */
#include <sys/syscall.h>    /* SYS_gettid for per-thread nice */
#include <sys/ioctl.h>      /* FIONREAD */
#include <signal.h>
#include <limits.h>
#include <netdb.h>

#include <errno.h>          /* errno, strerror                           */
#include <time.h>           /* time()                                    */
#include <strings.h>        /* strcasecmp, strncasecmp                   */
#include <stdint.h>
#include <stdatomic.h>      /* global live-connection counter            */
#include <ucontext.h>       /* coroutines: a route yields while it waits */
#include <sys/mman.h>       /* coroutine stacks                          */
#include <poll.h>           /* co_wait_fd() outside a coroutine          */

/* --- the epoll machinery --- */
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>    /* TCP_NODELAY, TCP_DEFER_ACCEPT, TCP_FASTOPEN */
#include <sched.h>          /* CPU pinning                               */

#include "cJSON.h"          /* JSON: see JSON_README.c */

#define BACKLOG 65535        /* per listener, capped by net.core.somaxconn
                                (os_tune.c raises somaxconn to match)     */
#define DEBUG_LEVEL 0

/* The only debug hook with a call site (parse_request dumps the header
   table). The other DEBUG_LEVEL bits had no users and were dropped. */
#define TOKEN_DUMP if(DEBUG_LEVEL & 1)

#define PORT 443
#define HTTP_PORT 80
#define BIND_ADDR "0.0.0.0"       /* -b overrides */
#define DOMAIN "example.com"       /* -d overrides: the fallback virtual host */

/* Filesystem paths are NOT compile-time constants any more. resolve_paths()
   reads /proc/self/exe at startup and derives everything from where the
   binary actually sits, so the tree can be moved or checked out anywhere
   without editing this file:

       home       = the directory holding the binary   .../site-root/EPOLL_VANILLA/
       workspace  = one folder up, the site root       .../site-root/
       cert_dir   = certs/ next to the binary or in the nearest parent

   `workspace` replaces what used to be the HOME macro (site lookups:
   get_file, is_file_allowed, is_known_host). `cert_dir` replaces the
   CERT_FILE / KEY_FILE macros. Both can be overridden with -r and -c. */
#define CERT_SUBDIR "certs/"
#define CERT_NAME   "fullchain.pem"
#define KEY_NAME    "privkey.pem"

/* MySQL credentials -- only used when USE_DATABASE is 1. "localhost"
   makes libmysqlclient use the unix socket. Replace the dummies. */
#define DB_HOST     "localhost"
#define DB_USERNAME "dbuser"
#define DB_PASSWORD "dbpassword"
#define DB_SCHEMA   "dbname"

#define ANSI_RESET    "\e[0m"
#define ANSI_GREEN    "\e[32m"
#define ANSI_CYAN     "\e[36m"
#define ANSI_YELLOW   "\e[33m"
#define ANSI_BOLD_RED "\e[1;31m"
#define ANSI_DIM_GRAY "\e[2;37m"
#define ANSI_MAGENTA  "\e[35m"

#define BUFFER_SIZE 8192
#define MAX_HEADER_BLOCK 65536
#define MAX_REQUEST_SIZE (8 * 1024 * 1024)   /* headers + body hard cap   */

/* epoll engine tuning */
#define MAX_EVENTS          128   /* epoll_wait batch size per worker     */
#define DEFAULT_WORKERS       0   /* 0 = one epoll worker per hardware    */
                                  /* thread (they never block now)        */
#define MAX_WORKERS         256   /* hard ceiling for -w / the auto default */

/* Routes run as coroutines on the epoll workers and yield while they
   wait, so there is no handler thread per request any more. Two pools
   remain:
   - helper threads: run the few library calls that have no
     non-blocking form (MySQL queries, DNS lookups) while the route
     yields. A query occupies a helper for its duration, so there is
     one helper per pooled MySQL connection -- every connection can be
     mid-query at once and helpers are never the limit -- plus
     HELPERS_FOR_DNS. Parked threads cost nothing, so this is not a
     knob: it follows -D.
   - MySQL connections (-D): a route takes one with connect_db() and
     gives it back with db_release(); the pool is capped below the
     server's max_connections (read at startup). */
#define HELPERS_FOR_DNS       4   /* helpers beyond the MySQL pool size   */
#define HELPERS_MIN          16
#define HELPERS_MAX         512
#define DB_POOL_DEFAULT     256   /* -D; clamped to max_connections minus */
#define DB_RESERVE_PCT       10   /*   this share (at least DB_RESERVE_MIN) */
#define DB_RESERVE_MIN       10   /*   left for the mysql CLI, backups, ... */
#define HELPER_NICE           5   /* helpers run below the workers' priority:
                                     when the cores are saturated the event
                                     loops (TLS, parsing, routes) win     */
#define DB_POOL_MAX       10000
#define DB_WAIT_MS        10000   /* connect_db() waits this long for a   */
                                  /* free connection, then returns NULL   */

/* coroutine stacks: virtual size (only touched pages are resident) */
#define CO_STACK_SIZE   (256 * 1024)
#define CO_GUARD_SIZE      4096   /* overflow -> SIGSEGV, never silent    */
#define CO_POOL_KEEP        256   /* idle coroutines kept per worker      */

/* upstream HTTP clients: https_request() / http_request(). The guard
   exists to free a route whose call is truly stuck, never to cut a
   slow-but-working one: set it to about three times the slowest
   upstream reply you expect. */
#define HTTP_TIMEOUT_DEFAULT 60   /* seconds for the whole exchange       */
#define IDLE_TIMEOUT_SECS    15   /* connection killed if it goes quiet   */
#define SWEEP_INTERVAL_MS   250   /* epoll_wait timeout / sweep cadence   */
#define SHUTDOWN_MAX_TRIES    2   /* SSL_shutdown attempts before close   */

/* TCP path tuning (see the notes at the top of epoll_helpers.c) */
#define ACCEPT_BATCH          8   /* accepts per listener wakeup. Workers no
                                     longer block, so a batch only costs the
                                     TLS handshakes it serialises (~1 ms each);
                                     8 keeps bursts spread across workers  */
#define DEFER_ACCEPT_SECS     5   /* TCP_DEFER_ACCEPT                     */
#define FASTOPEN_QLEN      4096   /* TCP_FASTOPEN queue                   */
#define DEFAULT_KEEPALIVE    15   /* -k: keep-alive idle seconds, 0 = off */
#define MAX_KEEPALIVE_REQS 10000  /* requests per connection              */
#define TMO_HANDSHAKE_MS  10000
#define TMO_LINGER_MS      2000   /* wait for the peer's FIN after ours   */
#define POOL_KEEP_FREE     4096   /* pooled conn_t per worker             */
#define POOL_BUF_MAX      65536   /* shrink buffers above this on reuse   */
#define LOG_BUF_SIZE      65536   /* per-worker request log batch         */

char * domain;
char * bind_addr;
int https_port;
int http_port;
int num_workers;

int keepalive_secs = DEFAULT_KEEPALIVE; /* -k */
int log_requests   = 1;                 /* -l */
int max_conns      = 0;                 /* -m, 0 = as many as fds allow */
int busy_poll_us   = 0;                 /* -B, 0 = off */
int pin_cpus       = 0;                 /* -a: pin worker i to CPU i % ncpu */
int num_helpers    = 0;                 /* sized from the MySQL pool (-D)   */
int db_pool_max    = DB_POOL_DEFAULT;   /* -D                               */
int g_ncpu         = 1;

/* Filled in by resolve_paths() before the arguments are parsed; -r and -c
   may then replace workspace / cert_dir. All three keep a trailing '/'. */
char * home;        /* directory this binary lives in                     */
char * workspace;   /* one folder up -- the site root, was the HOME macro */
char * cert_dir;    /* where fullchain.pem and privkey.pem are read from  */
char   cert_file[PATH_MAX];
char   key_file[PATH_MAX];

typedef struct {
    size_t size;
    char *data;
} FileInfo;

typedef struct {
    char *headers;
    size_t headers_len;
    char *body;
    size_t body_len;
    char status[32];
} Response;

typedef enum {
    M_OPTIONS,
    M_DELETE,
    M_CONNECT,
    M_GET,
    M_PUT,
    M_PATCH,
    M_TRACE,
    M_HEAD,
    M_POST,
    M_UNSUPPORTED
} Method;

/* ------------------------------------------------------------------ *
 *  Connection state machine
 * ------------------------------------------------------------------ */
typedef enum {
    CS_HANDSHAKE,   /* SSL_accept in progress (skipped for plain :80)   */
    CS_READ,        /* pulling request-line + headers + body            */
    CS_HANDLE,      /* transient: parse, then start the route coroutine */
    CS_BUSY,        /* the route coroutine owns c->in / c->out; it is   */
                    /* either running or waiting on an upstream/helper  */
    CS_WRITE,       /* draining the out buffer                          */
    CS_SHUTDOWN,    /* close_notify + FIN                               */
    CS_LINGER,      /* drain input until the peer's FIN (avoids a RST)  */
    CS_DEAD         /* closed, recycled at the end of the epoll batch   */
} conn_state;

/* what the last non-blocking I/O attempt wants next */
typedef enum {
    IO_OK,
    IO_WANT_READ,
    IO_WANT_WRITE,
    IO_EOF,
    IO_ERR
} io_state;

/* what conn_drive()'s per-state helpers report back */
typedef enum {
    DR_AGAIN,   /* state advanced, run the machine again                */
    DR_WAIT,    /* armed in epoll, return to the loop                   */
    DR_DEAD     /* connection destroyed, pointer no longer valid        */
} drive_r;

typedef struct worker worker_t;
typedef struct conn   conn_t;
typedef struct coro   coro_t;

/* things that can sit in epoll's data.ptr -- the first int says which.
   EP_CORO is an upstream socket a route coroutine is waiting on.
   EP_WAKE is the worker's eventfd: helper threads and other workers ring
   it when a coroutine of this worker may continue, and main() rings it
   (with w->stop set) to shut the worker down. */
enum { EP_CONN = 1, EP_LISTEN_TLS, EP_LISTEN_PLAIN, EP_CORO, EP_WAKE };

/* ------------------------------------------------------------------ *
 *  A route coroutine. One per request in flight: its own stack, the
 *  saved registers, and what it is currently waiting for. Lives in the
 *  worker that owns the connection and never moves to another thread
 *  (helper threads run a function FOR it and hand it back).
 * ------------------------------------------------------------------ */
struct coro {
    int             kind;          /* EP_CORO -- must stay first         */
    ucontext_t      ctx;
    conn_t         *c;
    worker_t       *w;
    void           *stack;
    size_t          stack_size;
    int             done;          /* handler_run() returned             */
    int             cancelled;     /* server stopping: every wait fails  */

    /* waiting on an fd (co_wait_fd) and/or a deadline (co_sleep_ms) */
    int             wait_fd;       /* -1 = none                          */
    int             fd_in_epoll;   /* wait_fd is registered (ONESHOT)    */
    uint32_t        ready;         /* events delivered; 0 = timed out    */
    uint64_t        deadline;      /* 0 = no timer                       */
    coro_t         *tprev, *tnext; /* worker's timer list                */

    /* waiting on a helper thread (co_offload) */
    void          (*fn)(void *);
    void           *arg;

    coro_t         *next;          /* free list / grave / helper queue / */
                                   /* done stack / lock wait queue       */
};

/* timer classes: one FIFO list each, sorted by deadline for free because
   every member of a list shares the same timeout */
enum { TL_HANDSHAKE = 0, TL_IDLE, TL_IO, TL_LINGER, TL_COUNT };

/* The request view over conn->in. Every string below points into
   conn->in -- the table owns no character data, only the char** rows
   and the outer char*** array.

   Produced by parse_request(), which both the HTTPS handler and the
   plain-HTTP handler call: the parse does not care which listener the
   bytes arrived on, only that a whole request is sitting in conn->in.
   It lives inside conn_t (c->req) while the route coroutine runs. */
typedef struct {
    conn_t *c;

    /* 1 once the request-line, header table and body are all set.
       0 means the request was malformed -- headers may still hold a
       partly built table, so callers must free_headers() either way. */
    int parsed;
    int is_tls;         /* which listener this arrived on              */

    Method method;
    char ip[INET_ADDRSTRLEN];

    char * buffer;
    int buffer_size;
    int total_read;

    char * version;

    char * uri;
    char * query;

    char *** headers;
    int headers_count;

    char * body;
    size_t body_len;

    /* No `host` field: the Host header is in the table like every other
       header. Read it with get_header(req, "Host"), or
       get_header_default(req, "Host", domain) where a missing Host would
       otherwise be a NULL. */
} Request;

struct conn {
    int                 kind;        /* EP_CONN -- must stay first       */
    int                 fd;
    int                 is_tls;      /* 0 for the plain :80 redirector   */
    SSL                *ssl;
    SSL_CTX            *ctx;
    struct sockaddr_in  address;
    char                ip[INET_ADDRSTRLEN];

    conn_state          state;
    uint32_t            armed;       /* events registered (once, ET)     */
    int                 in_epoll;
    int                 shutdown_tries;
    time_t              last_active;

    /* readiness, tracked so no syscall is made that would EAGAIN */
    io_state            want;        /* what the last op is waiting for  */
    unsigned            rd_ready:1;
    unsigned            wr_ready:1;
    unsigned            rdhup:1;     /* peer sent FIN                    */
    unsigned            keepalive:1; /* this request allows reuse        */
    unsigned            close_after:1;
    unsigned            http10:1;
    unsigned            requests;

    /* inbound: request-line + headers + body, always NUL-terminated */
    char               *in;
    size_t              in_len;
    size_t              in_cap;
    size_t              scan_from;   /* resume point for the CRLFCRLF scan */
    long                headers_end; /* index just past CRLFCRLF, -1 = unknown */
    long                need;        /* total bytes wanted, -1 = unknown  */

    /* outbound: the complete response, written as the socket allows */
    char               *out;
    size_t              out_len;
    size_t              out_cap;
    size_t              out_sent;

    /* the request being handled: filled by parse_request(), read by the
       route coroutine, freed in handle_finish() */
    Request             req;
    coro_t             *co;             /* the route coroutine, while CS_BUSY */
    size_t              hreq_len;       /* bytes of this request in c->in */
    size_t              hfull_len;      /* in_len incl. pipelined bytes   */
    char                hsaved;         /* byte hidden behind the request */

    worker_t           *w;
    struct conn        *next_pending;   /* pool / close-batch / handler   */
                                        /* queue / done-list link         */
    struct conn        *prev, *next;    /* timer list                     */
    int                 tlist;          /* which timer list, -1 = none    */
    uint64_t            deadline;
};

typedef struct { conn_t *head, *tail; uint64_t timeout_ms; } tlist_t;
typedef struct { int kind; } ep_tag;

struct worker {
    int              id;
    int              cpu;               /* pinned CPU, -1 = not pinned    */
    pthread_t        tid;
    int              epfd;
    int              evfd;              /* wake doorbell: helper threads, */
                                        /* other workers, main() ring it  */
    int              lfd_tls;           /* the SHARED listeners (same fds */
    int              lfd_plain;         /* in every worker)               */
    ep_tag           tag_tls, tag_plain, tag_wake;
    SSL_CTX         *ctx;
    int              nlive;             /* open on this worker right now  */
                                        /* (the cap is global: g_max_live)*/
    int              peak;              /* most open at once              */
    unsigned long    accepted;
    unsigned long    handled;           /* requests answered              */
    unsigned long    shed;              /* refused: at cap / out of fds   */

    /* coroutines (Section 7 of epoll_helpers.c) */
    ucontext_t       main_ctx;          /* the worker loop itself         */
    coro_t          *co_free;           /* pooled, with their stacks      */
    int              co_nfree;
    coro_t          *co_grave;          /* finished this batch            */
    coro_t          *co_thead, *co_ttail; /* waiting with a deadline      */
    int              co_inflight;       /* routes started, not finished   */
    unsigned long    co_timeouts;       /* waits that hit their deadline  */

    /* any thread may push a coroutine of this worker here (lock-free
       stack) and ring evfd; the worker resumes it on its own thread */
    _Atomic(coro_t *) done_head;
    atomic_int       stop;              /* set by main() before the ring  */
    int              spare_fd;          /* kept for EMFILE recovery       */
    uint64_t         last_emfile_log;

    conn_t          *free_list;         /* pooled conn_t                  */
    int              nfree;
    conn_t          *grave;             /* closed during this batch       */
    tlist_t          tl[TL_COUNT];
    uint64_t         now_ms;

    char             log[LOG_BUF_SIZE];
    size_t           log_len;
} __attribute__((aligned(64)));

/* (Request is defined above conn_t -- it is embedded in it as c->req.) */

typedef struct {
    const char *extension;
    const char *mime_type;
} MimeType;


static const MimeType mime_map[] = {
    { "aac", "audio/aac" },
    { "abw", "application/x-abiword" },
    { "arc", "application/x-freearc" },
    { "avi", "video/x-msvideo" },
    { "azw", "application/vnd.amazon.ebook" },
    { "bin", "application/octet-stream" },
    { "bmp", "image/bmp" },
    { "bz", "application/x-bzip" },
    { "bz2", "application/x-bzip2" },
    { "csh", "application/x-csh" },
    { "css", "text/css" },
    { "csv", "text/csv" },
    { "doc", "application/msword" },
    { "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
    { "eot", "application/vnd.ms-fontobject" },
    { "epub", "application/epub+zip" },
    { "gz", "application/gzip" },
    { "gif", "image/gif" },
    { "htm", "text/html" },
    { "html", "text/html" },
    { "ico", "image/vnd.microsoft.icon" },
    { "ics", "text/calendar" },
    { "jar", "application/java-archive" },
    { "jpeg", "image/jpeg" },
    { "jpg", "image/jpeg" },
    { "js", "application/javascript" },
    { "json", "application/json" },
    { "jsonld", "application/ld+json" },
    { "mid", "audio/midi" },
    { "midi", "audio/midi" },
    { "mjs", "text/javascript" },
    { "mp3", "audio/mpeg" },
    { "mp4", "video/mp4" },
    { "mpeg", "video/mpeg" },
    { "mpkg", "application/vnd.apple.installer+xml" },
    { "odp", "application/vnd.oasis.opendocument.presentation" },
    { "ods", "application/vnd.oasis.opendocument.spreadsheet" },
    { "odt", "application/vnd.oasis.opendocument.text" },
    { "oga", "audio/ogg" },
    { "ogv", "video/ogg" },
    { "ogx", "application/ogg" },
    { "opus", "audio/opus" },
    { "otf", "font/otf" },
    { "png", "image/png" },
    { "pdf", "application/pdf" },
    { "php", "application/x-httpd-php" },
    { "ppt", "application/vnd.ms-powerpoint" },
    { "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
    { "rar", "application/vnd.rar" },
    { "rtf", "application/rtf" },
    { "sh", "application/x-sh" },
    { "svg", "image/svg+xml" },
    { "tar", "application/x-tar" },
    { "tif", "image/tiff" },
    { "tiff", "image/tiff" },
    { "ts", "video/mp2t" },
    { "ttf", "font/ttf" },
    { "txt", "text/plain" },
    { "vsd", "application/vnd.visio" },
    { "wav", "audio/wav" },
    { "weba", "audio/webm" },
    { "webm", "video/webm" },
    { "webp", "image/webp" },
    { "woff", "font/woff" },
    { "woff2", "font/woff2" },
    { "xhtml", "application/xhtml+xml" },
    { "xls", "application/vnd.ms-excel" },
    { "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
    { "xml", "application/xml" },
    { "xul", "application/vnd.mozilla.xul+xml" },
    { "zip", "application/zip" },
    { "3gp", "video/3gpp" },
    { "3g2", "video/3gpp2" },
    { "7z", "application/x-7z-compressed" },
    { "MOV", "video/quicktime" },
    { "mov", "video/quicktime"},
    { NULL, NULL }
};

/* ------------------------------------------------------------------ *
 *  Forward declarations - every function is defined below main(),     *
 *  in this file or in one of the #included ones.                      *
 * ------------------------------------------------------------------ */

/* --- general helpers --- */
void free_response(Response res);
char *hebrew_to_uri(const char *input);
/* Upstream HTTP clients. Both open a fresh connection per call (no
   pooling, by design), send the request verbatim and read until the
   peer closes. `timeout_s` bounds the WHOLE exchange -- DNS, connect,
   TLS, send, receive; on expiry the usual failure Response comes back
   (status "" / "-1", no body). Inside a route they yield while waiting,
   so a 30 s upstream call costs the worker nothing; outside a coroutine
   they block the caller as a plain client would.

   Call them with the timeout, always:
       https_request(host, req, HTTP_TIMEOUT_DEFAULT);
       http_request(host, port, req, HTTP_TIMEOUT_DEFAULT);
   A call that leaves the timeout out still compiles and gets
   HTTP_TIMEOUT_DEFAULT (the macros below count the arguments). */
ssize_t  ssl_read_all(SSL *ssl, char **out, uint64_t deadline_ms);
Response https_request(const char *hostname, const char *req, int timeout_s);
Response http_request(const char *host, int port, const char *request, int timeout_s);
#define HTTPREQ_PICK4(_1, _2, _3, NAME, ...)      NAME
#define HTTPREQ_PICK5(_1, _2, _3, _4, NAME, ...)  NAME
#define https_request_2(h, r)        https_request(h, r, HTTP_TIMEOUT_DEFAULT)
#define https_request_3(h, r, t)     https_request(h, r, t)
#define https_request(...)  HTTPREQ_PICK4(__VA_ARGS__, https_request_3, https_request_2)(__VA_ARGS__)
#define http_request_3(h, p, r)      http_request(h, p, r, HTTP_TIMEOUT_DEFAULT)
#define http_request_4(h, p, r, t)   http_request(h, p, r, t)
#define http_request(...)   HTTPREQ_PICK5(__VA_ARGS__, http_request_4, http_request_3)(__VA_ARGS__)
static int contains_dotdot(const char *s);
int is_file_allowed(const char *home, const char *host, const char *uri);
FileInfo get_file(const char* host, const char* filename);
/* How a route uses the database:
       MYSQL *conn = connect_db();   -- a pooled connection, reset to a
                                        clean session; NULL if none could
                                        be had within DB_WAIT_MS
       co_mysql_query(conn, sql);    -- instead of mysql_query()
       co_mysql_store_result(conn);  -- instead of mysql_store_result()
       ... mysql_fetch_row / mysql_free_result / mysql_error / etc.
           exactly as before (they do not talk to the server)
       db_release(conn);             -- where mysql_close(conn) used to be
   The co_ calls run the query on a helper thread while this route
   yields; the worker keeps serving its other connections meanwhile.
   Never mysql_close() a pooled connection. If the route does not need
   the database during a long upstream call, db_release() before it and
   connect_db() again after -- the pool is shared by every request.
   With USE_DATABASE 0, connect_db() always returns NULL. */
MYSQL * connect_db(void);
void    db_release(MYSQL *conn);
void print_signal_error(int sig_num);
void handler(int sig);
void bind_signal_handlers();
SSL_CTX *create_ssl_context();
static int ktls_available(void);
void configure_ssl_context(SSL_CTX *ctx);
char * method_to_str(Method method);
static char *trim_inplace(char *s);
char * get_header(Request * req, const char * name);
char * get_header_default(Request * req, const char * name, char * fallback);
void free_headers(Request * req);
const char *get_mime_type(const char *filename);
void random_string(char *out, size_t len);

/* --- startup: path discovery and arguments --- */
static char *   dir_with_slash(const char *p);
static int      resolve_paths(const char *argv0);
static char *   find_up(const char *start, const char *sub);
static void     print_sites(void);
static void     build_cert_paths(void);
static int      parse_int_arg(const char *s, int lo, int hi, int *out);
static void     usage(const char *prog);

/* --- the epoll engine --- */
static int      set_nonblocking(int fd) __attribute__((unused));
static int      make_listener(const char *addr, int port);
static conn_t * conn_new(worker_t *w, int fd, struct sockaddr_in *addr, SSL_CTX *ctx, int is_tls);
static void     conn_destroy(conn_t *c);
static void     conn_touch(conn_t *c) __attribute__((unused));
static void     conn_timer(conn_t *c, int list);
static void     conn_timer_unlink(conn_t *c);
static io_state conn_recv(conn_t *c, void *buf, size_t len, size_t *got);
static io_state conn_send(conn_t *c, const void *buf, size_t len, size_t *sent);
static int      in_reserve(conn_t *c, size_t extra);
static int      out_append(conn_t *c, const void *data, size_t len);
static int      request_complete(conn_t *c);
static int      response_wants_close(conn_t *c);
static void     send_error_close(conn_t *c, int status);
static drive_r  do_handshake(conn_t *c);
static drive_r  do_read(conn_t *c);
static drive_r  do_handle(conn_t *c);
static void     handler_run(conn_t *c);
static drive_r  handle_finish(conn_t *c);
static drive_r  do_write(conn_t *c);
static drive_r  do_shutdown(conn_t *c);
static drive_r  do_linger(conn_t *c);
static void     conn_drive(conn_t *c);
static void     worker_accept(worker_t *w, int lfd, int is_tls);
static void     worker_sweep_idle(worker_t *w);
static void     conn_drop_buffers(conn_t *c);
static void     worker_shed_one(worker_t *w, int lfd);
static const char *conn_keepalive_hdr(conn_t *c) __attribute__((unused));
static void     worker_reap(worker_t *w);
static void     worker_drain_done(worker_t *w);
static void  *  worker_main(void *arg);

/* ---------------------------------------------------------------------
 *  Coroutines (Section 7 of epoll_helpers.c). What a route may use:
 *
 *    co_wait_fd(fd, events, timeout_ms)  wait for a non-blocking socket
 *                                        -> revents, CO_TIMEOUT or -1
 *    co_close(fd)                        close a socket you waited on
 *    co_sleep_ms(ms)                     pause without blocking the worker
 *    co_offload(fn, arg)                 run fn(arg) on a helper thread,
 *                                        continue here when it returns
 *    co_mutex_t + co_mutex_lock/unlock   a lock that may be held across
 *                                        any of the calls above (a
 *                                        pthread mutex must NOT be)
 *  Every one of them also works outside a coroutine (startup code):
 *  it then simply blocks the calling thread.
 * ------------------------------------------------------------------- */
#define CO_TIMEOUT 0
typedef struct {
    pthread_mutex_t mu;                 /* guards the fields, never held across a yield */
    pthread_cond_t  cv;                 /* for non-coroutine callers      */
    int             locked;
    coro_t         *head, *tail;        /* coroutines waiting for it      */
} co_mutex_t;
#define CO_MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL, NULL }

static int      co_wait_fd(int fd, uint32_t events, int timeout_ms);
static void     co_close(int fd);
static void     co_sleep_ms(int ms) __attribute__((unused));
static void     co_offload(void (*fn)(void *), void *arg);
static void     co_mutex_lock(co_mutex_t *m)   __attribute__((unused));   /* for your routes */
static void     co_mutex_unlock(co_mutex_t *m) __attribute__((unused));
static drive_r  co_spawn(conn_t *c);
static void     co_wake(coro_t *co);
static void     co_sweep(worker_t *w);
static void     co_cancel_all(worker_t *w);
static void     co_reap(worker_t *w);
static int      helpers_start(int nthreads);
static void     helpers_stop(void);
static void     helpers_stats(unsigned long *run, int *peak_queued);

/* --- OS settings (os_tune.c): checked and applied once at startup --- */
typedef struct {
    /* in */
    long mem_budget_kb;      /* RAM the server may use for connections */
    long want_conns;         /* connections it would like to be able to hold */
    int  workers, helpers, db_conns;
    /* out */
    long fd_limit;           /* RLIMIT_NOFILE in force after tuning */
    long somaxconn, syn_backlog;
    int  is_root, changed, failed;
} os_tune_t;
static void os_tune_apply(os_tune_t *t);

/* --- MySQL: the connection pool and the yielding query calls --- */
static MYSQL *  db_open_raw(void);          /* one fresh connection (main.c) */
static int      db_pool_init(int max);
static void     db_pool_shutdown(void);
static void     db_pool_stats(int *open, int *idle, unsigned long *waits);
int             co_mysql_query(MYSQL *m, const char *q);
int             co_mysql_real_query(MYSQL *m, const char *q, unsigned long len);
MYSQL_RES *     co_mysql_store_result(MYSQL *m);

/* --- request handling (the part that is the same server as before) --- */
Request      parse_request(conn_t *c);                      /* http + https */
static void  handle_request(conn_t *c, Request *req);       /* https routes */
static void  handle_http_redirect(conn_t *c, Request *req); /* :80 redirect */
static int   is_known_host(const char *host);
static const char *redirect_host(Request *req, char *buf, size_t buflen);

static worker_t workers[MAX_WORKERS];

/* Open connections across ALL workers, and the cap they share. One
   global counter instead of a per-worker share: with the shared listener
   a worker's load depends on what it was doing when connections arrived,
   so a fixed share would refuse clients on one worker while others still
   had room. Touched once per accept and once per close -- an atomic
   add on a shared cache line, cheap next to the accept4() beside it. */
static atomic_long g_live     = 0;
static long        g_max_live = 0;        /* 0 = unlimited */

/* ---- hardware scan: what this VM can carry ---------------------------
   Read once at startup; decides the defaults and is printed so the
   operator sees why the limits are what they are. */
static long read_proc_long(const char *path, const char *key) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    long v = -1;
    if (!key) {
        if (fgets(line, sizeof(line), f)) v = atol(line);
    } else {
        size_t kl = strlen(key);
        while (fgets(line, sizeof(line), f))
            if (!strncmp(line, key, kl)) { v = atol(line + kl); break; }
    }
    fclose(f);
    return v;
}

/* Helper threads follow the MySQL pool: one per connection (so every
   connection can be mid-query at the same time) plus a few for DNS. */
static int helpers_for_pool(int db_conns) {
    int n = db_conns + HELPERS_FOR_DNS;
    if (n < HELPERS_MIN) n = HELPERS_MIN;
    if (n > HELPERS_MAX) n = HELPERS_MAX;
    return n;
}

/* Memory a connection costs, used to bound the connection cap:
   idle keep-alive  ~  conn_t + SSL object             ~ 6 KB
   mid-request      +  in/out buffers + TLS record bufs ~ 50 KB
   A busy server is a blend; 24 KB is a conservative average, and
   connections may claim at most CONN_MEM_PCT of what is free so MySQL,
   upstream replies and the page cache keep theirs. Nothing is allocated up
   front -- this only bounds how far the server lets itself grow. */
#define CONN_MEM_EST_KB  24
#define CONN_MEM_PCT     75


int main(int argc, char *argv[]) {

    setbuf(stdout, NULL);
    srand(time(NULL));

    /* Where am I? Everything on disk hangs off this, so it happens before
       the arguments are read -- -r and -c overwrite the results below. */
    if (resolve_paths(argc > 0 ? argv[0] : NULL) != 0)
        exit(EXIT_FAILURE);

    cert_dir = find_up(home, CERT_SUBDIR);
    if (!cert_dir) { perror("malloc cert_dir"); exit(EXIT_FAILURE); }

    /* FIX: these were malloc(16)/malloc(256) written with strcpy() straight
       from argv, so a long -b or -d overflowed the heap. */
    bind_addr = malloc(64*sizeof(char));
    domain = malloc(256*sizeof(char));
    if (!bind_addr || !domain) { perror("malloc"); exit(EXIT_FAILURE); }
    snprintf(domain, 256, "%s", DOMAIN);
    snprintf(bind_addr, 64, "%s", BIND_ADDR);
    https_port = PORT;
    http_port  = HTTP_PORT;
    num_workers = DEFAULT_WORKERS;
    g_ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (g_ncpu < 1) g_ncpu = 1;

    /* ---- arguments ----------------------------------------------------
       No arguments at all is the normal case (that is how the systemd
       unit starts it) and runs with the defaults above. Anything the
       parser does not understand -- an unknown flag, a flag with no
       value, a port that is not a number, an address that is not an
       IPv4 -- prints what was wrong, prints the help page, and exits
       instead of limping on with a half-applied configuration.
       -h / -help / --help / -? / ? print the help page and exit 0. */
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (!strcmp(a, "-h")     || !strcmp(a, "-help") ||
            !strcmp(a, "--help") || !strcmp(a, "-?")    ||
            !strcmp(a, "?")      || !strcmp(a, "/?")) {
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        }

        /* everything else is a single-letter flag taking one value */
        if (a[0] != '-' || a[1] == '\0' || a[2] != '\0') {
            fprintf(stderr, "ERROR: unrecognised argument: %s\n\n", a);
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }

        if (i + 1 >= argc) {
            fprintf(stderr, "ERROR: option %s needs a value\n\n", a);
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }

        const char *val = argv[++i];

        switch (a[1]) {
          case 'b': {
            struct in_addr probe;
            if (inet_pton(AF_INET, val, &probe) != 1) {
                fprintf(stderr, "ERROR: -b expects an IPv4 address, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            snprintf(bind_addr, 64, "%s", val);
            break;
          }

          case 'p':
            if (parse_int_arg(val, 1, 65535, &https_port) != 0) {
                fprintf(stderr, "ERROR: -p expects a port in 1..65535, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'P':                      /* the plain-HTTP listener */
            if (parse_int_arg(val, 1, 65535, &http_port) != 0) {
                fprintf(stderr, "ERROR: -P expects a port in 1..65535, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'd':
            if (*val == '\0' || strlen(val) >= 256) {
                fprintf(stderr, "ERROR: -d expects a domain of 1..255 characters\n\n");
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            memset(domain, '\0', 256*sizeof(char));
            snprintf(domain, 256, "%s", val);
            break;

          case 'm':                      /* max open connections, all workers */
            if (parse_int_arg(val, 0, 10000000, &max_conns) != 0) {
                fprintf(stderr, "ERROR: -m expects a connection count (0 = auto), got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'B':                      /* busy-poll microseconds */
            if (parse_int_arg(val, 0, 100000, &busy_poll_us) != 0) {
                fprintf(stderr, "ERROR: -B expects microseconds in 0..100000, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'w':
            if (parse_int_arg(val, 1, MAX_WORKERS, &num_workers) != 0) {
                fprintf(stderr, "ERROR: -w expects a worker count in 1..%d, got: %s\n\n",
                        MAX_WORKERS, val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'D':                      /* MySQL connection pool */
            if (parse_int_arg(val, 1, DB_POOL_MAX, &db_pool_max) != 0) {
                fprintf(stderr, "ERROR: -D expects a MySQL connection count in 1..%d, got: %s\n\n",
                        DB_POOL_MAX, val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'k':                      /* keep-alive idle timeout */
            if (parse_int_arg(val, 0, 3600, &keepalive_secs) != 0) {
                fprintf(stderr, "ERROR: -k expects seconds in 0..3600, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'l':                      /* per-request log line */
          case 'a':                      /* CPU pinning */
            if (parse_int_arg(val, 0, 1, a[1] == 'l' ? &log_requests : &pin_cpus) != 0) {
                fprintf(stderr, "ERROR: %s expects 0 or 1, got: %s\n\n", a, val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'r': {                    /* override the site root */
            char *w = dir_with_slash(val);
            if (!w) {
                fprintf(stderr, "ERROR: -r expects a directory: %s\n\n", strerror(errno));
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            free(workspace);
            workspace = w;
            break;
          }

          case 'c': {                    /* override the cert directory */
            char *d = dir_with_slash(val);
            if (!d) {
                fprintf(stderr, "ERROR: -c expects a directory: %s\n\n", strerror(errno));
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            free(cert_dir);
            cert_dir = d;
            break;
          }

          default:
            fprintf(stderr, "ERROR: unknown option: %s\n\n", a);
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // bind_signal_handlers();

    /* A single process now owns every connection, so one write to a
       socket the peer already closed must not take the server down. */
    signal(SIGPIPE, SIG_IGN);

    if (mysql_library_init(0, NULL, NULL) != 0) {
        fprintf(stderr, "mysql_library_init() failed\n");
        exit(EXIT_FAILURE);
    }

    build_cert_paths();

    /* ---- hardware scan: size the server to the VM --------------------
       Epoll workers: one per hardware thread. Routes run on them as
         coroutines and yield while they wait, so the workers never
         block and one per core is all the CPU can use.
       Helper threads: one per pooled MySQL connection plus a few for
         DNS (recomputed once the pool has been clamped to the server's
         max_connections below). They run only the library calls that
         cannot yield -- a MySQL query, a DNS lookup -- while the route
         waits.
       MySQL connections: -D, clamped to the server's max_connections.
       Connections: bounded by the smallest of
         - memory: CONN_MEM_PCT of MemAvailable at CONN_MEM_EST_KB each
           (nothing is allocated up front; this is a ceiling),
         - file descriptors, after os_tune.c has raised the limits,
         - -m if given.
       The cap is global (g_max_live), not per worker. os_tune.c checks
       the kernel settings a server of this size needs and applies them
       for this boot (not persisted) when running as root. */
    if (num_workers == 0) {
        num_workers = g_ncpu;
        if (num_workers > MAX_WORKERS) num_workers = MAX_WORKERS;
    }
    num_helpers = helpers_for_pool(db_pool_max);     /* provisional, for the fd budget */

    long mem_avail_kb = read_proc_long("/proc/meminfo", "MemAvailable:");
    long mem_total_kb = read_proc_long("/proc/meminfo", "MemTotal:");
    long mem_budget_kb = mem_avail_kb > 0 ? mem_avail_kb / 100 * CONN_MEM_PCT : 0;
    long mem_cap = mem_budget_kb > 0 ? mem_budget_kb / CONN_MEM_EST_KB : 1000000;
    if (mem_cap < num_workers) mem_cap = num_workers;
    long want = (max_conns > 0 && max_conns < mem_cap) ? max_conns : mem_cap;

    os_tune_t tune = {0};
    tune.mem_budget_kb = mem_budget_kb;
    tune.want_conns    = want;
    tune.workers       = num_workers;
    tune.helpers       = num_helpers;
    tune.db_conns      = db_pool_max;
    os_tune_apply(&tune);
    long fd_limit = tune.fd_limit;

    /* fds not available to client connections: each helper may hold a
       MySQL socket, each route in flight an upstream socket (counted inside
       the connection estimate), each worker an epoll fd, an eventfd and
       a spare; plus listeners, certs, logs */
    long usable = fd_limit - 64 - 4L * num_workers - 2L * num_helpers - db_pool_max;
    if (usable < num_workers) usable = num_workers;

    const char *bound = "memory";
    long cap = mem_cap;
    if (usable < cap)                     { cap = usable;    bound = "file descriptors"; }
    if (max_conns > 0 && max_conns < cap) { cap = max_conns; bound = "-m"; }
    g_max_live = cap;

    long somaxconn   = tune.somaxconn;
    long syn_backlog = tune.syn_backlog;
    long backlog_eff = (somaxconn > 0 && somaxconn < BACKLOG) ? somaxconn : BACKLOG;

    fprintf(stdout,"\e[0;93mbinary dir  \e[96m%s\e[0m\n", home);
    fprintf(stdout,"\e[0;93msite root   \e[96m%s\e[0m\n", workspace);
    print_sites();
    fprintf(stdout,"\e[0;93mcerts       \e[96m%s\e[0m\n", cert_dir);

    /* Say plainly which file is missing rather than letting OpenSSL
       report a bare "no such file" from inside the handshake setup. */
    if (access(cert_file, R_OK) != 0 || access(key_file, R_OK) != 0) {
        fprintf(stderr,
            "\e[1;31mcertificates not readable\e[0m\n"
            "  expected: %s\n"
            "            %s\n"
            "  put them there, or point elsewhere with -c <dir>\n",
            cert_file, key_file);
        exit(EXIT_FAILURE);
    }

    SSL_CTX *ctx = create_ssl_context();
    configure_ssl_context(ctx);

    /* ---- listeners: ONE pair, shared by every worker. Each worker adds
       the same two fds to its own epoll set with EPOLLEXCLUSIVE, so a new
       connection wakes exactly one worker that is idle in epoll_wait().
       That is the load balancing: a worker blocked in a handler is never
       chosen, an idle one is. ---- */
    int lfd_tls   = make_listener(bind_addr, https_port);
    int lfd_plain = make_listener(bind_addr, http_port);
    if (lfd_tls < 0 || lfd_plain < 0) {
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < num_workers; i++) {
        workers[i].lfd_tls   = lfd_tls;
        workers[i].lfd_plain = lfd_plain;
    }

    /* only the main thread takes SIGINT/SIGTERM; workers inherit the mask */
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);

    /* ---- spin up the worker pool: one epoll instance per worker ---- */
    for (int i = 0; i < num_workers; i++) {
        worker_t *w = &workers[i];
        w->id  = i;
        w->ctx = ctx;
        w->cpu = pin_cpus ? i % g_ncpu : -1;
        w->tag_tls.kind   = EP_LISTEN_TLS;
        w->tag_plain.kind = EP_LISTEN_PLAIN;
        w->tag_wake.kind  = EP_WAKE;
        atomic_init(&w->done_head, NULL);
        atomic_init(&w->stop, 0);

        w->epfd = epoll_create1(EPOLL_CLOEXEC);
        if (w->epfd < 0) { perror("epoll_create1"); exit(EXIT_FAILURE); }

        w->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (w->evfd < 0) { perror("eventfd"); exit(EXIT_FAILURE); }
    }

    /* the DB pool and the helpers must be up before the first request.
       The pool is clamped to what MySQL will accept: ask it once; the
       helper count follows the pool. With USE_DATABASE 0 none of this
       happens and the helpers only serve DNS lookups. */
    long db_max_connections = -1;
    if (USE_DATABASE) {
        MYSQL *probe = db_open_raw();
        if (probe) {
            if (mysql_query(probe, "SELECT @@max_connections") == 0) {
                MYSQL_RES *r = mysql_store_result(probe);
                MYSQL_ROW row = r ? mysql_fetch_row(r) : NULL;
                if (row && row[0]) db_max_connections = atol(row[0]);
                if (r) mysql_free_result(r);
            }
            mysql_close(probe);
        } else {
            fprintf(stderr, "\e[1;33mwarning\e[0m: MySQL not reachable at startup -- routes that need it will answer 500 until it is\n");
        }
        if (db_max_connections > 0) {
            long reserve = db_max_connections * DB_RESERVE_PCT / 100;
            if (reserve < DB_RESERVE_MIN) reserve = DB_RESERVE_MIN;
            if (db_pool_max > db_max_connections - reserve) {
                db_pool_max = (int)(db_max_connections - reserve);
                if (db_pool_max < 1) db_pool_max = 1;
            }
        }
    }
    if (USE_DATABASE) {
        if (db_pool_init(db_pool_max) != 0) exit(EXIT_FAILURE);
        num_helpers = helpers_for_pool(db_pool_max);
    } else {
        db_pool_max = 0;                       /* connect_db() answers NULL */
        num_helpers = HELPERS_MIN;             /* DNS only */
    }
    if (helpers_start(num_helpers) != 0) exit(EXIT_FAILURE);

    for (int i = 0; i < num_workers; i++) {
        if (pthread_create(&workers[i].tid, NULL, worker_main, &workers[i]) != 0) {
            perror("worker thread creation failed");
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stdout,"\033[95mHTTP Server is listening on \e[96m%s\e[97m:\e[92m%d\e[0m\n", bind_addr, http_port);
    fprintf(stdout,"\e[0;93mHTTPS Server is listening on \e[96m%s\e[97m:\e[92m%d\e[0m\n", bind_addr, https_port);
    fprintf(stdout,"\e[0;93mhardware:    \e[92m%d\e[0m cpus, \e[92m%ld\e[0m MB total / \e[92m%ld\e[0m MB free (budget %d%% = %ld MB), fd limit \e[92m%ld\e[0m\n",
            g_ncpu, mem_total_kb > 0 ? mem_total_kb / 1024 : -1,
            mem_avail_kb > 0 ? mem_avail_kb / 1024 : -1, CONN_MEM_PCT, mem_budget_kb / 1024, fd_limit);
    fprintf(stdout,"\e[0;93mepoll workers: \e[92m%d\e[0m (one per cpu, pinned %s, shared listener + EPOLLEXCLUSIVE; routes are coroutines, never block)\n",
            num_workers, pin_cpus ? "yes" : "no");
    if (USE_DATABASE) {
        fprintf(stdout,"\e[0;93mhelper threads: \e[92m%d\e[0m (one per MySQL connection + %d for DNS)   \e[0;93mMySQL pool: \e[92m%d\e[0m connections (-D%s)\n",
                num_helpers, HELPERS_FOR_DNS, db_pool_max,
                db_max_connections > 0 ? "" : "; max_connections unknown, MySQL was unreachable");
        if (db_max_connections > 0)
            fprintf(stdout,"               MySQL max_connections = %ld, %d%% (at least %d) left for other clients\n",
                    db_max_connections, DB_RESERVE_PCT, DB_RESERVE_MIN);
        if (!strcmp(DB_HOST, "localhost") || !strcmp(DB_HOST, "127.0.0.1"))
            fprintf(stdout,"               MySQL is local and shares the %d cpus; helpers run at nice +%d so the workers keep priority\n",
                    g_ncpu, HELPER_NICE);
    } else {
        fprintf(stdout,"\e[0;93mdatabase:    \e[92moff\e[0m (USE_DATABASE 0 in main.c)   \e[0;93mhelper threads: \e[92m%d\e[0m (DNS lookups)\n",
                num_helpers);
    }
    fprintf(stdout,"\e[0;93mconnections: \e[92m%ld\e[0m open at once (bounded by %s; memory allows %ld, fds allow %ld)%s\n",
            cap, bound, mem_cap, usable,
            bound[0] == 'f' ? "\n               -- the fd limit is the ceiling: run as root (os_tune raises it) or set LimitNOFILE=" : "");
    fprintf(stdout,"\e[0;93maccept queue: \e[92m%ld\e[0m per listener (syn backlog %ld)%s\n", backlog_eff, syn_backlog,
            backlog_eff < BACKLOG ? " -- capped by net.core.somaxconn (os_tune raises it when root)" : "");
    fprintf(stdout,"\e[0;93mkeep-alive: \e[92m%ds\e[0m  request log: %s  kTLS: %s\n",
            keepalive_secs, log_requests ? "on" : "off",
            ktls_available() ? "on" : "off (run `modprobe tls` to enable)");
    fprintf(stdout,"\e[0;93mtcp: \e[92mnodelay, defer-accept, fastopen%s\e[0m\n",
            busy_poll_us ? ", busy-poll" : "");
    fprintf(stdout,"\e[0;93mtls: \e[92mTLS1.2+, AEAD, X25519, ALPN http/1.1, tickets, release-buffers\e[0m\n");
    fprintf(stdout,"\e[0;93mupstream:    \e[92mhttps_request/http_request %d s timeout\e[0m, fresh connection per call\n", HTTP_TIMEOUT_DEFAULT);

    /* No acceptor loop any more -- the workers accept for themselves.
       The main thread just waits for Ctrl-C / SIGTERM. */
    int sig = 0;
    sigwait(&sigs, &sig);
    fprintf(stdout, "\nsignal %d -- stopping\n", sig);

    /* Order: workers first -- each stops accepting, fails every wait its
       routes are in, lets them run to the end (STOP_GRACE_MS at most)
       and exits. Only then are the helper threads and the DB pool torn
       down, because routes in flight may still be using them. */
    uint64_t one = 1;
    for (int i = 0; i < num_workers; i++) {
        atomic_store(&workers[i].stop, 1);
        if (write(workers[i].evfd, &one, sizeof(one)) < 0) { /* ignore */ }
    }
    for (int i = 0; i < num_workers; i++)
        pthread_join(workers[i].tid, NULL);
    close(lfd_tls);                 /* shared, so closed once, here */
    close(lfd_plain);
    helpers_stop();
    if (USE_DATABASE) db_pool_shutdown();

    unsigned long total = 0, total_req = 0, total_to = 0;
    for (int i = 0; i < num_workers; i++) {
        total += workers[i].accepted; total_req += workers[i].handled; total_to += workers[i].co_timeouts;
    }
    for (int i = 0; i < num_workers; i++)
        fprintf(stdout, "worker %2d: accepted %-9lu (%5.1f%%) requests %-9lu peak open %-7d refused %-6lu upstream timeouts %lu\n",
                i, workers[i].accepted,
                total ? 100.0 * (double)workers[i].accepted / (double)total : 0.0,
                workers[i].handled, workers[i].peak, workers[i].shed, workers[i].co_timeouts);
    fprintf(stdout, "total: %lu connections, %lu requests over %d workers, %lu upstream/db waits timed out\n",
            total, total_req, num_workers, total_to);
    {
        unsigned long hr = 0, dbw = 0; int hq = 0, dbo = 0, dbi = 0;
        helpers_stats(&hr, &hq);
        db_pool_stats(&dbo, &dbi, &dbw);
        if (USE_DATABASE)
            fprintf(stdout, "helpers: %d threads, %lu calls run, peak queue %d   MySQL pool: %d open, %lu times a route waited for a free connection\n",
                    num_helpers, hr, hq, dbo, dbw);
        else
            fprintf(stdout, "helpers: %d threads, %lu calls run, peak queue %d\n", num_helpers, hr, hq);
    }

    SSL_CTX_free(ctx);
    mysql_library_end();

    return 0;
}



/* ==================================================================== *
 *  Section 0 -- working out where we are on disk
 * ==================================================================== */

/* strdup(p) with exactly one trailing '/'. NULL on empty input or OOM. */
static char * dir_with_slash(const char *p) {
    if (!p || !*p) { errno = EINVAL; return NULL; }

    size_t len = strlen(p);
    while (len > 1 && p[len-1] == '/') len--;   /* collapse "a///" -> "a/" */

    char *out = malloc(len + 2);
    if (!out) return NULL;
    memcpy(out, p, len);
    if (out[len-1] != '/') out[len++] = '/';
    out[len] = '\0';
    return out;
}

/* `sub` (e.g. "certs/") in `start`, or in the closest parent directory
   that has it -- so a binary in a subfolder still finds the shared
   certs/ one or two levels up. Falls back to start/sub.
   Result is malloc'd and keeps a trailing '/'. */
static char *find_up(const char *start, const char *sub) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", start);
    for (int level = 0; level < 4; level++) {
        char cand[PATH_MAX];
        struct stat st;
        int len = snprintf(cand, sizeof(cand), "%s%s", dir, sub);
        if (len > 0 && len < (int)sizeof(cand) &&
            stat(cand, &st) == 0 && S_ISDIR(st.st_mode)) return strdup(cand);
        size_t n = strlen(dir);
        if (n <= 1) break;
        dir[n - 1] = '\0';                          /* drop trailing '/' */
        char *slash = strrchr(dir, '/');
        if (!slash) break;
        slash[1] = '\0';                            /* parent, with '/' */
    }
    char *out = malloc(strlen(start) + strlen(sub) + 1);
    if (out) sprintf(out, "%s%s", start, sub);
    return out;
}

/* Fill in `home` (the directory this binary lives in) and `workspace`
   (one folder up). /proc/self/exe is the authoritative answer on Linux --
   it survives a relative invocation, a PATH lookup, and a changed cwd,
   all of which make argv[0] unreliable. argv[0] via realpath() is only
   the fallback for a kernel without /proc mounted. */
static int resolve_paths(const char *argv0) {
    char exe[PATH_MAX];

    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
    } else if (!argv0 || !realpath(argv0, exe)) {
        fprintf(stderr, "cannot resolve the server's own path: %s\n",
                strerror(errno));
        return -1;
    }

    char *slash = strrchr(exe, '/');
    if (!slash) {
        fprintf(stderr, "unexpected executable path: %s\n", exe);
        return -1;
    }

    *slash = '\0';                       /* .../site-root/EPOLL_VANILLA */
    home = dir_with_slash(*exe ? exe : "/");
    if (!home) { perror("malloc home"); return -1; }

    slash = strrchr(exe, '/');           /* one folder up               */
    if (slash) *slash = '\0';
    workspace = dir_with_slash(*exe ? exe : "/");
    if (!workspace) { perror("malloc workspace"); return -1; }

    return 0;
}

/* List the (sub)domain folders in the site root -- every directory whose
   name is a valid hostname (letters, digits, '-', '.', at least one dot).
   Only these are ever served; anything else there (source folders,
   certs, ...) is not reachable through the Host header. */
static void print_sites(void) {
    DIR *d = opendir(workspace);
    if (!d) {
        fprintf(stdout, "\e[1;31mwarning\e[0m: site root %s cannot be opened: %s\n",
                workspace, strerror(errno));
        return;
    }
    int n = 0, have_fallback = 0;
    struct dirent *de;
    fprintf(stdout, "\e[0;93msites       \e[92m");
    while ((de = readdir(d))) {
        /* listing only: hostnames have a dot, so sibling folders such as
           EPOLL_VANILLA/ or certs/ are not shown as sites (is_known_host()
           in handlers.c is unchanged -- this does not alter what is served) */
        if (de->d_name[0] == '.' || !strchr(de->d_name, '.') || !is_known_host(de->d_name)) continue;
        fprintf(stdout, "%s%s", n++ ? ", " : "", de->d_name);
        if (strcasecmp(de->d_name, domain) == 0) have_fallback = 1;
    }
    closedir(d);
    fprintf(stdout, "%s\e[0m\n", n ? "" : "(none)");
    if (!have_fallback)
        fprintf(stdout, "\e[1;33mwarning\e[0m: no folder for the fallback domain %s in %s"
                        " -- unknown Hosts will 404\n", domain, workspace);
}

/* cert_dir + the two filenames, after -c has had its say. */
static void build_cert_paths(void) {
    snprintf(cert_file, sizeof(cert_file), "%s%s", cert_dir, CERT_NAME);
    snprintf(key_file,  sizeof(key_file),  "%s%s", cert_dir, KEY_NAME);
}

/* strtol with the checks atoi() silently skips: no digits at all, trailing
   junk ("8443x"), overflow, and out-of-range. 0 on success. */
static int parse_int_arg(const char *s, int lo, int hi, int *out) {
    if (!s || !*s) return -1;

    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);

    if (errno != 0)   return -1;      /* ERANGE */
    if (end == s)     return -1;      /* no digits */
    if (*end != '\0') return -1;      /* trailing junk */
    if (v < lo || v > hi) return -1;

    *out = (int)v;
    return 0;
}

/* The help page. Prints the live defaults and the paths resolve_paths()
   just worked out, so it doubles as "what would this binary actually do". */
static void usage(const char *prog) {
    const char *name = "server";
    if (prog && *prog) {
        const char *slash = strrchr(prog, '/');
        name = slash ? slash + 1 : prog;
    }

    printf(
"EPOLL_VANILLA -- a generic HTTPS server: static sites by virtual host on one\n"
"port, an HTTP->HTTPS redirect on another, your routes in handlers.c.\n"
"\n"
"Usage: %s [options]\n"
"       %s                       run with the defaults below\n"
"       %s --help                show this page\n"
"\n"
"Options:\n"
"  -b <ipv4>   address to bind both listeners to   (default %s)\n"
"  -p <port>   HTTPS port,  1..65535               (default %d)\n"
"  -P <port>   plain HTTP port, 1..65535           (default %d)\n"
"  -d <name>   domain used when a request's Host is missing or unknown\n"
"                                                  (default %s)\n"
"  -w <n>      epoll worker threads, 1..%d         (default: one per CPU)\n"
"              they accept, do TLS and I/O, and run the routes as\n"
"              coroutines that yield while waiting; never block\n"
"  -D <n>      MySQL connections in the pool       (default %d, clamped to max_connections-10;\n"
"              ignored unless USE_DATABASE is 1 in main.c)\n"
"              helper threads (one per connection, for MySQL queries and\n"
"              DNS lookups while a route waits) follow this number\n"
"  -m <n>      max open connections, all workers   (default: from the fd limit and free memory)\n"
"  -k <secs>   keep-alive idle timeout, 0 = off    (default %d)\n"
"  -a 0|1      pin worker i to CPU i %% ncpu        (default 0)\n"
"  -l 0|1      one log line per request            (default 1)\n"
"  -B <usec>   busy-poll the NIC, 0 = off          (default 0; lower latency, more CPU)\n"
"  -r <dir>    site root: sites are served from <dir>/<host>/  (default: folder above the binary)\n"
"  -c <dir>    directory holding %s and %s  (default: nearest certs/)\n"
"              plus optional <name>.<tag> pairs, e.g. fullchain.pem.opaq +\n"
"              privkey.pem.opaq -- one RSA and one ECDSA chain side by side\n"
"  -h, --help, -help, -?, ?   show this page and exit\n"
"\n"
"Paths for this binary (worked out at startup from /proc/self/exe;\n"
"-r and -c override them):\n"
"  binary dir  %s\n"
"  site root   %s\n"
"  certs       %s\n"
"\n"
"Examples:\n"
"  %s -w 8\n"
"  %s -b 0.0.0.0 -p 8443 -P 8080 -w 8\n"
"  %s -r /srv/sites -c /etc/letsencrypt/live/%s\n",
        name, name, name,
        BIND_ADDR, PORT, HTTP_PORT, DOMAIN,
        MAX_WORKERS,
        DB_POOL_DEFAULT,
        DEFAULT_KEEPALIVE,
        CERT_NAME, KEY_NAME,
        home      ? home      : "(unresolved)",
        workspace ? workspace : "(unresolved)",
        cert_dir  ? cert_dir  : "(unresolved)",
        name, name, name, DOMAIN);
}


/* The event engine and the request handlers live in their own files.
   Both are textually included (not separate translation units), so they
   see every type, global and prototype declared above main() -- and
   neither belongs on the gcc line in ./compile. */
#include "os_tune.c"       /* kernel settings check + live apply at startup */
#include "epoll_helpers.c"
#include "handlers.c"

/* ==================================================================== *
 *  Section 4 -- general helpers
 * ==================================================================== */

void free_response(Response res){
    if(res.headers) free(res.headers);
    if(res.body) free(res.body);
}

char *hebrew_to_uri(const char *input) {
    const unsigned char *p = (const unsigned char *)input;
    char *out = malloc(strlen(input) * 3 + 1);  // worst case: every byte becomes %XX
    char *q = out;

    while (*p) {
        // Unreserved characters (RFC 3986)
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            *q++ = *p;
        } else {
            // Percent-encode everything else (including Hebrew UTF-8 bytes)
            sprintf(q, "%%%02X", *p);
            q += 3;
        }
        p++;
    }

    *q = '\0';
    return out;
}

/* ---- the upstream clients ------------------------------------------
   Non-blocking sockets driven with co_wait_fd(): inside a route the
   worker serves other connections while these wait, outside a route
   they simply block. One deadline for the whole exchange. */

static inline int deadline_left_ms(uint64_t deadline_ms) {
    uint64_t now = mono_ms();
    return now >= deadline_ms ? 0 : (int)(deadline_ms - now);
}

/* Wait until `fd` is ready for what OpenSSL asked for. 1 = go on,
   0 = deadline passed or error. */
static int ssl_wait(SSL *ssl, int fd, int r, uint64_t deadline_ms) {
    int err = SSL_get_error(ssl, r);
    uint32_t ev;
    if      (err == SSL_ERROR_WANT_READ)  ev = EPOLLIN;
    else if (err == SSL_ERROR_WANT_WRITE) ev = EPOLLOUT;
    else return 0;
    int left = deadline_left_ms(deadline_ms);
    if (left <= 0) return 0;
    return co_wait_fd(fd, ev, left) > 0;
}

/* Reads until the peer is done, into a buffer it grows itself. The buffer
   is handed back through *out and belongs to the caller.

   Returns the number of bytes read, or -1 on a fatal error or when the
   deadline passes before the peer finishes -- the same "return the
   count" convention. On -1 nothing
   is written to *out and the buffer is already freed. */
ssize_t ssl_read_all(SSL *ssl, char **out, uint64_t deadline_ms) {
    size_t cap = 65536;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return -1;
    int fd = SSL_get_fd(ssl);

    while (1) {
        if (len + 8192 > cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) {
                free(buf);
                return -1;
            }
            buf = tmp;
        }

        ERR_clear_error();
        int n = SSL_read(ssl, buf + len, cap - len);

        if (n > 0) {
            len += n;
            continue;
        }

        int err = SSL_get_error(ssl, n);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (ssl_wait(ssl, fd, n, deadline_ms)) continue;
            fprintf(stderr, "ssl_read_all: timed out waiting for the peer\n");
            free(buf);
            return -1;
        }

        if (err == SSL_ERROR_ZERO_RETURN) {
            // clean shutdown (peer sent close_notify)
            break;
        }

        if (err == SSL_ERROR_SYSCALL) {
            // connection closed at TCP level without close_notify
            if (len == 0) {
                fprintf(stderr,
                    "ssl_read_all: SYSCALL error before any data, errno=%d (%s)\n",
                    errno, strerror(errno));
            }
            break;
        }

        if (err == SSL_ERROR_SSL &&
            ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
            // OpenSSL 3.x reports an unclean close (no close_notify) here
            // instead of via SSL_ERROR_SYSCALL. Treat it like EOF.
            break;
        }

        // genuinely fatal error
        fprintf(stderr, "ssl_read_all: fatal SSL error\n");
        ERR_print_errors_fp(stderr);
        free(buf);
        return -1;
    }

    *out = buf;
    return (ssize_t)len;
}

/* getaddrinfo() has no non-blocking form: a route hands it to a helper
   thread through co_offload() and yields meanwhile. */
struct dns_task { const char *host; const char *port; struct addrinfo *res; int err; };
static void dns_task_run(void *arg) {
    struct dns_task *t = arg;
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    t->err = getaddrinfo(t->host, t->port, &hints, &t->res);
}

/* Non-blocking connect: 0 = connected, -1 = failed or deadline passed. */
static int connect_within(int sock, const struct sockaddr *sa, socklen_t salen, uint64_t deadline_ms) {
    if (connect(sock, sa, salen) == 0) return 0;
    if (errno != EINPROGRESS) return -1;
    int left = deadline_left_ms(deadline_ms);
    if (left <= 0 || co_wait_fd(sock, EPOLLOUT, left) <= 0) return -1;
    int soerr = 0; socklen_t sl = sizeof(soerr);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0 || soerr != 0) {
        errno = soerr;
        return -1;
    }
    return 0;
}

/* HTTPS client: fresh TCP + TLS connection per call, no certificate
   verification (as before), one deadline for everything. Yields inside
   a route. The parenthesised name keeps the default-argument macro
   from rewriting this definition. */
Response (https_request)(const char *hostname, const char *req, int timeout_s) {
    Response resp = {.headers = NULL, .headers_len = 0,
                      .body = NULL, .body_len = 0, .status = {0}};
    const char *port = "443";
    int sock = -1;
    struct addrinfo *res = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *response = NULL;
    size_t out_len = 0;
    uint64_t deadline = mono_ms() + (uint64_t)(timeout_s > 0 ? timeout_s : HTTP_TIMEOUT_DEFAULT) * 1000u;

    // 1. Resolve hostname (on a helper thread; this route yields)
    struct dns_task dns = { hostname, port, NULL, 0 };
    co_offload(dns_task_run, &dns);
    res = dns.res;
    if (dns.err != 0 || !res) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(dns.err));
        return resp;
    }

    // 2. Create TCP socket and connect
    sock = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, res->ai_protocol);
    if (sock < 0) {
        perror("socket");
        goto cleanup;
    }
    if (connect_within(sock, res->ai_addr, res->ai_addrlen, deadline) < 0) {
        perror("connect");
        goto cleanup;
    }

    // 3. TLS context for this call
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // 4. Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    SSL_set_fd(ssl, sock);

    // ** Set SNI before the handshake ** -- without it many servers
    // silently close the connection or route you somewhere unexpected.
    SSL_set_tlsext_host_name(ssl, hostname);

    // 5. TLS handshake
    for (;;) {
        ERR_clear_error();
        int r = SSL_connect(ssl);
        if (r == 1) break;
        if (!ssl_wait(ssl, sock, r, deadline)) {
            fprintf(stderr, "SSL_connect failed\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
    }

    // 6. Send HTTPS request
    {
        size_t len = strlen(req), sent = 0;
        while (sent < len) {
            ERR_clear_error();
            int r = SSL_write(ssl, req + sent, (int)(len - sent));
            if (r > 0) { sent += (size_t)r; continue; }
            if (!ssl_wait(ssl, sock, r, deadline)) {
                fprintf(stderr, "SSL_write failed\n");
                ERR_print_errors_fp(stderr);
                goto cleanup;
            }
        }
    }

    // 7. Read response -- the byte count comes back as the return value
    {
        ssize_t nread = ssl_read_all(ssl, &response, deadline);
        if (nread < 0) {
            fprintf(stderr, "ssl_read_all failed\n");
            goto cleanup;
        }
        out_len = (size_t)nread;
    }

    {
        char *tmp = realloc(response, out_len + 1);
        if (!tmp) {
            fprintf(stderr, "realloc failed\n");
            free(response);
            response = NULL;
            goto cleanup;
        }
        response = tmp;
        response[out_len] = '\0';
    }

    // --- split headers/body ---
    {
        char *p = response;
        char *hdr_end = strstr(p, "\r\n\r\n");
        if (hdr_end) {
            size_t hdr_size = hdr_end - p;
            resp.headers = malloc(hdr_size + 1);
            if (resp.headers) {
                memcpy(resp.headers, p, hdr_size);
                resp.headers[hdr_size] = '\0';
                resp.headers_len = hdr_size;
            }

            char *body_start = hdr_end + 4;
            size_t body_len = out_len - (body_start - p);
            resp.body = malloc(body_len + 1);
            if (resp.body) {
                memcpy(resp.body, body_start, body_len);
                resp.body[body_len] = '\0';
                resp.body_len = body_len;
            }

            // status line: "HTTP/1.1 200 OK"
            if (resp.headers) {
                char *sp1 = strchr(resp.headers, ' ');
                if (sp1) {
                    char *sp2 = strchr(sp1 + 1, ' ');
                    char *line_end = strstr(resp.headers, "\r\n");
                    char *status_end = sp2 ? sp2 : line_end;
                    if (status_end) {
                        size_t status_len = status_end - (sp1 + 1);
                        if (status_len >= sizeof(resp.status))
                            status_len = sizeof(resp.status) - 1;
                        strncpy(resp.status, sp1 + 1, status_len);
                        resp.status[status_len] = '\0';
                    }
                }
            }
        }
    }

    free(response);

cleanup:
    if (ssl) {
        SSL_shutdown(ssl);               /* one-way close_notify, no waiting */
        SSL_free(ssl);
    }
    if (ctx) SSL_CTX_free(ctx);
    if (sock >= 0) co_close(sock);
    if (res) freeaddrinfo(res);
    return resp;
}

/*
 * Plain-HTTP client -- the non-TLS sibling of https_request().
 * Connects to host:port, sends `request` verbatim, and returns the response.
 *   host      - dotted IPv4 address, e.g. "10.21.2.10"
 *   port      - TCP port, e.g. 80
 *   request   - the full raw HTTP request (headers + body), sent as-is
 *   timeout_s - deadline for the whole exchange (HTTP_TIMEOUT_DEFAULT)
 *
 * On success returns a Response whose .headers and .body are heap-allocated
 * (free via free_response) and .status holds the numeric code (e.g. "200").
 * On any failure, including the deadline passing, returns a Response with
 * headers == NULL, body == NULL and status == "-1".
 *
 * Inside a route it yields while waiting (the worker serves other
 * connections); outside a coroutine it blocks the caller.
 */
Response (http_request)(const char *host, int port, const char *request, int timeout_s) {
    Response resp;
    memset(&resp, 0, sizeof(resp));
    strcpy(resp.status, "-1");

    if (host == NULL || request == NULL)
        return resp;

    size_t req_len = strlen(request);
    uint64_t deadline = mono_ms() + (uint64_t)(timeout_s > 0 ? timeout_s : HTTP_TIMEOUT_DEFAULT) * 1000u;

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0)
        return resp;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        co_close(sock);
        return resp;
    }

    if (connect_within(sock, (struct sockaddr *)&addr, sizeof(addr), deadline) < 0) {
        co_close(sock);
        return resp;
    }

    /* Send the whole request, handling partial writes. */
    size_t sent = 0;
    while (sent < req_len) {
        ssize_t w = send(sock, request + sent, req_len - sent, MSG_NOSIGNAL);
        if (w > 0) { sent += (size_t)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int left = deadline_left_ms(deadline);
            if (left > 0 && co_wait_fd(sock, EPOLLOUT, left) > 0) continue;
        }
        co_close(sock);
        return resp;
    }

    /* Read the full response into a growing buffer. */
    char   *raw = NULL;
    size_t  raw_len = 0, raw_cap = 0;
    char    buf[4096];
    ssize_t n;
    for (;;) {
        n = recv(sock, buf, sizeof(buf), 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int left = deadline_left_ms(deadline);
            if (left > 0 && co_wait_fd(sock, EPOLLIN, left) > 0) continue;
            free(raw); raw = NULL;            /* timed out: fail like an error */
            break;
        }
        if (n <= 0) break;                    /* peer closed, or error */
        if (raw_len + (size_t)n + 1 > raw_cap) {
            size_t new_cap = raw_cap ? raw_cap * 2 : 8192;
            while (new_cap < raw_len + (size_t)n + 1) new_cap *= 2;
            char *tmp = realloc(raw, new_cap);
            if (!tmp) { free(raw); co_close(sock); return resp; }
            raw = tmp;
            raw_cap = new_cap;
        }
        memcpy(raw + raw_len, buf, (size_t)n);
        raw_len += (size_t)n;
    }
    co_close(sock);

    if (raw == NULL)                      /* no data received */
        return resp;
    raw[raw_len] = '\0';

    /* Extract the numeric status code (2nd token of the status line) into
       resp.status. Falls back to "-1" if it can't be parsed. */
    {
        size_t i = 0;
        while (i < raw_len && raw[i] != ' ' && raw[i] != '\r' && raw[i] != '\n')
            i++;                              /* skip "HTTP/1.1" */
        while (i < raw_len && raw[i] == ' ')
            i++;                              /* skip spaces */
        size_t j = 0;
        while (i < raw_len && raw[i] >= '0' && raw[i] <= '9'
               && j < sizeof(resp.status) - 1)
            resp.status[j++] = raw[i++];      /* copy the code digits */
        resp.status[j] = '\0';
        if (j == 0)
            strcpy(resp.status, "-1");
    }

    /* Split headers and body at the first CRLFCRLF. */
    char *split = NULL;
    for (size_t i = 0; i + 4 <= raw_len; i++) {
        if (memcmp(raw + i, "\r\n\r\n", 4) == 0) { split = raw + i; break; }
    }

    if (split) {
        resp.headers_len = (size_t)(split - raw);
        resp.body_len    = raw_len - resp.headers_len - 4;

        resp.headers = malloc(resp.headers_len + 1);
        resp.body    = malloc(resp.body_len + 1);
        if (!resp.headers || !resp.body) {
            free(resp.headers); free(resp.body);
            memset(&resp, 0, sizeof(resp));
            strcpy(resp.status, "-1");
            free(raw);
            return resp;
        }
        memcpy(resp.headers, raw, resp.headers_len);
        resp.headers[resp.headers_len] = '\0';
        memcpy(resp.body, split + 4, resp.body_len);
        resp.body[resp.body_len] = '\0';

        /* HTTP/1.1 servers may answer "Transfer-Encoding: chunked" even
           with Connection: close. Decode in place so callers always see
           the real payload: each chunk is "<hex-len>[;ext]\r\n<data>\r\n",
           terminated by a zero-length chunk. */
        {
            int chunked = 0;
            const char *te = resp.headers;
            while ((te = strcasestr(te, "transfer-encoding:")) != NULL) {
                const char *eol = strstr(te, "\r\n");
                size_t span = eol ? (size_t)(eol - te) : strlen(te);
                char line[128];
                if (span >= sizeof(line)) span = sizeof(line) - 1;
                memcpy(line, te, span);
                line[span] = '\0';
                if (strcasestr(line, "chunked")) { chunked = 1; break; }
                te += 18;
            }
            if (chunked) {
                size_t in = 0, out = 0;
                while (in < resp.body_len) {
                    char *endp = NULL;
                    unsigned long len = strtoul(resp.body + in, &endp, 16);
                    if (endp == resp.body + in) break;         /* not a hex size */
                    char *crlf = strstr(endp, "\r\n");
                    if (!crlf) break;
                    in = (size_t)(crlf - resp.body) + 2;         /* past size line */
                    if (len == 0) break;                         /* last chunk */
                    if (in + len > resp.body_len) len = resp.body_len - in;
                    memmove(resp.body + out, resp.body + in, len);
                    out += len;
                    in  += len + 2;                              /* skip chunk CRLF */
                }
                resp.body_len = out;
                resp.body[out] = '\0';
            }
        }
    } else {
        resp.headers_len = raw_len;
        resp.headers = malloc(raw_len + 1);
        if (!resp.headers) {
            memset(&resp, 0, sizeof(resp));
            strcpy(resp.status, "-1");
            free(raw);
            return resp;
        }
        memcpy(resp.headers, raw, raw_len);
        resp.headers[raw_len] = '\0';
        resp.body = malloc(1);
        if (resp.body) resp.body[0] = '\0';
        resp.body_len = 0;
    }

    free(raw);
    return resp;
}

/* return 1 if s contains "..", else 0 */
static int contains_dotdot(const char *s) {
    if (!s) return 1;
    for (const char *p = s; *p; ++p) {
        if (p[0] == '.' && p[1] == '.') return 1;
    }
    return 0;
}

/* Simple allowed-file check using stat + access only.
 * home should be like "/var/www/" (prefer trailing slash).
 * host is the site folder (e.g., "example.com").
 * uri is the request path (e.g., "/index.html" or "index.html").
 * Returns 1 if file exists, is regular, and readable; otherwise 0.
 */
int is_file_allowed(const char *home, const char *host, const char *uri) {
    if (!home || !host || !uri) return 0;

    if (contains_dotdot(host) || contains_dotdot(uri)) return 0;

    /* normalize uri: skip leading slash */
    const char *u = uri;
    if (u[0] == '/') u++;

    char candidate[PATH_MAX];
    int n = snprintf(candidate, sizeof(candidate), "%s%s/%s", home, host, u);
    if (n < 0 || n >= (int)sizeof(candidate)) return 0;

    struct stat st;
    if (stat(candidate, &st) != 0) return 0;        /* not exists or stat error */
    if (!S_ISREG(st.st_mode)) return 0;             /* not a regular file */
    if (access(candidate, R_OK) != 0) return 0;     /* not readable */

    return 1;
}

FileInfo get_file(const char* host, const char* filename) {
    FileInfo result;
    result.data = NULL;
    result.size = 0;
    char path[PATH_MAX];
    if (!host || !filename) return result;

    /* FIX: was strcpy + two strcat into char[1024]. Harmless while HOME was
       a fixed literal; with a runtime site root it needs a bound. */
    int n = snprintf(path, sizeof(path), "%s%s%s", workspace, host, filename);
    if (n < 0 || n >= (int)sizeof(path)) {
        fprintf(stderr, "path too long: %s%s%s\n", workspace, host, filename);
        return result;
    }

    FILE* file = fopen(path, "r");
    if (!file) {
        perror("Failed to open file");
        return result;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek failed");
        fclose(file);
        return result;
    }

    long size = ftell(file);
    if (size < 0) {
        perror("ftell failed");
        fclose(file);
        return result;
    }
    rewind(file);

    char* buffer = (char*)calloc((size_t)size + 1, sizeof(char));
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return result;
    }

    size_t read = fread(buffer, 1, size, file);
    fclose(file);

    if (read != (size_t)size) {
        fprintf(stderr, "Only read %zu of %ld bytes\n", read, size);
        free(buffer);
        return result;
    }

    result.data = buffer;
    result.size = read;
    return result;
}

/* One fresh connection with the credentials above. Routes do NOT call
   this: they call connect_db(), which keeps one of these per handler
   thread and hands it out again and again (see epoll_helpers.c). */
static MYSQL *db_open_raw(void) {
    MYSQL *conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init() failed\n");
        return NULL;
    }
    if (mysql_real_connect(conn, DB_HOST, DB_USERNAME, DB_PASSWORD, DB_SCHEMA, 0, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect() failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }
    return conn;
}

void print_signal_error(int sig_num) {
    const char *sig_name;

    switch (sig_num) {
        case SIGHUP:    sig_name = "SIGHUP (Hangup detected)"; break;
        case SIGINT:    sig_name = "SIGINT (Interrupt from keyboard)"; break;
        case SIGQUIT:   sig_name = "SIGQUIT (Quit from keyboard)"; break;
        case SIGILL:    sig_name = "SIGILL (Illegal instruction)"; break;
        case SIGTRAP:   sig_name = "SIGTRAP (Trace/breakpoint trap)"; break;
        case SIGABRT:   sig_name = "SIGABRT (Abort signal)"; break;
        case SIGBUS:    sig_name = "SIGBUS (Bus error)"; break;
        case SIGFPE:    sig_name = "SIGFPE (Floating point exception)"; break;
        case SIGKILL:   sig_name = "SIGKILL (Kill signal)"; break;
        case SIGUSR1:   sig_name = "SIGUSR1 (User-defined signal 1)"; break;
        case SIGSEGV:   sig_name = "SIGSEGV (Segmentation fault)"; break;
        case SIGUSR2:   sig_name = "SIGUSR2 (User-defined signal 2)"; break;
        case SIGPIPE:   sig_name = "SIGPIPE (Broken pipe)"; break;
        case SIGALRM:   sig_name = "SIGALRM (Timer signal)"; break;
        case SIGTERM:   sig_name = "SIGTERM (Termination signal)"; break;
        case SIGSTKFLT: sig_name = "SIGSTKFLT (Stack fault on coprocessor)"; break;
        case SIGCHLD:   sig_name = "SIGCHLD (Child stopped or terminated)"; break;
        case SIGCONT:   sig_name = "SIGCONT (Continue if stopped)"; break;
        case SIGSTOP:   sig_name = "SIGSTOP (Stop process)"; break;
        case SIGTSTP:   sig_name = "SIGTSTP (Stop typed at terminal)"; break;
        case SIGTTIN:   sig_name = "SIGTTIN (Terminal input for background process)"; break;
        case SIGTTOU:   sig_name = "SIGTTOU (Terminal output for background process)"; break;
        case SIGURG:    sig_name = "SIGURG (Urgent condition on socket)"; break;
        case SIGXCPU:   sig_name = "SIGXCPU (CPU time limit exceeded)"; break;
        case SIGXFSZ:   sig_name = "SIGXFSZ (File size limit exceeded)"; break;
        case SIGVTALRM: sig_name = "SIGVTALRM (Virtual alarm clock)"; break;
        case SIGPROF:   sig_name = "SIGPROF (Profiling timer expired)"; break;
        case SIGWINCH:  sig_name = "SIGWINCH (Window size change)"; break;
        case SIGIO:     sig_name = "SIGIO (I/O now possible)"; break;
        case SIGPWR:    sig_name = "SIGPWR (Power failure)"; break;
        case SIGSYS:    sig_name = "SIGSYS (Bad system call)"; break;
        default:        sig_name = "Unknown signal"; break;
    }

    fprintf(stdout, "Received signal %d: %s\n", sig_num, sig_name);
}

void handler(int sig) {
    print_signal_error(sig);
}

void bind_signal_handlers(){
    signal(SIGHUP, handler);
//    signal(SIGINT, handler);
//    signal(SIGQUIT, handler);
    signal(SIGILL, handler);
    signal(SIGTRAP, handler);
    signal(SIGABRT, handler);
#ifdef SIGIOT
    signal(SIGIOT, handler);
#endif
    signal(SIGBUS, handler);
    signal(SIGFPE, handler);
//    signal(SIGKILL, handler); // Cannot be caught or ignored
    signal(SIGUSR1, handler);
    signal(SIGSEGV, handler);
    signal(SIGUSR2, handler);
//    signal(SIGPIPE, handler); // ignored in main() instead
    signal(SIGALRM, handler);
//    signal(SIGTERM, handler);
    signal(SIGCHLD, handler);
    signal(SIGCONT, handler);
  //  signal(SIGSTOP, handler); // Cannot be caught or ignored
    signal(SIGTSTP, handler);
    signal(SIGTTIN, handler);
    signal(SIGTTOU, handler);
    signal(SIGURG, handler);
    signal(SIGXCPU, handler);
    signal(SIGXFSZ, handler);
    signal(SIGVTALRM, handler);
    signal(SIGPROF, handler);
    signal(SIGWINCH, handler);
    signal(SIGPOLL, handler);
#ifdef SIGPWR
    signal(SIGPWR, handler);
#endif
#ifdef SIGSYS
    signal(SIGSYS, handler);
#endif
}

/* Server-side ALPN. SSL_CTX_set_alpn_protos() is the CLIENT API -- on a
   server it has no effect, so http/1.1 was never actually negotiated. */
static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    static const unsigned char h11[] = "\x08http/1.1";
    unsigned char *sel = NULL;
    if (SSL_select_next_proto(&sel, outlen, h11, sizeof(h11) - 1, in, inlen)
            == OPENSSL_NPN_NEGOTIATED) {
        *out = sel;
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

#ifndef SSL_OP_ENABLE_KTLS
#define SSL_OP_ENABLE_KTLS 0
#endif

/* "tls" listed in tcp_available_ulp == the kernel TLS module is loaded */
static int ktls_available(void) {
    FILE *f = fopen("/proc/sys/net/ipv4/tcp_available_ulp", "r");
    if (!f) return 0;
    char buf[256] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    for (char *t = strtok(buf, " \n"); t; t = strtok(NULL, " \n"))
        if (strcmp(t, "tls") == 0) return 1;
    return 0;
}

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Failed to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* SSL_OP_ENABLE_KTLS: once the handshake is done OpenSSL hands the keys
       to the kernel (if `modprobe tls` is loaded) and SSL_write becomes a
       plain write that the kernel encrypts. Harmless when unavailable. */
    /* IGNORE_UNEXPECTED_EOF: a client that just closes (most browsers do,
       without close_notify) is treated as a normal EOF instead of an error
       that fills OpenSSL's error queue on every connection. */
    long opts = SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION |
                SSL_OP_CIPHER_SERVER_PREFERENCE;
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    opts |= SSL_OP_IGNORE_UNEXPECTED_EOF;
#endif
    /* only ask for kTLS when the kernel has it -- otherwise OpenSSL makes
       two failing setsockopt(TCP_ULP) calls on every connection */
    if (ktls_available()) opts |= SSL_OP_ENABLE_KTLS;
    SSL_CTX_set_options(ctx, opts);

    /* AEAD only, X25519 first: fastest key exchange, and the suites the
       kernel can offload */
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384");
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");

    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);

    /* Stateless session tickets instead of the server-side cache: the
       cache is one table behind one lock shared by every worker. */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx, 1);

    /* one recv() per TLS record instead of a 5-byte header read + body */
    SSL_CTX_set_read_ahead(ctx, 1);

    /* Non-blocking sockets: let SSL_write report a partial write instead of
       insisting the whole record go out in one call, and tolerate the buffer
       address moving between retries. */
    /* RELEASE_BUFFERS: OpenSSL frees its ~17 KB read and ~17 KB write
       record buffers whenever they are empty, instead of keeping both for
       the life of the connection. Idle keep-alive connections then cost a
       few KB each -- the single biggest lever for holding many at once. */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                          SSL_MODE_RELEASE_BUFFERS);
    return ctx;
}

/* Load one certificate CHAIN + key.

   SSL_CTX_use_certificate_chain_file() -- not SSL_CTX_use_certificate_file()
   -- so the leaf AND every intermediate go out in the handshake. OpenSSL
   keeps one chain per key type, so an RSA and an ECDSA chain can be loaded
   side by side: modern clients get ECDSA (a much cheaper handshake), old
   RSA-only clients still connect.

   Returns 0 loaded, 1 skipped (that key type is already loaded), -1 fatal. */
static int load_cert_pair(SSL_CTX *ctx, const char *chain, const char *key,
                          int *have_rsa, int *have_ec) {
    FILE *f = fopen(chain, "r");
    if (!f) { fprintf(stderr, "cannot open %s: %s\n", chain, strerror(errno)); return -1; }
    int ncerts = 0;
    X509 *leaf = NULL, *x;
    while ((x = PEM_read_X509(f, NULL, NULL, NULL))) {
        if (!leaf) leaf = x; else X509_free(x);
        ncerts++;
    }
    fclose(f);
    ERR_clear_error();                          /* PEM EOF leaves an error */
    if (!leaf) { fprintf(stderr, "no certificate in %s\n", chain); return -1; }

    int type  = EVP_PKEY_get_base_id(X509_get0_pubkey(leaf));
    int is_ec = (type == EVP_PKEY_EC);
    int *slot = is_ec ? have_ec : have_rsa;
    const char *tname = is_ec ? "ECDSA" : (type == EVP_PKEY_RSA ? "RSA" : "other");

    char cn[256] = "?";
    X509_NAME_get_text_by_NID(X509_get_subject_name(leaf), NID_commonName, cn, sizeof(cn));
    int days = 0, secs = 0;
    ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(leaf));
    X509_free(leaf);

    if (*slot) {
        fprintf(stdout, "\e[1;33mwarning\e[0m: %s is a second %s chain -- skipped\n", chain, tname);
        return 1;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, chain) <= 0) {
        fprintf(stderr, "Failed to load certificate chain %s\n", chain);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Private key %s does not load or does not match %s\n", key, chain);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *slot = 1;

    fprintf(stdout, "\e[0;93mcert         \e[92m%-5s\e[0m %s  CN=%s  chain=%d  expires in %d days\n",
            tname, chain, cn, ncerts, days);
    if (ncerts < 2)
        fprintf(stdout, "\e[1;31mwarning\e[0m: %s holds only the leaf certificate -- use the "
                        "FULL chain (fullchain.pem) or many clients will reject it\n", chain);
    if (days < 0)
        fprintf(stdout, "\e[1;31mwarning\e[0m: %s has EXPIRED\n", chain);
    else if (days < 14)
        fprintf(stdout, "\e[1;33mwarning\e[0m: %s expires in %d days -- renew it\n", chain, days);
    return 0;
}

void configure_ssl_context(SSL_CTX *ctx) {
    int have_rsa = 0, have_ec = 0;

    /* primary pair: certs/fullchain.pem + certs/privkey.pem (required) */
    if (load_cert_pair(ctx, cert_file, key_file, &have_rsa, &have_ec) != 0) {
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    /* extra pairs: certs/fullchain.pem.<tag> + certs/privkey.pem.<tag> */
    DIR *d = opendir(cert_dir);
    if (!d) return;
    const char *pfx = CERT_NAME ".";
    size_t pl = strlen(pfx);
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strncmp(de->d_name, pfx, pl) != 0 || !de->d_name[pl]) continue;
        char chain[PATH_MAX], key[PATH_MAX];
        snprintf(chain, sizeof(chain), "%s%s", cert_dir, de->d_name);
        snprintf(key, sizeof(key), "%s" KEY_NAME ".%s", cert_dir, de->d_name + pl);
        if (access(key, R_OK) != 0) {
            fprintf(stdout, "\e[1;33mwarning\e[0m: %s has no matching %s -- skipped\n", chain, key);
            continue;
        }
        if (load_cert_pair(ctx, chain, key, &have_rsa, &have_ec) < 0) {
            closedir(d);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }
    closedir(d);
}

char * method_to_str(Method method){
  switch(method){
    case M_OPTIONS: return "OPTIONS";
    case M_DELETE:  return "DELETE";
    case M_CONNECT: return "CONNECT";
    case M_GET:     return "GET";
    case M_PUT:     return "PUT";
    case M_PATCH:   return "PATCH";
    case M_TRACE:   return "TRACE";
    case M_HEAD:    return "HEAD";
    case M_POST:    return "POST";
    default:      return "UNSUPPORTED_METHOD";
  }
}

const char *get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return "text/html";
    const char *ext = dot + 1;

    for (int i = 0; mime_map[i].extension != NULL; ++i) {
        if (strcasecmp(ext, mime_map[i].extension) == 0) {
            return mime_map[i].mime_type;
        }
    }
    return "application/octet-stream";
}

void random_string(char *out, size_t len) {
    const char *alphabet =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    size_t alphabet_len = 62;

    for (size_t i = 0; i < len; i++) {
        out[i] = alphabet[rand() % alphabet_len];
    }

    out[len] = '\0';
}
