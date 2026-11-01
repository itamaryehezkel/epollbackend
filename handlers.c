/* ====================================================================
 *  handlers.c
 *
 *  Requests: parsing bytes into a Request, the Request header-table API,
 *  and the two handlers -- handle_request() for the HTTPS routes (YOUR
 *  CODE GOES THERE) and handle_http_redirect() for the plain :80
 *  listener.
 *
 *  NOT a separate translation unit -- main.c #includes it textually. It
 *  relies on the types, globals and prototypes declared above main.c's
 *  #include of this file, and must NOT be added to the gcc line in
 *  ./compile.
 *
 *  How a route runs, in one paragraph: handle_request() executes as a
 *  coroutine on the thread that owns the client's socket, a thread that
 *  also serves thousands of other connections. It may do anything,
 *  provided that when it WAITS it waits through the calls that park the
 *  route and let the worker go on -- https_request() / http_request(),
 *  co_mysql_query() / co_mysql_store_result(), connect_db(),
 *  co_sleep_ms(), co_offload(), co_mutex_lock() -- and never through
 *  sleep(), a blocking socket, getaddrinfo(), mysql_query() or a pthread
 *  lock held across those calls. See HANDLER_README.c.
 * ==================================================================== */
#ifndef HANDLERS_C_INCLUDED
#define HANDLERS_C_INCLUDED

/* ==================================================================== *
 *  Section 2 -- request parsing, shared by the HTTP and HTTPS handlers
 * ==================================================================== */

/* ------------------------------------------------------------------ *
 *  parse_request -- the shared HTTP parser.
 *
 *  Request-line tokenising, the method enum, the uri/query split and an
 *  in-place header table, as one function, so the HTTPS side and the
 *  plain :80 side both get their Request from one place.
 *
 *  Transport-agnostic on purpose -- it never touches the SSL object. It
 *  reads the finished byte buffer the state machine collected (c->in,
 *  complete through c->headers_end + Content-Length) and parses it in
 *  place, so every string in the returned Request points into c->in and
 *  none of them is separately owned.
 *
 *  Returns the Request by value. Check .parsed: 1 means usable, 0 means
 *  the request was malformed and the caller should drop the connection.
 *  Either way the caller must free_headers() -- a failed parse can still
 *  have allocated part of the table.
 * ------------------------------------------------------------------ */
Request parse_request(conn_t *c) {
    Request  r;
    Request *req = &r;

    memset(req, 0, sizeof(*req));
    req->c      = c;
    req->parsed = 0;
    req->is_tls = c->is_tls;

    char *buf = c->in;
    int   total = (int)c->in_len;
    long  headers_end = c->headers_end;

    req->buffer      = buf;
    req->buffer_size = (int)c->in_cap;
    req->total_read  = total;
    memcpy(req->ip, c->ip, INET_ADDRSTRLEN);

    if (headers_end < 0) {
        fprintf(stderr, "headers not complete or buffer overflow\n");
        return r;
    }

    /* Parse request-line (first line up to CRLF) */
    int reqline_end = -1;
    for (int i = 0; i < total - 1; ++i) {
        if (buf[i] == '\r' && buf[i+1] == '\n') {
            reqline_end = i;
            break;
        }
    }
    if (reqline_end < 0) {
        fprintf(stderr, "malformed request-line\n");
        return r;
    }

    /* Make request-line a C string */
    buf[reqline_end] = '\0';

    /* tokens: METHOD SP URI SP VERSION */
    char *cursor = buf;
    char *method_tok = cursor;
    char *sp = strchr(cursor, ' ');
    if (!sp) return r;
    *sp = '\0';
    cursor = sp + 1;

    char *uri_tok = cursor;
    sp = strchr(cursor, ' ');
    if (!sp) return r;
    *sp = '\0';
    cursor = sp + 1;

    char *version_tok = cursor;

    /* set method enum */
    if (strcasecmp(method_tok, "GET") == 0) req->method = M_GET;
    else if (strcasecmp(method_tok, "POST") == 0) req->method = M_POST;
    else if (strcasecmp(method_tok, "PUT") == 0) req->method = M_PUT;
    else if (strcasecmp(method_tok, "PATCH") == 0) req->method = M_PATCH;
    else if (strcasecmp(method_tok, "DELETE") == 0) req->method = M_DELETE;
    else if (strcasecmp(method_tok, "OPTIONS") == 0) req->method = M_OPTIONS;
    else if (strcasecmp(method_tok, "HEAD") == 0) req->method = M_HEAD;
    else if (strcasecmp(method_tok, "TRACE") == 0) req->method = M_TRACE;
    else if (strcasecmp(method_tok, "CONNECT") == 0) req->method = M_CONNECT;
    else req->method = M_UNSUPPORTED;

    req->version = version_tok;

    /* set uri and query pointers (in-place) */
    char *qmark = strchr(uri_tok, '?');
    if (qmark) {
        *qmark = '\0';
        req->uri = uri_tok;
        req->query = qmark + 1;
    } else {
        req->uri = uri_tok;
        req->query = NULL;
    }

    /* Parse headers: each header line between reqline_end+2 and headers_end-1 */
    int hdr_start = reqline_end + 2;      /* skip CRLF */
    int hdr_end   = (int)headers_end;     /* points after CRLFCRLF */

    /* Count header lines first */
    int count = 0;
    for (int i = hdr_start; i < hdr_end - 1; ) {
        int le = i;
        while (le < hdr_end - 1 && !(buf[le] == '\r' && buf[le+1] == '\n')) le++;
        if (le >= hdr_end - 1) break;
        count++;
        i = le + 2;
    }

    req->headers = NULL;
    req->headers_count = 0;

    if (count > 0) {
        /* outer array: one char** row per header + a NULL terminator */
        req->headers = calloc(count + 1, sizeof(char **));
        if (!req->headers) {
            perror("calloc headers");
            return r;
        }
    }

    int idx = 0;
    for (int i = hdr_start; i < hdr_end - 1; ) {
        int le = i;
        while (le < hdr_end - 1 && !(buf[le] == '\r' && buf[le+1] == '\n')) le++;
        if (le >= hdr_end - 1) break;
        /* null-terminate this header line */
        buf[le] = '\0';

        char *line  = buf + i;
        char *colon = strchr(line, ':');
        i = le + 2;                       /* advance regardless of what follows */

        if (!colon) continue;             /* malformed header line -- skip it */
        if (!req->headers) continue;

        *colon = '\0';                    /* split "Name: value" in place */
        char *name  = trim_inplace(line);
        char *value = trim_inplace(colon + 1);
        if (*name == '\0') continue;      /* empty header name -- skip it */

        /* row: { name, value, NULL } */
        char **pair = calloc(3, sizeof(char *));
        if (!pair) {
            perror("calloc header pair");
            if (req->headers) req->headers[idx] = NULL;  /* keep it walkable */
            return r;
        }
        pair[0] = name;
        pair[1] = value;
        pair[2] = NULL;
        req->headers[idx++] = pair;
    }
    if (req->headers) req->headers[idx] = NULL;
    req->headers_count = idx;

    

    /* Nothing is copied out of the table here -- Host and everything else
       are read on demand with get_header() / get_header_default(). */

    /* Body: everything after the header block (we waited for
       Content-Length bytes, so this is the whole body). */
    if (total > hdr_end) {
        req->body     = buf + hdr_end;
        req->body_len = (size_t)(total - hdr_end);
    } else {
        req->body     = NULL;
        req->body_len = 0;
    }

    req->parsed = 1;
    return r;
}

/* Does this server actually serve `host`? True when <workspace>/<host> is
   a directory -- the same site-per-directory layout get_file() and
   is_file_allowed() already assume. Also the trust boundary for the
   redirect below: a Host the server does not serve is not a Host we are
   willing to send a browser to. */
static int is_known_host(const char *host) {
    if (!host || !*host) return 0;
    if (contains_dotdot(host)) return 0;

    /* hostname characters only -- no '/', no ':', no CR/LF (header
       injection), no anything that could steer the Location elsewhere */
    for (const char *p = host; *p; ++p) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-'))
            return 0;
    }

    char candidate[PATH_MAX];
    int n = snprintf(candidate, sizeof(candidate), "%s%s", workspace, host);
    if (n < 0 || n >= (int)sizeof(candidate)) return 0;

    struct stat st;
    if (stat(candidate, &st) != 0) return 0;
    return S_ISDIR(st.st_mode) ? 1 : 0;
}

/* Which host the 302 should point at.
   The Host header is client-controlled, so it is never reflected as-is:
   the port is stripped, then the name has to pass is_known_host(). A
   host we serve redirects to itself (so api.example.com stays on
   api.example.com); anything else -- a missing Host, a garbage Host, or
   "Host: evil.com" trying to borrow this server as an open redirector --
   falls back to DOMAIN. Result is written into buf, or `domain` is
   returned directly. */
static const char *redirect_host(Request *req, char *buf, size_t buflen) {
    const char *h = get_header(req, "Host");
    if (!h || !*h) return domain;

    /* copy out up to ":port" -- the header value points into c->in */
    size_t n = 0;
    while (h[n] && h[n] != ':' && n + 1 < buflen) n++;
    if (h[n] && h[n] != ':') return domain;     /* longer than buf */

    memcpy(buf, h, n);
    buf[n] = '\0';

    return is_known_host(buf) ? buf : domain;
}

/* The plain :80 listener: a 302 up to TLS. It lives in the same event
   loop as everything else.
   The request is fully parsed before we get here (same parse_request()
   the HTTPS side uses), so it is logged like any other request and its
   body is drained. The Location now follows the parsed Host header
   instead of always being DOMAIN, subject to the check above; the path
   is not carried over, every redirect lands on the site root. */
static void handle_http_redirect(conn_t *c, Request *req) {
    char hostbuf[256];
    const char *host = redirect_host(req, hostbuf, sizeof(hostbuf));

    char response[512];
    int n = snprintf(response, sizeof(response),
                     "HTTP/1.1 302 Found\r\n"
                     "Location: https://%s/\r\n"
                     "Connection: keep-alive\r\n\r\n", host);
    if (n > 0 && n < (int)sizeof(response))
        out_append(c, response, (size_t)n);
}


/* ==================================================================== *
 *  Section 3 -- the routes
 *
 *  A route builds its response and hands it to out_append(); writing to
 *  the socket is the state machine's job, not the handler's. A route
 *  that wants to drop the connection simply stops appending. The full
 *  API a route can use is documented in HANDLER_README.c; the short
 *  version:
 *
 *   req->method / uri / query / body / body_len / ip / is_tls
 *   get_header(req, name), get_header_default(req, name, fallback)
 *   out_append(c, data, len)
 *   get_file(host, path), get_mime_type(path), is_file_allowed(root, host, uri)
 *   https_request() / http_request() / free_response()     (they yield)
 *   connect_db() / db_release() / co_mysql_*()              (USE_DATABASE 1)
 *   random_string(out, len), cJSON_*
 * ==================================================================== */

/* Queue a 500 Internal Server Error onto the connection's out buffer.
   Used everywhere handle_request() hits an unrecoverable per-request error
   (DB down, a failed query, an allocation failure). It must NEVER take the
   whole server down -- one bad request is one 500, not an exit(). Uses its
   own small stack buffer so it is safe even when `res` could not be
   allocated. do_handle() moves the connection to CS_WRITE afterwards, so
   whatever we append here is what the client receives. */
static void send_500(conn_t *c) {
    static const char body[] = "{\"status\":\"error\"}";
    char hdr[192];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n\r\n%s", sizeof(body) - 1, body);
    if (n > 0 && n < (int)sizeof(hdr))
        out_append(c, hdr, (size_t)n);
}

static void handle_request(conn_t *c, Request *req) {

    /* Host comes out of the header table -- looked up once here and
       passed down. The domain fallback keeps a Host-less request from
       reaching get_file() with a NULL. The Host header may carry
       ":port", so compare on a stripped copy. */
    char *host = get_header_default(req, "Host", domain);
    char hostname[256];
    {
        size_t n = 0;
        while (host[n] && host[n] != ':' && n + 1 < sizeof(hostname)) n++;
        memcpy(hostname, host, n);
        hostname[n] = '\0';
    }

    /* Response header buffer. Bodies go through out_append() directly,
       so this only ever holds a status line and headers. */
    char *res = malloc(2048);
    if (!res) { send_500(c); return; }

    /* ---------------------------------------------------------------- *
     *  YOUR ROUTES GO HERE, before the static-file fallback, e.g.
     *
     *      if (strcmp(req->uri, "/api/hello") == 0 && req->method == M_GET) {
     *          const char *body = "{\"hello\":\"world\"}";
     *          sprintf(res, "HTTP/1.1 200 OK\r\n"
     *              "Content-Type: application/json; charset=utf-8\r\n"
     *              "Content-Length: %zu\r\n"
     *              "Connection: keep-alive\r\n\r\n", strlen(body));
     *          out_append(c, res, strlen(res));
     *          out_append(c, body, strlen(body));
     *          free(res);
     *          return;
     *      }
     *
     *  With USE_DATABASE 1 (main.c):
     *      MYSQL *conn = connect_db();          // NULL -> send_500(c)
     *      co_mysql_query(conn, "SELECT ...");  // yields while MySQL works
     *      MYSQL_RES *r = co_mysql_store_result(conn);
     *      ... mysql_fetch_row / mysql_free_result as usual ...
     *      db_release(conn);                    // never mysql_close()
     *
     *  Calling another server (yields while waiting, fresh connection):
     *      Response up = https_request("api.example.com", request_text,
     *                                  HTTP_TIMEOUT_DEFAULT);
     *      ... up.status / up.body / up.body_len ...
     *      free_response(up);
     *
     *  Every response says "Connection: keep-alive"; the engine rewrites
     *  it to "close" by itself when the connection must close.
     * ---------------------------------------------------------------- */

    /* ---- static files, by virtual host --------------------------------
       A request for host H and path P is served from <site root>/H/P
       ("/" -> /index.html) if a folder H exists there and P stays inside
       it (is_file_allowed() rejects ".." and the like). */
    if (!is_known_host(hostname)) {
        sprintf(res, "HTTP/1.1 403 Forbidden\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n"
            "\r\n");
        out_append(c, res, strlen(res));

    } else if (strcmp(req->uri, "/") == 0 || is_file_allowed(workspace, hostname, req->uri)) {
        const char *path = strcmp(req->uri, "/") == 0 ? "/index.html" : req->uri;
        FileInfo file = get_file(hostname, path);

        if (!file.data) {
            sprintf(res, "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n"
                "Connection: keep-alive\r\n"
                "\r\n");
            out_append(c, res, strlen(res));
        } else {
            sprintf(res, "HTTP/1.1 200 OK\r\n"
                "Content-Type: %s; charset=utf-8\r\n"
                "Content-Length: %ld\r\n"
                "Connection: keep-alive\r\n"
                "\r\n", get_mime_type(path), file.size);
            out_append(c, res, strlen(res));
            out_append(c, file.data, file.size);
            free(file.data);
        }

    } else {
        sprintf(res, "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n"
            "\r\n");
        out_append(c, res, strlen(res));
    }

    free(res);
}

/* Helper: trim leading/trailing whitespace in-place, return pointer to trimmed start */
static char *trim_inplace(char *s) {
    if (!s) return NULL;
    /* trim leading */
    while (*s && (*s == ' ' || *s == '\t')) s++;
    /* trim trailing */
    char *end = s + strlen(s) - 1;
    while (end >= s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return s;
}

/* ------------------------------------------------------------------ *
 *  Request header table (req->headers, a NULL-terminated char ***)
 *
 *      headers[i][0] = name, headers[i][1] = value, headers[i][2] = NULL
 *
 *  Names and values point into conn->in, so they live exactly as long
 *  as the request does and must never be freed individually.
 * ------------------------------------------------------------------ */

/* Case-insensitive lookup. Returns the trimmed value, or NULL if the
   header is not present. The returned pointer is owned by the request. */
char * get_header(Request * req, const char * name){
    if (req == NULL || req->headers == NULL || name == NULL) return NULL;

    for (int i = 0; req->headers[i] != NULL; i++) {
        if (req->headers[i][0] == NULL) continue;
        if (strcasecmp(req->headers[i][0], name) == 0)
            return req->headers[i][1];
    }
    return NULL;
}

/* Same as get_header(), but substitutes fallback when the header is
   missing (or its value is NULL) -- handy for printf-style callers. */
char * get_header_default(Request * req, const char * name, char * fallback){
    char * val = get_header(req, name);
    return val != NULL ? val : fallback;
}

/* Frees the rows and the outer array. The strings themselves belong to
   conn->in and are left alone. Safe to call on a NULL table. */
void free_headers(Request * req){
    if (req == NULL || req->headers == NULL) return;

    for (int i = 0; req->headers[i] != NULL; i++)
        free(req->headers[i]);

    free(req->headers);
    req->headers = NULL;
    req->headers_count = 0;
}

#endif /* HANDLERS_C_INCLUDED */
