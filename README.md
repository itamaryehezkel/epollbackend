# EPOLL_VANILLA

A generic HTTPS/HTTP server in C to start new projects from. Out of the
box it serves static sites by virtual host; your own routes go into one
function (`handle_request()` in handlers.c). The engine underneath is
built for very large numbers of connections and never blocks on anything a
route does — see `TUNING.md` for how it scales and `HANDLER_README.c` for
the API a route can use.

## Files

| file | role | edit? |
|---|---|---|
| `main.c` | configuration (`USE_DATABASE`, `BIND_ADDR`, `DOMAIN`, `DB_*`, ports, tuning constants), startup, argument parsing, general helpers (`get_file`, mime types, `https_request` / `http_request`, TLS context) | the config block at the top |
| `handlers.c` | HTTP parsing, the `Request` API, **`handle_request()` — your routes**, the :80 redirect | yes, this is where routes go |
| `epoll_helpers.c` | the engine: listeners, connection state machine, workers, coroutines, helper threads, MySQL pool | no |
| `os_tune.c` | kernel settings checked and applied live at startup | no |
| `cJSON.c` / `cJSON.h` | JSON library (see `JSON_README.c`) | no |
| `compile` | build script: `./compile` → `./server`, `./compile debug` → `./server_debug` (ASan/UBSan) | no |
| `HANDLER_README.c` | what a route may call, and the rules | read |
| `TUNING.md` | capacity model, OS settings, systemd unit | read |

Everything except `cJSON.c` is textually `#include`d by `main.c`; only
`main.c cJSON.c` are on the gcc line.

## Build

Needs gcc, `libssl-dev` (OpenSSL 3) and the MySQL client dev package
(`libmysqlclient-dev` or `libmariadb-dev`, providing `mysql_config`). The
MySQL client is linked even when the database is switched off.

```
./compile
```

## Configure (top of main.c)

```c
#define USE_DATABASE 0            // 1 = open a MySQL pool at startup
#define PORT 443
#define HTTP_PORT 80
#define BIND_ADDR "0.0.0.0"       // -b overrides
#define DOMAIN "example.com"      // -d overrides: fallback virtual host
#define DB_HOST     "localhost"   // only with USE_DATABASE 1
#define DB_USERNAME "dbuser"
#define DB_PASSWORD "dbpassword"
#define DB_SCHEMA   "dbname"
```

## Site layout

The site root is the folder **above** the binary by default (`-r` overrides).
Inside it, one folder per virtual host, named exactly like the `Host`
header the browser sends:

```
site-root/
├── EPOLL_VANILLA/          this folder (the binary lives here)
│   └── certs/
│       ├── fullchain.pem   your certificate chain
│       └── privkey.pem     its private key
├── example.com/
│   └── index.html          https://example.com/      -> this file
└── www.example.com/
    └── ...
```

A request for `Host: H` and path `P` is served from `site-root/H/P`
(`/` means `/index.html`); hosts without a folder get 403, missing files
404, and paths that try to leave the folder are refused. Plain HTTP on
:80 redirects to the HTTPS site.

Certificates: `certs/fullchain.pem` + `certs/privkey.pem` next to the
binary (or in the nearest parent, or `-c <dir>`). Additional chains as
`fullchain.pem.<tag>` + `privkey.pem.<tag>` — e.g. one RSA and one ECDSA —
are served side by side. For a local test, any self-signed pair works.

## Run

```
sudo ./server                       # defaults: 0.0.0.0:443 / :80, root = parent folder
./server -h                         # every flag
./server -b 127.0.0.1 -p 8443 -P 8080 -r /srv/sites -d example.com
```

Run as root in production: that is what lets `os_tune.c` raise the kernel
limits (and bind :443). Not root, it still runs with whatever limits it
has and prints what it could not change.

The startup screen shows the tuning table, then the sizing: workers,
helpers, database on/off, the connection cap and what bounds it. Ctrl‑C /
SIGTERM prints a per-worker report.

## Adding a route

Open `handle_request()` in handlers.c; the comment block at its top shows
the pattern. A route parses `req`, builds a response and calls
`out_append()`. If it has to wait for anything — another server
(`https_request()` / `http_request()`), the database (`co_mysql_query()`
/ `co_mysql_store_result()`), a pause (`co_sleep_ms()`), any other
blocking call (`co_offload()`) — it uses those calls and nothing else to
wait, and the server keeps serving everyone else meanwhile.

With `USE_DATABASE 1`: `MYSQL *conn = connect_db();` … `db_release(conn);`
— never `mysql_close()` a pooled connection.
