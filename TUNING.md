# EPOLL_VANILLA — how it scales, and what the OS needs

The server sizes itself from the machine at startup, checks the kernel
settings it needs and (as root) applies them live for this boot, and
prints all of it. This file explains the model and the few things that
stay outside the binary.

## The model

| what | count (default) | does | blocks? |
|---|---|---|---|
| epoll worker (`-w`) | one per hardware thread | accept, TLS, HTTP framing, socket I/O, timers, **and the routes** | never |
| route coroutine | one per request in flight | `handle_request()` as plain sequential code | yields instead |
| helper thread | one per MySQL connection + 4 (follows `-D`, 16..512; 16 with `USE_DATABASE 0`), nice +5 | runs a MySQL query or a DNS lookup for a route while it waits | yes, for the query's duration |
| MySQL connection (`-D`) | 256, clamped to `max_connections - 10`; none with `USE_DATABASE 0` | pooled; `connect_db()` / `db_release()` | — |

Every route runs as a coroutine on the worker that owns the client's
socket. When it waits — an upstream call, a query, a DNS lookup — it yields:
the worker serves its other connections and resumes the route when the
wait is over. A route that waits costs one stack (256 KB of virtual
memory, a few pages resident) and nothing else: no thread, no CPU. So
the number of slow requests in flight is bounded by memory and by the
connection cap, not by a thread count.

MySQL connections (with `USE_DATABASE 1`) are held from `connect_db()` to
`db_release()`. Give one back before a long upstream call and take a
fresh one after it, so a connection is held for the milliseconds of the
queries, never for the seconds of the call; otherwise the number of
requests mid-call at once is bounded by the pool, not by memory. `times a
route waited for a free connection` in the shutdown report is normal
under load as long as the waits are short; sustained waits mean raise
`-D` (and MySQL's `max_connections`). Helper threads are sized from the
pool — one per connection, so every connection can be mid-query at once
— and are never the limit; they are not a knob. They run at nice +5,
below the workers, so under CPU saturation the event loops (TLS,
parsing, routes) are scheduled first; a parked helper costs no CPU at
all. With MySQL on the same machine, MariaDB's own threads are what share
the cores with the workers.

Upstream calls: `https_request()` / `http_request()` open a fresh
connection per call (by design, no pooling), with `HTTP_TIMEOUT_DEFAULT`
(60 s) for the whole exchange — set it to about three times your slowest
upstream so only a stuck call is cut. Every outbound call leaves a
TIME_WAIT on this machine; os_tune widens the ephemeral port range to
~64k and enables `tcp_tw_reuse`, which lets those ports be reused after
one second, so outbound calls are not port-bound at any rate this server
can reach.

Clients get HTTP/1.1 keep-alive: routes write `Connection: keep-alive`
and the engine rewrites it to `close` when it must close (client asked,
HTTP/1.0, no Content-Length, limits). `-k` sets the idle timeout.

## Connections

`connections:` in the banner is the smallest of

* memory: 75% of `MemAvailable` at startup, ~24 KB per connection
  (nothing is allocated up front; this is a ceiling);
* file descriptors after os_tune raised the limits;
* `-m` if given.

The same 75% budget is written to `net.ipv4.tcp_mem`, so the kernel's
own socket memory is capped at it too.

## What os_tune.c does at startup (needs root)

It reads each setting from `/proc/sys`, compares with what this server
size needs, and writes the new value where it differs — the same thing
`sysctl -w` does, and just as non-persistent: a reboot restores the
distribution defaults and the next start applies them again. Nothing is
written under `/etc`. Not root: it reports the differences and the
server starts with what it has.

What it sets: `fs.nr_open`, `fs.file-max`, `RLIMIT_NOFILE`,
`vm.max_map_count` (two mappings per route in flight),
`net.ipv4.tcp_mem` (the RAM cap), `tcp_rmem`/`tcp_wmem` (small idle
buffers), `net.core.somaxconn`, `tcp_max_syn_backlog`,
`netdev_max_backlog`, `tcp_syncookies`, `tcp_max_tw_buckets`,
`tcp_tw_reuse`, `ip_local_port_range`, `tcp_fin_timeout`,
`tcp_slow_start_after_idle`, `tcp_fastopen`, `nf_conntrack_max` (if
the firewall tracks connections), and `modprobe tls` for kTLS.

## systemd unit — the only thing outside the binary

```ini
[Unit]
Description=EPOLL_VANILLA server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/path/to/EPOLL_VANILLA/server
User=root
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target


OR

Description=ITL HTTPS multithreaded server
Documentation=file:/home/user/BACKEND_EPOLL/Backend_epoll/README.md

# Order of operations: wait for dependencies to be up before initializing
After=network-online.target mysql.service

# Strict demand: refuse to boot if network or mysql fail to start
Requires=network-online.target mysql.service

# Lifecycle locking: kill this server instantly if network drops or mysql dies
BindsTo=network-online.target mysql.service

# Crash-loop protection: if it crashes 5 times in 5 mins, slow down but keep attempting via Restart
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'LOG="/home/user/BACKEND_EPOLL/Backend_epoll/output.log"; if [ -f "$LOG" ] && [ $(stat -c%%s "$LOG") -gt 536870912 ]; then tail -c 536870912 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; fi'
WorkingDirectory=/home/user/BACKEND_EPOLL/Backend_epoll/
ExecStart=/home/user/BACKEND_EPOLL/Backend_epoll/itl_server_epoll
User=root

# Uptime Management: auto-restart on crashes or when dependencies recover
Restart=always
RestartSec=1s

# Performance limits (High-concurrency epoll socket pool)
LimitNOFILE=10048576

# Security Hardening
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=yes
ProtectSystem=full

# Native systemd logging
StandardOutput=append:/home/user/BACKEND_EPOLL/Backend_epoll/output.log
StandardError=append:/home/user/BACKEND_EPOLL/Backend_epoll/output.log

[Install]
WantedBy=multi-user.target
```

`User=root` is what lets os_tune apply the settings (and the server bind
:443). `LimitNOFILE=` is belt and braces: os_tune raises the limit itself
when root.

## MySQL

* Only with `USE_DATABASE 1`. `max_connections` ≥ `-D` + what other
  clients need; the pool clamps itself at startup to `max_connections`
  minus 10% (at least 10).
* `wait_timeout` may stay at its default: a dropped connection is
  detected and reopened on the next request.
* MySQL ≥ 5.7 or MariaDB ≥ 10.2 for `COM_RESET_CONNECTION`; older
  servers fall back to `mysql_ping()` automatically.

## Millions of connections

Descriptors belong to the process and are shared by all threads; the
thread count has nothing to do with it. With the limits os_tune sets, one
process can hold a million sockets and epoll handles that many idle
connections. Budget 10–20 GB of RAM per million (kernel socket state
plus this server's idle TLS state). The 64K-ports limit is per *client*
address towards one server address:port; different clients have
different addresses, and a server port is shared by all of them. Only
many clients behind one NAT address hit it, and the fix is on their side
(more public addresses) or more server addresses/ports to spread over.
A NAT or VPN device in front of the server is the first thing to hit its
connection-tracking limit.

## Reading the shutdown report

```
worker  0: accepted 2930 (61.0%) requests 2930 peak open 21 refused 0 upstream timeouts 0
helpers: 16 threads, 800 calls run, peak queue 5
```

`accepted` is spread by which worker was idle when each connection
arrived; uneven percentages are normal. `upstream timeouts` counts waits
that hit their deadline (upstream/DB too slow). `times a route waited` > 0
means a bigger pool. `refused`
> 0 means the connection cap was hit.
