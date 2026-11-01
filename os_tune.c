/* ====================================================================
 *  os_tune.c -- the kernel settings a server of this size needs
 *
 *  Called once, from main(), before the listeners are made. Reads what
 *  the running kernel has, works out what this process needs from the
 *  hardware scan (RAM budget, wanted connections, thread counts), and
 *  where they differ writes the new value straight into /proc/sys --
 *  exactly what `sysctl -w` does, and just as non-persistent: a reboot
 *  brings the distribution's defaults back and the next start applies
 *  them again. Nothing is written under /etc. Besides this, the only
 *  deployment artefact is the systemd unit.
 *
 *  Writing /proc/sys needs root (the binary binds :443 anyway). Not
 *  root: every difference is reported, nothing is changed, the server
 *  starts with what it has and the connection cap reflects that.
 *
 *  Textually included by main.c like the other parts (not on the gcc
 *  line). Ubuntu Server is the target; paths are the stock ones.
 *
 *  What is tuned and why (os_tune_apply has the numbers):
 *
 *   memory      net.ipv4.tcp_mem  -- the RAM cap. TCP's system-wide
 *               socket-buffer budget is set from the 75% of MemAvailable
 *               that main() worked out: past "pressure" the kernel
 *               shrinks buffers, at "high" it refuses more. This is what
 *               keeps a flood from eating the machine.
 *               tcp_rmem/tcp_wmem -- small default per-socket buffers so
 *               an idle connection costs little; autotuning grows them
 *               for connections that actually move data.
 *   descriptors fs.nr_open, fs.file-max, RLIMIT_NOFILE -- one fd per
 *               connection, plus the pools. The hard limit is raised to
 *               nr_open; this is also what LimitNOFILE= would do.
 *   stacks      vm.max_map_count -- every route in flight has its own
 *               stack (2 mappings each: guard page + stack); the default
 *               65530 would stop the server at ~30k routes in flight.
 *   queues      net.core.somaxconn, tcp_max_syn_backlog,
 *               netdev_max_backlog -- how many connections may wait in
 *               the kernel for accept() during a burst.
 *   churn       tcp_max_tw_buckets, tcp_fin_timeout, tcp_tw_reuse,
 *               ip_local_port_range -- every upstream call is a fresh
 *               outbound connection (by design) and leaves a TIME_WAIT;
 *               these keep that from exhausting ports or memory.
 *   latency     tcp_slow_start_after_idle=0 (keep-alive connections
 *               keep their window), tcp_fastopen=3.
 *   firewall    nf_conntrack_max -- only if the conntrack module is
 *               loaded; a stateful firewall tracks every connection.
 *   kTLS        modprobe tls -- record encryption in the kernel.
 * ==================================================================== */
#ifndef OS_TUNE_C_INCLUDED
#define OS_TUNE_C_INCLUDED

#include <sys/wait.h>

static int ot_root;
static int ot_changed, ot_failed;

static int ot_read(const char *path, char *buf, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, (int)n, f)) { fclose(f); return -1; }
    fclose(f);
    size_t l = strlen(buf);
    while (l && (buf[l-1] == '\n' || buf[l-1] == ' ' || buf[l-1] == '\t')) buf[--l] = '\0';
    return 0;
}

static int ot_write(const char *path, const char *val) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    int ok = fprintf(f, "%s\n", val) > 0;
    if (fclose(f) != 0) ok = 0;
    return ok ? 0 : -1;
}

static void ot_line(const char *name, const char *have, const char *want, const char *verdict) {
    fprintf(stdout, "  %-34s %-28s %-24s %s\n", name, have, want, verdict);
}

/* Set `path` to `want` if it is lower (or, with exact=1, different). */
static void ot_tune(const char *path, const char *name, const char *want, long want_num, int exact) {
    char have[128];
    if (ot_read(path, have, sizeof(have)) < 0) {
        ot_line(name, "(absent)", want, "skipped: not on this kernel");
        return;
    }
    int differs = exact ? strcmp(have, want) != 0 : atol(have) < want_num;
    if (!differs) { ot_line(name, have, want, "ok"); return; }
    if (!ot_root) { ot_line(name, have, want, "NOT ROOT: cannot change"); ot_failed++; return; }
    if (ot_write(path, want) == 0) {
        ot_line(name, have, want, "-> set");
        ot_changed++;
    } else {
        char why[96];
        snprintf(why, sizeof(why), "FAILED: %s", strerror(errno));
        ot_line(name, have, want, why);
        ot_failed++;
    }
}

static void ot_tune_num(const char *path, const char *name, long want) {
    char w[32];
    snprintf(w, sizeof(w), "%ld", want);
    ot_tune(path, name, w, want, 0);
}

static void ot_tune_str(const char *path, const char *name, const char *want) {
    ot_tune(path, name, want, 0, 1);
}

/* kTLS: the tls module. Loaded with the stock modprobe; not persisted. */
static void ot_ktls(void) {
    char buf[256];
    FILE *f = fopen("/proc/modules", "r");
    int loaded = 0;
    if (f) {
        while (fgets(buf, sizeof(buf), f))
            if (!strncmp(buf, "tls ", 4)) { loaded = 1; break; }
        fclose(f);
    }
    if (loaded) { ot_line("kernel module tls (kTLS)", "loaded", "loaded", "ok"); return; }
    if (!ot_root) { ot_line("kernel module tls (kTLS)", "not loaded", "loaded", "NOT ROOT: cannot modprobe"); ot_failed++; return; }
    pid_t pid = fork();
    if (pid == 0) {
        execl("/sbin/modprobe", "modprobe", "tls", (char *)NULL);
        _exit(127);
    }
    int st = -1;
    if (pid > 0) waitpid(pid, &st, 0);
    if (pid > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        ot_line("kernel module tls (kTLS)", "not loaded", "loaded", "-> modprobe tls");
        ot_changed++;
    } else {
        ot_line("kernel module tls (kTLS)", "not loaded", "loaded", "FAILED: modprobe tls");
        ot_failed++;
    }
}

static void os_tune_apply(os_tune_t *t) {
    ot_root = (geteuid() == 0);
    ot_changed = ot_failed = 0;
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;

    fprintf(stdout, "\e[0;93mos tuning\e[0m (%s; live for this boot only, nothing persisted)\n",
            ot_root ? "root: applying" : "not root: checking only");
    ot_line("setting", "current", "wanted", "result");

    /* ---- descriptors: one per connection, plus the pools ------------- */
    long fds_wanted = t->want_conns + 4L * t->workers + 2L * t->helpers + t->db_conns + 1024;
    if (fds_wanted < 1048576) fds_wanted = 1048576;         /* the usual floor */
    if (fds_wanted > 100000000) fds_wanted = 100000000;
    ot_tune_num("/proc/sys/fs/nr_open",   "fs.nr_open",   fds_wanted);
    ot_tune_num("/proc/sys/fs/file-max",  "fs.file-max",  fds_wanted);

    {
        char have[64], want[64];
        struct rlimit rl;
        long nr_open = 0;
        if (ot_read("/proc/sys/fs/nr_open", have, sizeof(have)) == 0) nr_open = atol(have);
        getrlimit(RLIMIT_NOFILE, &rl);
        rlim_t target = (rlim_t)(nr_open > 0 && nr_open < fds_wanted ? nr_open : fds_wanted);
        snprintf(have, sizeof(have), "%lu / %lu", (unsigned long)rl.rlim_cur, (unsigned long)rl.rlim_max);
        snprintf(want, sizeof(want), "%lu", (unsigned long)target);
        if (rl.rlim_cur >= target) {
            ot_line("RLIMIT_NOFILE (soft / hard)", have, want, "ok");
        } else {
            struct rlimit nw = { target, target };
            if (!ot_root && target > rl.rlim_max) { nw.rlim_cur = rl.rlim_max; nw.rlim_max = rl.rlim_max; }
            if (setrlimit(RLIMIT_NOFILE, &nw) == 0) {
                ot_line("RLIMIT_NOFILE (soft / hard)", have, want,
                        nw.rlim_cur >= target ? "-> set" : "-> raised to the hard limit only (not root)");
                if (nw.rlim_cur >= target) ot_changed++; else ot_failed++;
            } else {
                { char why[96]; snprintf(why, sizeof(why), "FAILED: setrlimit: %s", strerror(errno)); ot_line("RLIMIT_NOFILE (soft / hard)", have, want, why); }
                ot_failed++;
            }
        }
        getrlimit(RLIMIT_NOFILE, &rl);
        t->fd_limit = (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur > 100000000) ? 100000000 : (long)rl.rlim_cur;
    }

    /* ---- coroutine stacks: 2 mappings per route in flight ------------- */
    ot_tune_num("/proc/sys/vm/max_map_count", "vm.max_map_count", 2L * t->want_conns + 65536);

    /* ---- the RAM cap: TCP's socket-buffer budget ----------------------- */
    if (t->mem_budget_kb > 0) {
        long high = t->mem_budget_kb * 1024 / page;
        char want[96];
        snprintf(want, sizeof(want), "%ld\t%ld\t%ld", high / 2, high * 3 / 4, high);
        /* /proc shows the triple tab-separated; compare field by field */
        char have[128];
        int same = 0;
        if (ot_read("/proc/sys/net/ipv4/tcp_mem", have, sizeof(have)) == 0) {
            long a = 0, b = 0, c = 0;
            sscanf(have, "%ld %ld %ld", &a, &b, &c);
            same = (a == high / 2 && b == high * 3 / 4 && c == high);
        }
        if (same) ot_line("net.ipv4.tcp_mem (pages)", have, want, "ok");
        else      ot_tune_str("/proc/sys/net/ipv4/tcp_mem", "net.ipv4.tcp_mem (pages)", want);
    }
    ot_tune_str("/proc/sys/net/ipv4/tcp_rmem", "net.ipv4.tcp_rmem", "4096\t16384\t4194304");
    ot_tune_str("/proc/sys/net/ipv4/tcp_wmem", "net.ipv4.tcp_wmem", "4096\t16384\t4194304");

    /* ---- accept and packet queues -------------------------------------- */
    ot_tune_num("/proc/sys/net/core/somaxconn",            "net.core.somaxconn",            65535);
    ot_tune_num("/proc/sys/net/ipv4/tcp_max_syn_backlog",  "net.ipv4.tcp_max_syn_backlog",  65535);
    ot_tune_num("/proc/sys/net/core/netdev_max_backlog",   "net.core.netdev_max_backlog",   65536);
    ot_tune_num("/proc/sys/net/ipv4/tcp_syncookies",       "net.ipv4.tcp_syncookies",       1);

    /* ---- connection churn (fresh outbound connection per upstream call) --- */
    {
        long tw = t->want_conns > 1048576 ? t->want_conns : 1048576;
        ot_tune_num("/proc/sys/net/ipv4/tcp_max_tw_buckets", "net.ipv4.tcp_max_tw_buckets", tw);
    }
    ot_tune_num("/proc/sys/net/ipv4/tcp_tw_reuse",         "net.ipv4.tcp_tw_reuse",         1);
    ot_tune_str("/proc/sys/net/ipv4/ip_local_port_range",  "net.ipv4.ip_local_port_range",  "1024\t65535");
    {
        char have[64];
        if (ot_read("/proc/sys/net/ipv4/tcp_fin_timeout", have, sizeof(have)) == 0 && atol(have) <= 15)
            ot_line("net.ipv4.tcp_fin_timeout", have, "15", "ok");
        else
            ot_tune_str("/proc/sys/net/ipv4/tcp_fin_timeout", "net.ipv4.tcp_fin_timeout", "15");
    }

    /* ---- latency ------------------------------------------------------- */
    ot_tune_str("/proc/sys/net/ipv4/tcp_slow_start_after_idle", "net.ipv4.tcp_slow_start_after_idle", "0");
    ot_tune_num("/proc/sys/net/ipv4/tcp_fastopen",         "net.ipv4.tcp_fastopen",         3);

    /* ---- stateful firewall, if present --------------------------------- */
    if (access("/proc/sys/net/netfilter/nf_conntrack_max", F_OK) == 0)
        ot_tune_num("/proc/sys/net/netfilter/nf_conntrack_max", "net.netfilter.nf_conntrack_max", 2L * t->want_conns + 65536);
    else
        ot_line("net.netfilter.nf_conntrack_max", "(no conntrack)", "-", "skipped: firewall not tracking");

    /* ---- kTLS ---------------------------------------------------------- */
    ot_ktls();

    /* what the listeners will actually get */
    char buf[64];
    t->somaxconn   = ot_read("/proc/sys/net/core/somaxconn", buf, sizeof(buf)) == 0 ? atol(buf) : -1;
    t->syn_backlog = ot_read("/proc/sys/net/ipv4/tcp_max_syn_backlog", buf, sizeof(buf)) == 0 ? atol(buf) : -1;
    t->is_root = ot_root;
    t->changed = ot_changed;
    t->failed  = ot_failed;

    fprintf(stdout, "  %d changed, %d could not be changed%s\n", ot_changed, ot_failed,
            (!ot_root && ot_failed) ? " -- run as root (the systemd unit does) to apply them" : "");
}

#endif /* OS_TUNE_C_INCLUDED */
