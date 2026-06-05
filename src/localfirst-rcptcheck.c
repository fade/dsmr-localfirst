/*
 * localfirst-rcptcheck — SMTP-time recipient validator, wired via qmail-smtpd's
 * RCPTCHECK. It replaces chkuser as the sole recipient gate so that system
 * identities on a hybrid domain are accepted (chkuser, being vpopmail-only,
 * rejects them). See SPEC §4.3.
 *
 * qmail-smtpd contract (qmail-smtpd.c): the recipient is passed in the
 * environment as RECIPIENT=local@domain. SENDER/HELO/TCPREMOTEIP/RELAYCLIENT
 * are also in the environment. Exit status drives the SMTP response:
 *     exit 0   -> accept (250)
 *     exit 100 -> reject (550); an optional custom "550 ..." line may be
 *                 written to fd 4 when USE_FD4=1
 *     exit 111 -> temporary failure (451)
 * qmail-smtpd only invokes RCPTCHECK when (!relayclient || rcptcheckrelayclient),
 * so for authenticated submission it DOES run — hence the relay-safety clause
 * below is load-bearing, not cosmetic.
 *
 * Decision logic per recipient:
 *   domain NOT in rcpthosts        -> accept   (relay target; permission was
 *                                               already enforced by AUTH+tcprules)
 *   domain in locals               -> accept if system_identity(local)        (system domain:
 *                                     else reject                              users, qmail
 *                                                                              extension addressing,
 *                                                                              ~alias/.qmail — no
 *                                                                              vpopmail layer here)
 *   domain in localfirstdomains    -> accept if system_identity(local)        (hybrid: system-first)
 *                                     or vpopmail recipient exists             (fallthrough)
 *                                     else reject
 *   other local rcpthosts domain   -> accept if vpopmail recipient exists     (pure vpopmail)
 *                                     else reject
 *
 * The vpopmail existence check shells out to ~vpopmail/bin/vrcptcheck, which is
 * backend-agnostic (works against vpopmail's SQL backends). It is only reached
 * on local domains where the recipient is not a system identity. vrcptcheck
 * cannot itself distinguish "no such user" from "backend down" (both yield its
 * exit 1), so on an absent result we probe the SQL backend's reachability and
 * map a confirmed outage to a temporary failure (defer) — never a permanent
 * reject — and log it loudly for an out-of-band monitor. A vrcptcheck that is
 * not installed at all means there is no vpopmail layer (a system-only host),
 * in which case an unknown local recipient is rejected outright.
 *
 * On accept, control is handed to the next RCPTCHECK program in the chain
 * (rcptcheck-overlimit, the outbound relay throttle) if it is present, so both
 * checks share qmail's single RCPTCHECK slot without either losing its job.
 */
#include "system_identity.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

/* Production paths. Overridable at compile time (-D...) for hermetic tests;
 * never via the environment, so the recipient gate cannot be redirected at
 * run time. */
#ifndef RCPTHOSTS
#define RCPTHOSTS        "/var/qmail/control/rcpthosts"
#endif
/* qmail's locals: domains delivered to system accounts (qmail-send checks this
 * before virtualdomains). A recipient on a locals domain is validated against
 * the system layer alone — there is no vpopmail backend for it. */
#ifndef LOCALS
#define LOCALS           "/var/qmail/control/locals"
#endif
#ifndef LOCALFIRSTDOMAINS
#define LOCALFIRSTDOMAINS "/var/qmail/control/localfirstdomains"
#endif
#ifndef VRCPTCHECK
#define VRCPTCHECK       "/home/vpopmail/bin/vrcptcheck"
#endif
/* The next RCPTCHECK program to run on accept (qmail's RCPTCHECK is a single
 * slot; we chain). Default is vpopmail's outbound relay throttle. */
#ifndef RCPTCHECK_CHAIN
#define RCPTCHECK_CHAIN  "/var/qmail/bin/rcptcheck-overlimit"
#endif
/* vpopmail's SQL backend connection file, read only to extract host+port for a
 * liveness probe (never for credentials). PostgreSQL build; the MySQL build
 * uses vpopmail.mysql with the same SERVER|PORT|... first-field layout. */
#ifndef VPOPMAIL_SQLCONF
#define VPOPMAIL_SQLCONF "/home/vpopmail/etc/vpopmail.pgsql"
#endif
/* Seconds to wait for the backend TCP probe before declaring it unreachable. */
#ifndef BACKEND_PROBE_TIMEOUT
#define BACKEND_PROBE_TIMEOUT 3
#endif

#define RC_ACCEPT 0
#define RC_REJECT 100
#define RC_TEMP   111

/* vpopmail_exists outcomes:
 *   VP_EXISTS   recipient exists in vpopmail            -> accept
 *   VP_ABSENT   backend reachable, recipient unknown     -> reject (550)
 *   VP_TEMP     backend confirmed down / transient error -> defer  (451)
 *   VP_NO_LAYER vrcptcheck not installed (system-only)   -> reject (550) */
typedef enum { VP_EXISTS, VP_ABSENT, VP_TEMP, VP_NO_LAYER } vp_result;

/* Case-insensitive equality for domain names. */
static int domeq(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        ++a; ++b;
    }
    return *a == '\0' && *b == '\0';
}

/* Trim leading/trailing whitespace in place; returns the trimmed start. */
static char *trim(char *s)
{
    char *end;
    while (*s && isspace((unsigned char)*s))
        ++s;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

/* Does `domain` end with the (case-insensitive) suffix `suffix`? */
static int dom_hassuffix(const char *domain, const char *suffix)
{
    size_t dl = strlen(domain), sl = strlen(suffix);
    if (sl == 0 || dl <= sl)
        return 0;
    return domeq(domain + (dl - sl), suffix);
}

/*
 * Is `domain` listed in control file `path` (case-insensitive)? Matches qmail's
 * rcpthosts semantics: an exact entry matches that host; an entry beginning with
 * '.' (e.g. ".example.com") matches any strict subdomain (foo.example.com) but
 * not the bare domain. The leading-dot test requires a label boundary, so
 * ".example.com" never matches "evilexample.com".
 *
 * Not consulted: morercpthosts.cdb. A local domain held only there is missed,
 * which (for rcpthosts) means its recipients hit the relay-accept clause and
 * skip validation — a coverage gap, never a relay-safety breach. Hosts using
 * morercpthosts should also list system-first domains in localfirstdomains.
 */
static int domain_listed(const char *path, const char *domain)
{
    FILE *f = fopen(path, "r");
    char line[512];
    int found = 0;
    if (f == NULL)
        return 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        char *d = trim(line);
        if (d[0] == '\0' || d[0] == '#')
            continue;
        if (domeq(d, domain) || (d[0] == '.' && dom_hassuffix(domain, d))) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

/*
 * Probe whether vpopmail's SQL backend is reachable, used to tell "user does
 * not exist" apart from "backend is down" (vrcptcheck collapses both to exit 1).
 * Reads only host+port from the connection file (field 1 and field 2 of the
 * first non-comment line, '|'-separated) and attempts a bounded TCP connect.
 * Returns 1 = reachable, 0 = confirmed unreachable, -1 = cannot tell.
 * On -1 we do NOT defer: deferral requires positive evidence of an outage, so
 * an unparseable/unreadable config never turns a real "unknown user" into a
 * stuck-forever temp failure.
 */
static int backend_reachable(void)
{
    FILE *f = fopen(VPOPMAIL_SQLCONF, "r");
    char line[1024];
    char host[256], port[32];
    char *p, *bar;
    struct addrinfo hints, *res, *rp;
    int ok = -1;

    if (f == NULL)
        return -1;
    do {
        if (fgets(line, sizeof(line), f) == NULL) { fclose(f); return -1; }
    } while (line[0] == '#' || line[0] == '\n');
    fclose(f);

    /* field 1: host (empty -> localhost) */
    p = line;
    bar = strchr(p, '|');
    if (bar == NULL) return -1;
    if (bar == p || (size_t)(bar - p) >= sizeof(host))
        strcpy(host, "127.0.0.1");
    else { memcpy(host, p, bar - p); host[bar - p] = '\0'; }

    /* field 2: port (empty -> 5432) */
    p = bar + 1;
    bar = strchr(p, '|');
    if (bar == NULL || bar == p || (size_t)(bar - p) >= sizeof(port))
        strcpy(port, "5432");
    else { memcpy(port, p, bar - p); port[bar - p] = '\0'; }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;

    for (rp = res; rp != NULL && ok != 1; rp = rp->ai_next) {
        int s = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
        if (s < 0)
            continue;
        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0) {
            ok = 1;
        } else if (errno == EINPROGRESS) {
            fd_set wfds;
            struct timeval tv;
            int serr = 0;
            socklen_t slen = sizeof(serr);
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            tv.tv_sec = BACKEND_PROBE_TIMEOUT;
            tv.tv_usec = 0;
            if (select(s + 1, NULL, &wfds, NULL, &tv) > 0 &&
                getsockopt(s, SOL_SOCKET, SO_ERROR, &serr, &slen) == 0)
                ok = (serr == 0) ? 1 : 0;
            else
                ok = 0;   /* timed out or select error -> treat as down */
        } else {
            ok = 0;       /* connection refused etc. -> down */
        }
        close(s);
    }
    freeaddrinfo(res);
    return ok;
}

/* Shell out to vrcptcheck: feed "local@domain" on the child's fd 3, read its
 * exit status, and disambiguate "unknown user" from "backend down". */
static vp_result vpopmail_exists(const char *local, const char *domain)
{
    int pfd[2];
    pid_t pid;
    char addr[512];
    int written, status;

    written = snprintf(addr, sizeof(addr), "%s@%s", local, domain);
    if (written < 0 || (size_t)written >= sizeof(addr))
        return VP_ABSENT;

    if (pipe(pfd) != 0)
        return VP_TEMP;

    pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return VP_TEMP;
    }

    if (pid == 0) {
        /* child: wire the read end to fd 3, exec vrcptcheck */
        close(pfd[1]);
        if (pfd[0] != 3) {
            if (dup2(pfd[0], 3) != 3)
                _exit(111);
            close(pfd[0]);
        }
        /* Drop qmail-smtpd's RCPTCHECK error pipe (fd 4): vrcptcheck has no
         * business holding or writing it, and leaving it open would delay the
         * parent smtpd's EOF on that pipe. */
        close(4);
        execl(VRCPTCHECK, "vrcptcheck", (char *)NULL);
        /* Distinguish "not installed" (system-only host: no vpopmail layer)
         * from other exec failures (a real misconfiguration to defer on). */
        _exit(errno == ENOENT ? 127 : 126);
    }

    /* parent: write the address (NO trailing newline — vrcptcheck strtok's on
     * '@' and a newline would corrupt the domain), then close to signal EOF. */
    close(pfd[0]);
    {
        ssize_t n = write(pfd[1], addr, (size_t)written);
        (void)n;   /* a short/failed write surfaces as vrcptcheck temp/absent */
    }
    close(pfd[1]);

    if (waitpid(pid, &status, 0) != pid)
        return VP_TEMP;
    if (!WIFEXITED(status))
        return VP_TEMP;

    switch (WEXITSTATUS(status)) {
    case 0:
        return VP_EXISTS;
    case 1:
        /* Unknown user OR backend down — vrcptcheck cannot tell them apart.
         * Probe the backend: only a confirmed outage defers (and is logged
         * loudly for an out-of-band monitor); otherwise it is a real reject. */
        if (backend_reachable() == 0) {
            syslog(LOG_MAIL | LOG_CRIT,
                   "localfirst-rcptcheck: vpopmail SQL backend UNREACHABLE; "
                   "DEFERRING <%s@%s> (451). Recipient validation is degraded.",
                   local, domain);
            fprintf(stderr, "localfirst-rcptcheck: CRITICAL: vpopmail backend "
                            "unreachable; deferring <%s@%s>\n", local, domain);
            return VP_TEMP;
        }
        return VP_ABSENT;
    case 127:
        return VP_NO_LAYER;   /* vrcptcheck not installed: system-only host */
    default:
        return VP_TEMP;       /* 126 / 111 / unexpected: misconfig, defer */
    }
}

/* Emit a custom SMTP response line on fd 4 when qmail-smtpd asked for it. */
static void emit_fd4(const char *line)
{
    const char *use = getenv("USE_FD4");
    if (use == NULL || strcmp(use, "1") != 0)
        return;
    {
        ssize_t n = write(4, line, strlen(line));
        (void)n;
    }
}

static int reject(void)
{
    emit_fd4("550 5.1.1 sorry, no mailbox here by that name");
    return RC_REJECT;
}

/*
 * Accept the recipient, but first hand off to the next RCPTCHECK program in the
 * chain (the outbound relay throttle) if it is installed — it produces the
 * final verdict. qmail's RCPTCHECK is a single slot, so chaining is done by
 * exec. The full environment (RECIPIENT, SENDER, RELAYCLIENT, RCPTHOSTS,
 * SMTPAUTHUSER, TCPREMOTEIP) is inherited, which is all the throttle needs.
 * If the chain program is absent or exec fails, this is a plain accept — a
 * chaining problem must not fail an otherwise-valid recipient.
 */
static int accept_rcpt(void)
{
    if (access(RCPTCHECK_CHAIN, X_OK) == 0) {
        char *args[] = { (char *)RCPTCHECK_CHAIN, (char *)NULL };
        execv(RCPTCHECK_CHAIN, args);
    }
    return RC_ACCEPT;
}

int main(void)
{
    const char *recipient = getenv("RECIPIENT");
    char buf[512];
    char *at, *local, *domain;

    openlog("localfirst-rcptcheck", LOG_PID, LOG_MAIL);

    if (recipient == NULL || recipient[0] == '\0') {
        fprintf(stderr, "localfirst-rcptcheck: RECIPIENT not set\n");
        return RC_TEMP;
    }
    if (strlen(recipient) + 1 > sizeof(buf)) {
        fprintf(stderr, "localfirst-rcptcheck: RECIPIENT too long\n");
        return RC_TEMP;
    }
    strcpy(buf, recipient);

    /* Split on the last '@' — the domain is everything after it. */
    at = strrchr(buf, '@');
    if (at == NULL || at == buf || at[1] == '\0') {
        /* No domain part: not a recipient we can validate locally. Accept and
         * let qmail-send make the final disposition. */
        return accept_rcpt();
    }
    *at = '\0';
    local = buf;
    domain = at + 1;

    /* Relay safety: a recipient whose domain is not one of ours must never be
     * rejected here — an authenticated submitter is entitled to relay anywhere. */
    if (!domain_listed(RCPTHOSTS, domain))
        return accept_rcpt();

    /* The domain is local. A local-part containing '@' (e.g. a quoted-string
     * "a@b"@dom whose quotes qmail-smtpd already stripped) cannot name a system
     * account and would be mis-split by vrcptcheck (which parses on the FIRST
     * '@'), so the gate would validate a different pair than it authorizes.
     * Reject rather than validate an address we cannot faithfully represent.
     * This runs only for local domains, so relay targets are unaffected. */
    if (strchr(local, '@') != NULL)
        return reject();

    /* A locals domain is delivered to system accounts only (qmail-send resolves
     * it through users/assign, never vpopmail). Validate it against the system
     * layer exactly as qmail would deliver it — real users, qmail extension
     * addressing, and ~alias/.qmail aliases — and reject only what qmail-local
     * would bounce. There is no vpopmail fallthrough for a locals domain. */
    if (domain_listed(LOCALS, domain)) {
        if (system_identity(local, domain) != SI_NONE)
            return accept_rcpt();
        return reject();
    }

    if (domain_listed(LOCALFIRSTDOMAINS, domain)) {
        /* hybrid domain: system-first, then vpopmail fallthrough */
        if (system_identity(local, domain) != SI_NONE)
            return accept_rcpt();
    }
    /* For a hybrid domain that was not a system identity, and for any other
     * local rcpthosts domain, fall through to the vpopmail existence check. */
    switch (vpopmail_exists(local, domain)) {
    case VP_EXISTS:   return accept_rcpt();
    case VP_TEMP:     return RC_TEMP;   /* backend down: defer (already logged) */
    case VP_NO_LAYER:                   /* system-only host: unknown -> reject */
    case VP_ABSENT:
    default:          return reject();
    }
}
