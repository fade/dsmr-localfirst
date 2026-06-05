#include "system_identity.h"

#include <ctype.h>
#include <pwd.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

/* Homes under this prefix denote real human/shell accounts. Service accounts
 * (bin, daemon, www-data, …) live elsewhere and are deliberately excluded, so
 * a virtual recipient that merely collides with a service login is NOT treated
 * as a system identity. The alias user's home (/var/lib/qmail/alias) is also
 * outside /home/, so it is reachable only via clause 2. */
#define HOME_PREFIX "/home/"

/* qmail-getpw caps a candidate user name at GETPW_USERLEN (qmail-getpw.c); a
 * dash-prefix at least this long is never tried as a login, so we skip it too
 * to stay bug-for-bug compatible with qmail's address resolution. */
#define USERLEN_MAX 32

int si_qmail_ext(const char *localpart, char *out, size_t n)
{
    size_t i;
    size_t len = strlen(localpart);

    if (len + 1 > n)
        return -1;

    for (i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)localpart[i];
        if (c == '.')
            c = ':';
        else
            c = (unsigned char)tolower(c);
        out[i] = (char)c;
    }
    out[len] = '\0';
    return 0;
}

/* A local-part is only ever a single address component here. Reject anything
 * that could escape into a path, confuse downstream address splitting, or is
 * empty — defence in depth for the dot-qmail filename construction and the
 * getpwnam lookups. '@' is rejected because a local-part containing it cannot
 * name a system account and would be mis-split by tools that parse on the
 * first '@'. */
static int localpart_sane(const char *localpart)
{
    if (localpart == NULL || localpart[0] == '\0')
        return 0;
    if (strchr(localpart, '/') != NULL)
        return 0;
    if (strchr(localpart, '@') != NULL)
        return 0;
    if (strcmp(localpart, ".") == 0 || strcmp(localpart, "..") == 0)
        return 0;
    return 1;
}

static int home_under_home(const char *dir)
{
    return dir != NULL && strncmp(dir, HOME_PREFIX, sizeof(HOME_PREFIX) - 1) == 0;
}

static int is_regular_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/*
 * Would qmail-local deliver (rather than bounce) a recipient whose controlling
 * user has home `homedir` and qmail extension `ext`? This reproduces
 * qmail-local's qmesearch (qmail-local.c): for a non-empty extension it looks
 * for `.qmail-<safeext>` and then the `.qmail-…default` catch-all chain at each
 * '-' boundary down to `.qmail-default`. A regular file at any of those paths
 * means delivery; if none exists qmail-local bounces "no mailbox here by that
 * name" (qmail-local.c:616-618 — only when there is an extension). An empty
 * extension (a bare user) always delivers via the default delivery instruction,
 * so it returns 1 unconditionally.
 *
 * `ext` is the RAW extension (the local-part after the user's '-'); the
 * dash-to-colon/lowercase translation to qmail's safeext form is applied here.
 */
/*
 * Core of si_qmail_deliverable that also reports WHICH .qmail file made the
 * recipient deliverable — the file qmail-local would actually read/run. When
 * `match` is non-NULL it receives that path (capacity `mn`); it is set to "" for
 * the two deliverable-without-a-file cases (a bare extension, and the fail-open
 * unsearchable-home case) so a caller can tell "a real catch-all matched" from
 * "deliverable by default". si_qmail_deliverable is the path-less wrapper.
 */
static int qmail_deliverable_match(const char *homedir, const char *ext,
                                   char *match, size_t mn)
{
    char safeext[256];
    char path[1024];
    size_t sl;
    size_t i;
    int n;

    if (match != NULL && mn > 0)
        match[0] = '\0';

    if (ext == NULL || ext[0] == '\0')
        return 1;   /* bare address: default delivery, always deliverable */

    /* Fail open when the controlling user's home cannot be searched. The
     * validator runs as the smtpd user (vpopmail), which cannot traverse a
     * mode-700 private home (Debian's useradd default), so it cannot read the
     * user's .qmail files to judge an extension. The user exists; qmail-local
     * runs AS that user at delivery and will deliver or bounce. Accepting defers
     * that decision rather than false-rejecting a legitimate tagged address —
     * the same fail-open-on-uncertainty stance the validator takes for a
     * vpopmail backend it cannot reach. */
    if (access(homedir, X_OK) != 0)
        return 1;

    if (si_qmail_ext(ext, safeext, sizeof(safeext)) != 0)
        return 0;   /* extension too long to represent — treat as undeliverable */
    sl = strlen(safeext);

    /* Exact dot-qmail file: .qmail-<safeext> */
    n = snprintf(path, sizeof(path), "%s/.qmail-%s", homedir, safeext);
    if (n > 0 && (size_t)n < sizeof(path) && is_regular_file(path)) {
        if (match != NULL && mn > 0)
            snprintf(match, mn, "%s", path);
        return 1;
    }

    /* Catch-all chain: .qmail-<prefix>default at each '-' boundary in safeext
     * (and at the start), ending with .qmail-default. Matches qmesearch's
     * progressively-shorter -default search exactly. */
    for (i = sl; ; --i) {
        if (i == 0 || safeext[i - 1] == '-') {
            n = snprintf(path, sizeof(path), "%s/.qmail-%.*sdefault",
                         homedir, (int)i, safeext);
            if (n > 0 && (size_t)n < sizeof(path) && is_regular_file(path)) {
                if (match != NULL && mn > 0)
                    snprintf(match, mn, "%s", path);
                return 1;
            }
        }
        if (i == 0)
            break;
    }
    return 0;
}

int si_qmail_deliverable(const char *homedir, const char *ext)
{
    return qmail_deliverable_match(homedir, ext, NULL, 0);
}

/* --- fastforward catch-all awareness (clause 2) ------------------------------
 *
 * On a host whose ~alias/.qmail-default is `| fastforward <cdb>`, the catch-all
 * is NOT deliver-everything: fastforward bounces any recipient absent from <cdb>
 * (fastforward(1), default -P). A faithful RCPT gate must therefore reproduce
 * fastforward's own found/not-found verdict instead of accepting on the mere
 * existence of .qmail-default — otherwise unknown system recipients are accepted
 * at SMTP time and bounced later, generating backscatter. These helpers read the
 * fastforward cdb directly (printforward is not relied on): a constant database
 * is trivially probed and we only need a membership test, not the forward value.
 */

/* djb cdb hash: h = ((h << 5) + h) ^ c, seeded at 5381, modulo 2^32. */
static uint32_t cdb_hash(const unsigned char *buf, uint32_t len)
{
    uint32_t h = 5381;
    uint32_t i;
    for (i = 0; i < len; ++i)
        h = ((h << 5) + h) ^ (uint32_t)buf[i];
    return h;
}

/* Read a 4-byte little-endian unsigned int (cdb's on-disk integer format). */
static uint32_t cdb_u32(const unsigned char *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/*
 * Look up `key` (klen bytes) in the djb constant database at `path`.
 * Returns 1 if present, 0 if absent, -1 on any open/seek/read error so the
 * caller can fail open rather than false-reject on a transient I/O problem.
 *
 * cdb layout: a 2048-byte header of 256 (position,length) hash-table pointers,
 * then the records (klen,dlen,key,data), then the 256 hash tables of 8-byte
 * slots (hashval, record position). Standard linear-probe lookup.
 */
static int cdb_find(const char *path, const unsigned char *key, uint32_t klen)
{
    FILE *f;
    unsigned char rec[8];
    uint32_t h, tpos, tlen, slot, i;
    int result = 0;

    f = fopen(path, "rb");
    if (f == NULL)
        return -1;

    h = cdb_hash(key, klen);

    /* Header entry for this key's table: 8 bytes at (h & 255) * 8. */
    if (fseek(f, (long)((h & 255) * 8u), SEEK_SET) != 0 ||
        fread(rec, 1, 8, f) != 8) {
        fclose(f);
        return -1;
    }
    tpos = cdb_u32(rec);
    tlen = cdb_u32(rec + 4);
    if (tlen == 0) {
        fclose(f);
        return 0;   /* empty table: key cannot be present */
    }

    slot = (h >> 8) % tlen;
    for (i = 0; i < tlen; ++i) {
        uint32_t shash, rpos, rklen;
        unsigned char hdr[8];

        if (fseek(f, (long)(tpos + slot * 8u), SEEK_SET) != 0 ||
            fread(rec, 1, 8, f) != 8) {
            result = -1;
            break;
        }
        shash = cdb_u32(rec);
        rpos = cdb_u32(rec + 4);
        if (rpos == 0) {
            result = 0;   /* empty slot ends the probe: not found */
            break;
        }
        if (shash == h) {
            if (fseek(f, (long)rpos, SEEK_SET) != 0 ||
                fread(hdr, 1, 8, f) != 8) {
                result = -1;
                break;
            }
            rklen = cdb_u32(hdr);
            if (rklen == klen) {
                unsigned char kb[512];
                if (klen <= sizeof(kb)) {
                    if (fread(kb, 1, klen, f) != klen) {
                        result = -1;
                        break;
                    }
                    if (memcmp(kb, key, klen) == 0) {
                        result = 1;
                        break;
                    }
                }
                /* klen > our key buffer cannot be one of the bounded keys we
                 * build below — treat as a non-match and keep probing. */
            }
        }
        slot = (slot + 1) % tlen;
    }

    fclose(f);
    return result;
}

/* Append the lowercase of `s` to buf[*off..n), NUL not written here. */
static int append_lower(unsigned char *buf, size_t *off, size_t n, const char *s)
{
    for (; *s != '\0'; ++s) {
        if (*off >= n)
            return -1;
        buf[(*off)++] = (unsigned char)tolower((unsigned char)*s);
    }
    return 0;
}

/* Build a fastforward cdb key `:<lp>@<dom>` (both lowercased) into buf.
 * Returns the key length, or 0 if it does not fit. */
static uint32_t build_ff_key(unsigned char *buf, size_t n,
                             const char *lp, const char *dom)
{
    size_t off = 0;
    if (off >= n) return 0;
    buf[off++] = ':';
    if (append_lower(buf, &off, n, lp) != 0) return 0;
    if (off >= n) return 0;
    buf[off++] = '@';
    if (dom != NULL && append_lower(buf, &off, n, dom) != 0) return 0;
    return (uint32_t)off;
}

/*
 * Validate `localpart`@`domain` against a fastforward cdb exactly as fastforward
 * resolves a recipient (fastforward(1)/setforward(1) "TARGETS": for incoming
 * user@host it tries, in order, the targets  user@host , @host , user@ — and
 * obeys the first that exists). Lowercase, then probe the matching keys
 *   :lp@domain , :@domain , :lp@
 * A bare `:@` is NOT a fastforward target, so it is deliberately not consulted.
 * Returns 1 if any key is present (fastforward would forward, not bounce), 0 if
 * none are (fastforward bounces), -1 if the cdb cannot be read (caller fails
 * open). Order is immaterial to this membership test but mirrors fastforward.
 */
static int fastforward_cdb_match(const char *cdbpath, const char *localpart,
                                 const char *domain)
{
    const char *dom = (domain != NULL) ? domain : "";
    const char *lps[3];
    const char *doms[3];
    int i;

    lps[0] = localpart; doms[0] = dom;   /* :lp@domain */
    lps[1] = "";        doms[1] = dom;   /* :@domain   */
    lps[2] = localpart; doms[2] = "";    /* :lp@       */

    for (i = 0; i < 3; ++i) {
        unsigned char key[512];
        uint32_t klen = build_ff_key(key, sizeof(key), lps[i], doms[i]);
        int r;
        if (klen == 0)
            continue;   /* unrepresentable key: cannot match this slot */
        r = cdb_find(cdbpath, key, klen);
        if (r != 0)
            return r;   /* 1 = found (accept); -1 = unreadable (fail open) */
    }
    return 0;   /* every key absent: fastforward would bounce */
}

/*
 * If the dot-qmail instruction in `path` is a fastforward invocation
 *   | [dir/]fastforward [-flags] <cdb>
 * extract <cdb> (into cdb[cn]) and report whether -p (pass-through) is in
 * effect. Returns 1 if it is such an invocation with a cdb argument, else 0
 * (including on read error, an empty/comment-only file, or a shell-quoted line
 * we decline to parse — the caller then keeps qmail-local's plain
 * file-exists-means-deliverable behaviour). Only the first delivery line is
 * inspected, which is where the catch-all program lives.
 */
static int fastforward_invocation(const char *path, char *cdb, size_t cn,
                                  int *passthrough)
{
    FILE *f;
    char line[1024];
    char *p, *tok;
    const char *cmd = NULL;
    const char *base;
    const char *last_arg = NULL;
    int pt = 0;

    f = fopen(path, "r");
    if (f == NULL)
        return 0;

    /* First non-blank, non-comment line — qmail's dot-qmail ignores both. */
    for (;;) {
        if (fgets(line, sizeof(line), f) == NULL) { fclose(f); return 0; }
        p = line;
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '\n' || *p == '\0' || *p == '#')
            continue;
        break;
    }
    fclose(f);

    /* Strip the trailing newline. */
    {
        size_t l = strlen(p);
        while (l > 0 && (p[l - 1] == '\n' || p[l - 1] == '\r'))
            p[--l] = '\0';
    }

    /* A program delivery line begins with '|'. */
    if (*p != '|')
        return 0;
    ++p;

    /* If the command line carries shell metacharacters we cannot tokenise it
     * safely on whitespace alone; decline and fall back to accept. A plain
     * `| fastforward [-flags] cdb` has none of these. */
    if (strpbrk(p, "\"'`$\\;&|<>(){}*?[]~") != NULL)
        return 0;

    /* Whitespace-tokenise: first token is the command, the last non-flag token
     * is the positional cdb, and -p/-P toggle pass-through (last wins). */
    for (tok = strtok(p, " \t"); tok != NULL; tok = strtok(NULL, " \t")) {
        if (cmd == NULL) {
            cmd = tok;
            continue;
        }
        if (tok[0] == '-') {
            const char *c;
            for (c = tok + 1; *c != '\0'; ++c) {
                if (*c == 'p') pt = 1;
                else if (*c == 'P') pt = 0;
            }
        } else {
            last_arg = tok;
        }
    }

    if (cmd == NULL || last_arg == NULL)
        return 0;

    base = strrchr(cmd, '/');
    base = (base != NULL) ? base + 1 : cmd;
    if (strcmp(base, "fastforward") != 0)
        return 0;

    if (passthrough != NULL)
        *passthrough = pt;
    snprintf(cdb, cn, "%s", last_arg);
    return 1;
}

/*
 * clause 2 — the qmail-getpw fallback: an unresolved local-part is delivered by
 * the `alias` user (auto_usera) with the WHOLE local-part as the extension and a
 * leading dash (qmail-getpw.c main()). So the address is deliverable iff
 * ~alias/.qmail-<translate(localpart)> or one of its -default catch-alls exists.
 *
 * When the matched catch-all is a `| fastforward <cdb>` program, that program —
 * not qmail-local — decides deliver-vs-bounce: it bounces any recipient absent
 * from <cdb>. So we reproduce its verdict against <cdb> (using `domain` as the
 * $HOST it would resolve), and an unknown recipient becomes not-deliverable so
 * the RCPT gate rejects it (550) rather than letting it be accepted and bounced.
 * A real per-alias .qmail file, a `-p` pass-through (which never bounces), or an
 * unreadable cdb all keep the plain "deliverable" verdict.
 */
static int alias_deliverable(const char *localpart, const char *domain)
{
    struct passwd *pw = getpwnam("alias");
    char match[1024];
    char cdb[1024];
    int passthrough = 0;

    if (pw == NULL || pw->pw_dir == NULL)
        return 0;
    if (!qmail_deliverable_match(pw->pw_dir, localpart, match, sizeof(match)))
        return 0;

    if (match[0] != '\0' &&
        fastforward_invocation(match, cdb, sizeof(cdb), &passthrough) &&
        !passthrough) {
        if (fastforward_cdb_match(cdb, localpart, domain) == 0)
            return 0;   /* absent from cdb: fastforward would bounce -> reject */
    }
    return 1;
}

si_result system_identity(const char *localpart, const char *domain)
{
    size_t len;
    size_t pos;

    if (!localpart_sane(localpart))
        return SI_NONE;

    /*
     * clause 1 — qmail-getpw user resolution (qmail-getpw.c userext()): walk
     * dash-delimited prefixes from longest to shortest. The longest prefix that
     * names a real /home account (qmail lowercases the login first) is the
     * controlling user; the remainder after its '-' is the extension. A prefix
     * that is not such an account is skipped and a shorter one tried, exactly as
     * qmail-getpw continues past a non-match. uid 0 is excluded (qmail-getpw
     * requires pw_uid != 0); the /home restriction is the stack's hybrid-safety
     * narrowing of qmail's home-ownership test, applied identically by the
     * dispatcher so the SMTP-time and delivery-time views never disagree.
     *
     * Once the controlling user is found, deliverability follows qmail-local: a
     * bare user always delivers; an extension delivers only if a matching
     * .qmail-<ext>/.qmail-…default exists, else qmail-local bounces — so we
     * reject rather than fall back to a shorter user prefix (qmail does not).
     */
    len = strlen(localpart);
    for (pos = len; ; --pos) {
        if ((pos == len || localpart[pos] == '-') && pos < USERLEN_MAX) {
            char user[USERLEN_MAX];
            struct passwd *pw;
            size_t i;

            for (i = 0; i < pos; ++i)
                user[i] = (char)tolower((unsigned char)localpart[i]);
            user[pos] = '\0';

            pw = getpwnam(user);
            if (pw != NULL && pw->pw_uid != 0 && home_under_home(pw->pw_dir)) {
                if (pos == len)
                    return SI_PASSWD;   /* bare user: default delivery */
                return si_qmail_deliverable(pw->pw_dir, localpart + pos + 1)
                           ? SI_PASSWD : SI_NONE;
            }
        }
        if (pos == 0)
            break;
    }

    /* clause 2 — alias-configured identity (qmail-getpw auto_usera fallback) */
    if (alias_deliverable(localpart, domain))
        return SI_ALIAS;

    return SI_NONE;
}
