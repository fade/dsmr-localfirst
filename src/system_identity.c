#include "system_identity.h"

#include <ctype.h>
#include <pwd.h>
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
int si_qmail_deliverable(const char *homedir, const char *ext)
{
    char safeext[256];
    char path[1024];
    size_t sl;
    size_t i;
    int n;

    if (ext == NULL || ext[0] == '\0')
        return 1;   /* bare address: default delivery, always deliverable */

    if (si_qmail_ext(ext, safeext, sizeof(safeext)) != 0)
        return 0;   /* extension too long to represent — treat as undeliverable */
    sl = strlen(safeext);

    /* Exact dot-qmail file: .qmail-<safeext> */
    n = snprintf(path, sizeof(path), "%s/.qmail-%s", homedir, safeext);
    if (n > 0 && (size_t)n < sizeof(path) && is_regular_file(path))
        return 1;

    /* Catch-all chain: .qmail-<prefix>default at each '-' boundary in safeext
     * (and at the start), ending with .qmail-default. Matches qmesearch's
     * progressively-shorter -default search exactly. */
    for (i = sl; ; --i) {
        if (i == 0 || safeext[i - 1] == '-') {
            n = snprintf(path, sizeof(path), "%s/.qmail-%.*sdefault",
                         homedir, (int)i, safeext);
            if (n > 0 && (size_t)n < sizeof(path) && is_regular_file(path))
                return 1;
        }
        if (i == 0)
            break;
    }
    return 0;
}

/*
 * clause 2 — the qmail-getpw fallback: an unresolved local-part is delivered by
 * the `alias` user (auto_usera) with the WHOLE local-part as the extension and a
 * leading dash (qmail-getpw.c main()). So the address is deliverable iff
 * ~alias/.qmail-<translate(localpart)> or one of its -default catch-alls exists.
 */
static int alias_deliverable(const char *localpart)
{
    struct passwd *pw = getpwnam("alias");
    if (pw == NULL || pw->pw_dir == NULL)
        return 0;
    return si_qmail_deliverable(pw->pw_dir, localpart);
}

si_result system_identity(const char *localpart)
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
    if (alias_deliverable(localpart))
        return SI_ALIAS;

    return SI_NONE;
}
